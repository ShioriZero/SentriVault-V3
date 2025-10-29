/* SentriVault — client-side password manager
   Uses Web Crypto (PBKDF2 + AES-GCM) to encrypt vault in localStorage.
   Paste into CodePen JS panel. No external deps.
*/

(() => {
  // ---- Config ----
  const STORAGE_KEY = 'sentrivault_v1';
  const PBKDF2_ITER = 180_000; // reasonable client iteration count
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const AUTO_LOCK_MS = 5 * 60 * 1000; // 5 minutes

  // ---- Helpers: encoding ----
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  function toB64(buf) {
    const bin = String.fromCharCode(...new Uint8Array(buf));
    return btoa(bin);
  }
  function fromB64(b64) {
    const bin = atob(b64);
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
  }
  function randBytes(len) {
    const b = new Uint8Array(len);
    crypto.getRandomValues(b);
    return b.buffer;
  }

  // ---- Crypto primitives ----
  async function deriveKey(password, salt) {
    const pwKey = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      { name: 'PBKDF2' },
      false,
      ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: PBKDF2_ITER,
        hash: 'SHA-256'
      },
      pwKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encryptVault(vaultObj, password) {
    const salt = randBytes(SALT_BYTES);
    const iv = randBytes(IV_BYTES);
    const key = await deriveKey(password, salt);
    const data = enc.encode(JSON.stringify(vaultObj));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: new Uint8Array(iv) }, key, data);
    const bundle = {
      v: 1,
      salt: toB64(salt),
      iv: toB64(iv),
      ct: toB64(ct)
    };
    return JSON.stringify(bundle);
  }

  async function decryptVault(blobStr, password) {
    let bundle;
    try {
      bundle = JSON.parse(blobStr);
    } catch (e) {
      throw new Error('Invalid vault format');
    }
    if (!bundle.salt || !bundle.iv || !bundle.ct) throw new Error('Invalid vault format');
    const salt = fromB64(bundle.salt);
    const iv = new Uint8Array(fromB64(bundle.iv));
    const ct = fromB64(bundle.ct);
    const key = await deriveKey(password, salt);
    let plain;
    try {
      const decBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
      plain = dec.decode(new Uint8Array(decBuf));
    } catch (e) {
      throw new Error('Decryption failed — wrong password or corrupted vault');
    }
    return JSON.parse(plain);
  }

  // ---- Storage ----
  function hasSavedVault() {
    return !!localStorage.getItem(STORAGE_KEY);
  }
  function saveRawVault(str) {
    localStorage.setItem(STORAGE_KEY, str);
  }
  function loadRawVault() {
    return localStorage.getItem(STORAGE_KEY);
  }
  function clearVaultStorage() {
    localStorage.removeItem(STORAGE_KEY);
  }

  // ---- UI Binding ----
  const $ = id => document.getElementById(id);

  // Auth UI
  const newVaultUI = $('newVaultUI');
  const unlockUI = $('unlockUI');
  const newMaster = $('newMaster');
  const newMasterConfirm = $('newMasterConfirm');
  const createVaultBtn = $('createVaultBtn');
  const switchToUnlock = $('switchToUnlock');
  const master = $('master');
  const unlockBtn = $('unlockBtn');
  const switchToCreate = $('switchToCreate');
  const vaultExistsMsg = $('vaultExistsMsg');
  const fileInput = $('fileInput');
  const importBtn = $('importBtn');

  // Vault UI
  const vaultSection = $('vault');
  const authSection = $('auth');
  const lockBtn = $('lockBtn');
  const exportBtn = $('exportBtn');
  const searchInput = $('search');
  const entriesDiv = $('entries');
  const countLbl = $('countLbl');

  // Entry form
  const entryTitle = $('entryTitle');
  const entryUser = $('entryUser');
  const entryPass = $('entryPass');
  const entryURL = $('entryURL');
  const entryNotes = $('entryNotes');
  const addEntryBtn = $('addEntryBtn');
  const clearEntryBtn = $('clearEntryBtn');
  const generateBtn = $('generateBtn');
  const copyBtn = $('copyBtn');

  // Generator options
  const genLength = $('genLength');
  const genLenVal = $('genLenVal');
  const genLower = $('genLower');
  const genUpper = $('genUpper');
  const genNumbers = $('genNumbers');
  const genSymbols = $('genSymbols');

  // State
  let unlockedMaster = null;
  let vault = { entries: [] };
  let autoLockTimer = null;

  // ---- UI helpers ----
  function show(node) { node.classList.remove('hidden'); }
  function hide(node) { node.classList.add('hidden'); }
  function setAuthMode(hasVault) {
    if (hasVault) {
      show(unlockUI);
      hide(newVaultUI);
      vaultExistsMsg.textContent = 'Encrypted vault found in storage.';
    } else {
      show(newVaultUI);
      hide(unlockUI);
      vaultExistsMsg.textContent = '';
    }
  }

  function resetAutoLock() {
    if (autoLockTimer) clearTimeout(autoLockTimer);
    autoLockTimer = setTimeout(() => {
      lockVault();
      alert('Vault locked due to inactivity.');
    }, AUTO_LOCK_MS);
  }

  function updateEntriesList(filter = '') {
    entriesDiv.innerHTML = '';
    const filtered = vault.entries.filter(e => {
      const s = (e.title + ' ' + e.username + ' ' + e.url + ' ' + e.notes).toLowerCase();
      return s.includes(filter.toLowerCase());
    });
    countLbl.textContent = `(${filtered.length}/${vault.entries.length})`;
    filtered.forEach((e, idx) => {
      const card = document.createElement('div');
      card.className = 'entry-card';

      const meta = document.createElement('div');
      meta.className = 'entry-meta';
      meta.innerHTML = `<strong>${escapeHtml(e.title)}</strong>
                        <div class="details">${escapeHtml(e.username)} — <a href="${escapeHtml(e.url || '#')}" target="_blank">${escapeHtml(e.url || '')}</a></div>`;
      card.appendChild(meta);

      const actions = document.createElement('div');
      actions.className = 'entry-actions';

      const viewBtn = document.createElement('button');
      viewBtn.textContent = 'View';
      viewBtn.className = 'small';
      viewBtn.onclick = () => viewEntry(idx);
      actions.appendChild(viewBtn);

      const cpBtn = document.createElement('button');
      cpBtn.textContent = 'Copy';
      cpBtn.className = 'small';
      cpBtn.onclick = async () => {
        await navigator.clipboard.writeText(e.password);
        flash('Copied password to clipboard');
        resetAutoLock();
      };
      actions.appendChild(cpBtn);

      const editBtn = document.createElement('button');
      editBtn.textContent = 'Edit';
      editBtn.className = 'small';
      editBtn.onclick = () => editEntry(idx);
      actions.appendChild(editBtn);

      const delBtn = document.createElement('button');
      delBtn.textContent = 'Delete';
      delBtn.className = 'small';
      delBtn.onclick = () => {
        if (!confirm(`Delete "${e.title}"?`)) return;
        vault.entries.splice(idx, 1);
        saveVault();
        updateEntriesList(searchInput.value);
        resetAutoLock();
      };
      actions.appendChild(delBtn);

      card.appendChild(actions);
      entriesDiv.appendChild(card);
    });
  }

  function escapeHtml(s) {
    if (!s) return '';
    return s.replace(/[&<>"']/g, c => ({ '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;' })[c]);
  }

  function flash(msg) {
    // small ephemeral notification using alert fallback
    try {
      const toast = document.createElement('div');
      toast.textContent = msg;
      toast.style.position = 'fixed';
      toast.style.bottom = '20px';
      toast.style.left = '50%';
      toast.style.transform = 'translateX(-50%)';
      toast.style.padding = '10px 14px';
      toast.style.background = 'rgba(0,0,0,0.6)';
      toast.style.color = 'white';
      toast.style.borderRadius = '8px';
      document.body.appendChild(toast);
      setTimeout(() => toast.remove(), 2200);
    } catch {
      console.log(msg);
    }
  }

  // ---- Entry actions ----
  function viewEntry(idx) {
    const e = vault.entries[idx];
    const z = [
      `Title: ${e.title}`,
      `Username: ${e.username}`,
      `Password: ${e.password}`,
      `URL: ${e.url}`,
      `Notes: ${e.notes}`
    ].join('\n');
    prompt('Entry details (copy if needed):', z);
    resetAutoLock();
  }

  function editEntry(idx) {
    const e = vault.entries[idx];
    entryTitle.value = e.title;
    entryUser.value = e.username;
    entryPass.value = e.password;
    entryURL.value = e.url;
    entryNotes.value = e.notes || '';
    addEntryBtn.textContent = 'Save';
    addEntryBtn.dataset.editIndex = idx;
    resetAutoLock();
  }

  function clearEntryForm() {
    entryTitle.value = '';
    entryUser.value = '';
    entryPass.value = '';
    entryURL.value = '';
    entryNotes.value = '';
    addEntryBtn.textContent = 'Add';
    delete addEntryBtn.dataset.editIndex;
  }

  // ---- Save / Load vault ----
  async function saveVault() {
    if (!unlockedMaster) throw new Error('Not unlocked');
    const raw = await encryptVault(vault, unlockedMaster);
    saveRawVault(raw);
  }

  // ---- Flow: create / unlock / lock ----
  async function createNewVaultFlow(pw) {
    unlockedMaster = pw;
    vault = { entries: [], created: Date.now() };
    await saveVault();
    enterVault();
  }

  async function unlockVaultFlow(pw) {
    const raw = loadRawVault();
    if (!raw) throw new Error('No vault found');
    const obj = await decryptVault(raw, pw);
    unlockedMaster = pw;
    vault = obj;
    enterVault();
  }

  function enterVault() {
    hide(authSection);
    show(vaultSection);
    updateEntriesList();
    resetAutoLock();
  }

  function lockVault() {
    unlockedMaster = null;
    vault = { entries: [] };
    hide(vaultSection);
    show(authSection);
    setAuthMode(hasSavedVault());
    clearEntryForm();
    if (autoLockTimer) clearTimeout(autoLockTimer);
  }

  // ---- Export / Import ----
  function exportVault() {
    const raw = loadRawVault();
    if (!raw) return alert('No vault to export.');
    const blob = new Blob([raw], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentrivault_export.json';
    a.click();
    URL.revokeObjectURL(url);
  }

  function triggerImport() {
    fileInput.value = '';
    fileInput.click();
  }

  fileInput.addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const txt = await f.text();
    try {
      // Basic validation
      JSON.parse(txt);
    } catch {
      return alert('Invalid file format');
    }
    // Ask to replace existing vault
    if (hasSavedVault()) {
      if (!confirm('Replace existing vault with imported one?')) return;
    }
    saveRawVault(txt);
    alert('Imported vault saved to localStorage. You can now unlock it with the correct master password.');
    setAuthMode(true);
  });

  // ---- Password generation ----
  function generatePassword() {
    const length = Number(genLength.value || 16);
    const sets = [];
    if (genLower.checked) sets.push('abcdefghijklmnopqrstuvwxyz');
    if (genUpper.checked) sets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    if (genNumbers.checked) sets.push('0123456789');
    if (genSymbols.checked) sets.push('!@#$%^&*()-_=+[]{};:,.<>/?');
    if (!sets.length) {
      alert('Select at least one character set for generation.');
      return '';
    }
    const all = sets.join('');
    let out = '';
    const rnd = new Uint32Array(length);
    crypto.getRandomValues(rnd);
    for (let i = 0; i < length; i++) {
      out += all[rnd[i] % all.length];
    }
    return out;
  }

  // ---- Events ----
  switchToUnlock.addEventListener('click', () => setAuthMode(hasSavedVault()));
  switchToCreate.addEventListener('click', () => setAuthMode(false));

  createVaultBtn.addEventListener('click', async () => {
    const a = newMaster.value || '';
    const b = newMasterConfirm.value || '';
    if (!a) return alert('Choose a master password');
    if (a !== b) return alert('Passwords do not match');
    createVaultBtn.disabled = true;
    try {
      await createNewVaultFlow(a);
      flash('Vault created and unlocked');
    } catch (e) {
      alert('Failed to create vault: ' + e.message);
    } finally {
      createVaultBtn.disabled = false;
      newMaster.value = newMasterConfirm.value = '';
    }
  });

  unlockBtn.addEventListener('click', async () => {
    const pw = master.value || '';
    if (!pw) return alert('Enter master password');
    unlockBtn.disabled = true;
    try {
      await unlockVaultFlow(pw);
      flash('Unlocked');
    } catch (e) {
      alert(e.message);
    } finally {
      unlockBtn.disabled = false;
      master.value = '';
    }
  });

  lockBtn.addEventListener('click', () => {
    if (confirm('Lock vault now?')) lockVault();
  });

  exportBtn.addEventListener('click', exportVault);
  importBtn.addEventListener('click', triggerImport);

  addEntryBtn.addEventListener('click', async () => {
    const title = entryTitle.value.trim();
    const username = entryUser.value.trim();
    const password = entryPass.value;
    if (!title) return alert('Title required');
    if (!password) return alert('Password required');
    if (addEntryBtn.dataset.editIndex !== undefined) {
      const idx = Number(addEntryBtn.dataset.editIndex);
      vault.entries[idx] = { title, username, password, url: entryURL.value.trim(), notes: entryNotes.value };
      flash('Entry updated');
      delete addEntryBtn.dataset.editIndex;
      addEntryBtn.textContent = 'Add';
    } else {
      vault.entries.unshift({ title, username, password, url: entryURL.value.trim(), notes: entryNotes.value });
      flash('Entry added');
    }
    await saveVault();
    updateEntriesList(searchInput.value);
    clearEntryForm();
    resetAutoLock();
  });

  clearEntryBtn.addEventListener('click', clearEntryForm);

  generateBtn.addEventListener('click', () => {
    const pw = generatePassword();
    if (pw) {
      entryPass.value = pw;
      flash('Password generated');
    }
  });

  copyBtn.addEventListener('click', async () => {
    if (!entryPass.value) return;
    await navigator.clipboard.writeText(entryPass.value);
    flash('Copied to clipboard');
  });

  searchInput.addEventListener('input', () => {
    updateEntriesList(searchInput.value);
  });

  genLength.addEventListener('input', () => {
    genLenVal.textContent = genLength.value;
  });

  // Keep auto-lock alive on many UI interactions
  ['click', 'keydown', 'mousemove', 'touchstart'].forEach(ev => {
    document.addEventListener(ev, () => {
      if (unlockedMaster) resetAutoLock();
    }, { passive: true });
  });

  // ---- Initialize ----
  (function init() {
    setAuthMode(hasSavedVault());
    // Expose a console helper for debugging in CodePen
    window.SentriVault = {
      isLocked: () => !unlockedMaster,
      clearStorage: () => { clearVaultStorage(); setAuthMode(false); alert('Storage cleared'); }
    };
  })();

})();