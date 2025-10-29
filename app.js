/* SentriVault — fixed & improved
   - Fixes themeToggle null error by adding a theme toggle and guarding access
   - Separates Create and Unlock into separate buttons
   - Adds Exit button to clear master (in-memory) and return to auth
   - Enhances visuals via CSS (see style.css)
   Paste into CodePen JS panel. Uses Web Crypto: PBKDF2 + AES-GCM.
*/

(() => {
  // Config
  const STORAGE = 'sentrivault_v1';
  const ITER = 160_000;
  const SALT_BYTES = 16;
  const IV_BYTES = 12;
  const AUTO_LOCK = 3 * 60 * 1000; // 3 minutes

  const enc = new TextEncoder();
  const dec = new TextDecoder();

  // helpers: base64 + random
  function b64(buf){ return btoa(String.fromCharCode(...new Uint8Array(buf))); }
  function fromB64(s){ const bin = atob(s); const a=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) a[i]=bin.charCodeAt(i); return a.buffer; }
  function rand(n){ const b=new Uint8Array(n); crypto.getRandomValues(b); return b.buffer; }

  // derive key
  async function derive(password, salt){
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name:'PBKDF2', salt, iterations:ITER, hash:'SHA-256' },
      keyMaterial,
      { name:'AES-GCM', length:256 },
      false,
      ['encrypt','decrypt']
    );
  }

  // encrypt/decrypt vault bundles
  async function encrypt(obj, password){
    const salt = rand(SALT_BYTES);
    const iv = rand(IV_BYTES);
    const key = await derive(password, salt);
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv:new Uint8Array(iv) }, key, enc.encode(JSON.stringify(obj)));
    return JSON.stringify({ v:1, salt:b64(salt), iv:b64(iv), ct:b64(ct) });
  }

  async function decrypt(blob, password){
    let parsed;
    try { parsed = JSON.parse(blob); } catch { throw new Error('Invalid vault blob'); }
    const { salt, iv, ct } = parsed;
    if (!salt || !iv || !ct) throw new Error('Invalid vault format');
    const key = await derive(password, fromB64(salt));
    const plain = await crypto.subtle.decrypt({ name:'AES-GCM', iv:new Uint8Array(fromB64(iv)) }, key, fromB64(ct));
    return JSON.parse(dec.decode(plain));
  }

  // DOM helpers
  const $ = id => document.getElementById(id);
  const auth = $('auth'), vaultUI = $('vault');
  const pw1 = $('pw1'), pw2 = $('pw2'), createBtn = $('createBtn'), unlockBtn = $('unlockBtn');
  const fileInput = $('fileInput'), importBtn = $('importBtn');
  const titleIn = $('title'), userIn = $('user'), passIn = $('password'), urlIn = $('url');
  const saveBtn = $('saveBtn'), clearBtn = $('clearBtn'), genBtn = $('genBtn'), pasteBtn = $('pasteBtn');
  const entriesWrap = $('entries'), lockBtn = $('lockBtn'), exportBtn = $('exportBtn'), exitBtn = $('exitBtn');
  const search = $('search'), toastEl = $('toast'), lockVisual = $('lockVisual');
  const themeToggle = $('themeToggle');

  // State
  let master = null;
  let vault = { entries: [] };
  let autoLockTimer = null;

  // UI helpers
  function show(el){ if(!el) return; el.classList.remove('hidden'); el.setAttribute('aria-hidden','false'); }
  function hide(el){ if(!el) return; el.classList.add('hidden'); el.setAttribute('aria-hidden','true'); }
  function toast(msg){
    if(!toastEl) return;
    toastEl.textContent = msg;
    toastEl.classList.remove('hidden');
    setTimeout(()=> toastEl.classList.add('hidden'), 1600);
  }

  function saveRaw(s){ localStorage.setItem(STORAGE, s); }
  function loadRaw(){ return localStorage.getItem(STORAGE); }
  function hasVault(){ return !!loadRaw(); }

  // ensure themeToggle exists; if not, create fallback (prevents null errors)
  if (!themeToggle) {
    console.warn('themeToggle not found — creating fallback');
    const btn = document.createElement('button');
    btn.id = 'themeToggle';
    btn.className = 'btn-icon';
    btn.textContent = '🌓';
    btn.title = 'Toggle theme';
    document.querySelector('.controls')?.appendChild(btn);
  }
  const tgl = $('themeToggle');
  if (tgl) {
    tgl.addEventListener('click', () => {
      const body = document.body;
      const next = body.getAttribute('data-theme') === 'bright' ? 'dark' : 'bright';
      body.setAttribute('data-theme', next);
      toast(next === 'dark' ? 'Dark theme' : 'Bright theme');
    });
  }

  // set initial auth mode (show auth)
  (function initAuth(){
    show(auth);
    hide(vaultUI);
    pw1.value = pw2.value = '';
    lockVisual.style.transform = 'translateY(0)';
  })();

  // render entries
  function renderEntries(filter = ''){
    entriesWrap.innerHTML = '';
    const filtered = vault.entries.filter(e => (e.title + ' ' + e.username + ' ' + (e.url || '')).toLowerCase().includes(filter.toLowerCase()));
    filtered.forEach((e, idx) => {
      const card = document.createElement('div');
      card.className = 'card';
      // left meta
      const meta = document.createElement('div'); meta.className = 'meta';
      const t = document.createElement('div'); t.className = 'title'; t.textContent = e.title;
      const s = document.createElement('div'); s.className = 'sub'; s.textContent = `${e.username || ''}${e.url ? ' • ' + e.url : ''}`;
      meta.appendChild(t); meta.appendChild(s);

      // actions
      const actions = document.createElement('div'); actions.className = 'actions';
      const copyBtn = document.createElement('button'); copyBtn.className = 'action-btn'; copyBtn.textContent = 'Copy';
      copyBtn.title = 'Copy password';
      copyBtn.onclick = async () => {
        try {
          await navigator.clipboard.writeText(e.password);
          toast('Password copied');
        } catch {
          alert('Clipboard unavailable');
        }
        resetAutoLock();
      };

      const viewBtn = document.createElement('button'); viewBtn.className = 'action-btn'; viewBtn.textContent = 'View';
      viewBtn.onclick = () => { prompt('Entry details', `Title: ${e.title}\nUser: ${e.username}\nPassword: ${e.password}\nURL: ${e.url || ''}`); resetAutoLock(); };

      const editBtn = document.createElement('button'); editBtn.className = 'action-btn'; editBtn.textContent = 'Edit';
      editBtn.onclick = () => {
        titleIn.value = e.title;
        userIn.value = e.username;
        passIn.value = e.password;
        urlIn.value = e.url || '';
        saveBtn.dataset.edit = idx;
        saveBtn.textContent = 'Save';
        resetAutoLock();
      };

      const delBtn = document.createElement('button'); delBtn.className = 'action-btn'; delBtn.textContent = 'Del';
      delBtn.onclick = async () => {
        if (!confirm(`Delete "${e.title}"?`)) return;
        vault.entries.splice(idx, 1);
        await persist();
        renderEntries(search.value);
        toast('Deleted');
        resetAutoLock();
      };

      [copyBtn, viewBtn, editBtn, delBtn].forEach(b => actions.appendChild(b));
      card.appendChild(meta);
      card.appendChild(actions);
      entriesWrap.appendChild(card);
    });
  }

  // persist vault encrypted
  async function persist(){
    if (!master) throw new Error('locked');
    const raw = await encrypt(vault, master);
    saveRaw(raw);
  }

  // flows: create vs unlock separated
  createBtn.addEventListener('click', async () => {
    const a = pw1.value || '';
    const b = pw2.value || '';
    if (!a) return alert('Enter a master password to create a vault');
    if (hasVault()) {
      if (!confirm('A vault already exists in storage. Creating a new one will overwrite it. Continue?')) return;
    }
    if (a !== b) return alert('Passwords do not match');
    createBtn.disabled = true;
    try {
      master = a;
      vault = { entries: [], created: Date.now() };
      await persist();
      enterVault();
      toast('Vault created and unlocked');
    } catch (e) {
      alert('Failed to create vault: ' + e.message);
    } finally {
      createBtn.disabled = false;
      pw1.value = pw2.value = '';
    }
  });

  unlockBtn.addEventListener('click', async () => {
    const pw = pw1.value || '';
    if (!pw) return alert('Enter master password to unlock');
    if (!hasVault()) return alert('No encrypted vault found. Create one first or import.');
    unlockBtn.disabled = true;
    try {
      const raw = loadRaw();
      const obj = await decrypt(raw, pw);
      master = pw;
      vault = obj;
      enterVault();
      toast('Unlocked');
    } catch (e) {
      alert(e.message || 'Failed to unlock');
    } finally {
      unlockBtn.disabled = false;
      pw1.value = pw2.value = '';
    }
  });

  // Enter vault UI
  function enterVault(){
    hide(auth);
    show(vaultUI);
    lockVisual.style.transform = 'translateY(-8px) rotate(-3deg)';
    renderEntries();
    resetAutoLock();
  }

  // Lock vs Exit:
  // Lock: wipes master from memory and returns to auth (like Exit). Exit same behavior here but named differently.
  function lockNow(){
    master = null;
    vault = { entries: [] };
    show(auth);
    hide(vaultUI);
    pw1.value = pw2.value = '';
    lockVisual.style.transform = 'translateY(0)';
    toast('Locked');
    if (autoLockTimer) clearTimeout(autoLockTimer);
  }

  exitBtn.addEventListener('click', () => {
    if (confirm('Exit SentriVault? This will clear your unlocked session but keep the encrypted vault in storage.')) {
      lockNow();
    }
  });

  lockBtn.addEventListener('click', () => {
    if (confirm('Lock vault now?')) lockNow();
  });

  // Export / Import
  exportBtn.addEventListener('click', () => {
    const raw = loadRaw();
    if (!raw) return alert('No vault to export.');
    const blob = new Blob([raw], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'sentrivault_export.json';
    a.click();
    URL.revokeObjectURL(url);
  });

  importBtn.addEventListener('click', () => {
    fileInput.value = '';
    fileInput.click();
  });

  fileInput.addEventListener('change', async (e) => {
    const f = e.target.files && e.target.files[0];
    if (!f) return;
    const txt = await f.text();
    try {
      JSON.parse(txt);
    } catch {
      return alert('Invalid file format');
    }
    if (hasVault()) {
      if (!confirm('Replace existing vault with imported one?')) return;
    }
    saveRaw(txt);
    alert('Imported vault saved to localStorage. Unlock with the correct master password.');
  });

  // Entry actions: add / edit / save
  saveBtn.addEventListener('click', async (ev) => {
    ev.preventDefault();
    const title = titleIn.value.trim();
    const username = userIn.value.trim();
    const password = passIn.value;
    const url = urlIn.value.trim();
    if (!title || !password) return alert('Title and password required');
    if (saveBtn.dataset.edit !== undefined) {
      const idx = Number(saveBtn.dataset.edit);
      vault.entries[idx] = { title, username, password, url };
      delete saveBtn.dataset.edit;
      saveBtn.textContent = 'Add';
      toast('Updated');
    } else {
      vault.entries.unshift({ title, username, password, url });
      toast('Added');
    }
    await persist();
    renderEntries(search.value);
    titleIn.value = userIn.value = passIn.value = urlIn.value = '';
    resetAutoLock();
  });

  clearBtn.addEventListener('click', (e) => {
    e.preventDefault();
    titleIn.value = userIn.value = passIn.value = urlIn.value = '';
    saveBtn.textContent = 'Add';
    delete saveBtn.dataset.edit;
  });

  // generator + paste
  genBtn.addEventListener('click', () => {
    passIn.value = generatePassword(16);
    toast('Password generated');
  });

  pasteBtn.addEventListener('click', async () => {
    try {
      passIn.value = await navigator.clipboard.readText();
      toast('Pasted from clipboard');
    } catch {
      alert('Clipboard not available');
    }
  });

  function generatePassword(length = 16) {
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_+=';
    const arr = new Uint32Array(length);
    crypto.getRandomValues(arr);
    return Array.from(arr, n => chars[n % chars.length]).join('');
  }

  // search
  search.addEventListener('input', () => renderEntries(search.value));

  // auto-lock mechanics
  function resetAutoLock(){
    if (autoLockTimer) clearTimeout(autoLockTimer);
    if (!master) return;
    autoLockTimer = setTimeout(() => {
      lockNow();
      alert('Vault locked due to inactivity');
    }, AUTO_LOCK);
  }

  ['click', 'mousemove', 'keydown', 'touchstart'].forEach(ev =>
    document.addEventListener(ev, () => { if (master) resetAutoLock(); }, { passive: true })
  );

  // small helper: expose debug methods
  window.SentriVault = {
    isLocked: () => !master,
    clearStorage: () => { localStorage.removeItem(STORAGE); lockNow(); alert('Encrypted vault cleared from localStorage'); }
  };

  // init: set theme from previous if present
  (function initTheme(){
    const body = document.body;
    if (!body.getAttribute('data-theme')) body.setAttribute('data-theme', 'bright');
  })();

})();
