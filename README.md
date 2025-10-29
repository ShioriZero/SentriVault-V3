# SentriVault — Quick User Manual

SentriVault is a client-side password manager that runs entirely in your browser. Paste the HTML, CSS and JS into CodePen (or any static host) and you get a small, secure vault that encrypts everything locally with a master password.

This document is a short, focused user manual: how to run SentriVault and how to use its features safely.

---

## Quick start (CodePen)

1. Create a new Pen on CodePen.
2. Paste the provided `index.html` into the HTML panel.
3. Paste the provided `style.css` into the CSS panel.
4. Paste the provided `app.js` into the JS panel.
5. Open the page preview — you should see the SentriVault UI.

---

## First run — Create a vault

1. On the welcome screen, enter a master password in the "Master password" field and confirm it in the "Confirm password" field.
2. Click **Create Vault**.
3. SentriVault will:
   - create an empty encrypted vault,
   - store it in your browser (localStorage),
   - unlock the vault so you can add entries.

Important: the master password is not stored anywhere — remember it. If you lose it, your vault cannot be recovered.

---

## Unlocking an existing vault

1. If you already have an encrypted vault in localStorage (or imported one), enter your master password in the master field.
2. Click **Unlock Vault**.
3. If the password is correct, the vault will decrypt and open.

---

## Basic workflow (after unlocking)

- Search: type in the search box to filter entries by title, username, URL or notes.
- Add a new entry:
  1. Fill Title (required), Username, Password (required), and optional URL.
  2. Click **Add**.
  3. The entry is encrypted and saved automatically.
- Edit entry: click the entry's **Edit** button — the form fills with the entry; edit and click **Save**.
- Delete entry: click **Del** and confirm.
- View entry: click **View** to see details in a prompt (useful for copying).
- Copy password: click **Copy** on an entry to copy the password to your clipboard.

---

## Password generation & clipboard

- Use **Generate** to create a random password and populate the password field.
- Use **Paste** to paste clipboard contents into the password field.
- When you copy a password to the clipboard, clear it manually when finished (your browser may not clear it automatically). Consider using a clipboard manager or waiting for the browser to clear the data.

---

## Export / Import

- Export: click **Export** to download the encrypted vault JSON file. The file is the encrypted data — it cannot be read without the master password.
- Import: on the auth screen use **Import encrypted vault** and select a previously exported file. Importing will replace the vault in localStorage (you are prompted to confirm if a vault exists).

---

## Lock vs Exit

- Lock: clears the master password from memory and returns to the auth screen. The encrypted vault remains in localStorage.
- Exit: same as Lock — an immediate way to end the unlocked session without deleting stored data.

---

## Auto-lock

- SentriVault auto-locks after a short period of inactivity (default is 3 minutes). When it auto-locks, your master password is removed from memory and the UI returns to the auth screen.

---

## Security notes (short)

- Everything is encrypted in your browser using PBKDF2 + AES-GCM.
- The encrypted vault lives in localStorage. If you clear browser data, the vault will be lost.
- Your master password is the only key to decrypt. If you lose it, you cannot recover vault contents.
- Do not use this demo vault for very sensitive or high-value secrets without reviewing cryptography and threat model.
- Prefer to run SentriVault over HTTPS (CodePen and modern browsers already use HTTPS).
- Avoid using public or shared machines for long-term storage of your vault.

---

## Troubleshooting

- "No encrypted vault found": create a new vault or import an exported vault file.
- "Wrong password or corrupt vault": double-check the master password. If you imported a file, ensure it was not modified.
- Theme or UI issues in CodePen: make sure you pasted all three files into the correct panels and the preview is not blocked by extensions.
- If the page throws console errors, open DevTools to inspect — the app exposes a small debugging helper on the console as `SentriVault` with:
  - `SentriVault.isLocked()` — returns whether the vault is locked
  - `SentriVault.clearStorage()` — removes the encrypted vault from localStorage (use carefully)

---

## Short FAQ

- Q: Can I sync to the cloud?
  - A: Not by default. The exported encrypted JSON can be stored in cloud services yourself; keep it encrypted and keep the master password secure.
- Q: Is the vault recoverable without the master password?
  - A: No. The master password encrypts the vault and is required to decrypt it.
- Q: Can I change the master password?
  - A: Not directly in the UI. To change it: export the vault, decrypt it locally (by unlocking), re-encrypt with a new password (this is something we can add if you want), and save — or create a new vault and re-add entries.
