# SentriVault-V3
Work in Progress

# SentriVault — Client-side Password Manager (CodePen-ready)

SentriVault is a browser-only, client-side password manager you can drop into CodePen (or any static host). It stores an encrypted vault in localStorage and uses modern Web Crypto APIs (PBKDF2 + AES-GCM) to encrypt and decrypt your data with a master password. There is no backend: everything lives in your browser.

Important security notes
- The master password is never sent anywhere. Vault data is encrypted locally and stored in localStorage.
- This is intended as a reasonably-secure demo and light-weight manager. For production or high-security use, review the cryptography choices and threat model, use secure hosting (HTTPS), and consider audited solutions.
- If you lose your master password, you cannot recover the vault.

What you get
- Lock/unlock with a master password (create new vault or open an existing one)
- Add, edit, delete entries (name, username, password, URL, notes)
- Password generator with options
- Password strength indicator
- Search and copy-to-clipboard
- Export/import encrypted vault JSON
- Auto-lock on inactivity
- Works in CodePen: paste HTML, CSS, JS into CodePen panels or upload these files to a static host

Files
- index.html — UI and layout (paste into CodePen HTML pane)
- style.css — styling (paste into CodePen CSS pane)
- app.js — all logic and crypto (paste into CodePen JS pane)

How to run in CodePen
1. Create a new Pen.
2. Paste the contents of index.html into the HTML panel, style.css into the CSS panel, and app.js into the JS panel.
3. Open Console for any errors and interact with the UI.

License
- MIT-style: use as you like; please don't hold me responsible for misuse.
