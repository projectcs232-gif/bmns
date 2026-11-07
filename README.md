# BMNS KeyVault — PHP / XAMPP edition

Client-side encrypted password manager (AES-256-GCM, PBKDF2-SHA256). PHP + MySQL backend, no Node, no CDN, works offline.
Same database schema and encryption format as the Node version, so existing data and vaults keep working.

## Install (XAMPP, Windows/macOS/Linux)
1. Start **Apache** and **MySQL** in the XAMPP control panel.
2. Copy this folder to `xampp/htdocs/bmns-keyvault`.
3. Open **http://localhost/phpmyadmin** → **SQL** tab → paste the contents of `database.sql` → Go.
   (Already have the `bmns_keyvault` database from the Node version? Run it anyway; it only adds what is missing.)
4. Check `config/config.php`. The defaults match XAMPP (user `root`, empty password). Change them if you set a MySQL password.
5. Open **http://localhost/bmns-keyvault/** and choose *Create vault*.

Health check: `http://localhost/bmns-keyvault/api/health.php` should say `"database":"connected"`.
Requires PHP 8.1+ with `pdo_mysql` (default in XAMPP).

## Import the old browser-based vault
1. In `config/config.php` set `migration_key` to a long random string.
2. Open `http://localhost/bmns-keyvault/migrate.php` and follow the two steps on the page.
3. Sign in with the **same email and master password** as the old app. Then clear `migration_key` again.

## Notes
- Master password never leaves the browser; only encrypted data is stored. **There is no recovery** if it is forgotten.
- Vault auto-locks after 5 minutes idle; copied passwords are cleared from the clipboard after 30 seconds.
- Do not change the PBKDF2 iteration count (100,000): it would make existing vaults undecryptable.
- Putting it on the internet: use HTTPS, a strong MySQL password (not empty root), and back up the database.
- `.htaccess` files protect `config/`, `includes/` and `storage/` on Apache (XAMPP allows this by default).

## Layout
`index.php` UI · `assets/` CSS/JS · `api/` JSON endpoints · `includes/bootstrap.php` shared code · `config/config.php` settings
