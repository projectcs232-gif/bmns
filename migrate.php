<?php
declare(strict_types=1);
require __DIR__ . '/includes/bootstrap.php';
kv_security_headers(false);
header('Cache-Control: no-store');
kv_session_start();
$enabled = (string) (kv_config()['migration_key'] ?? '') !== '';
$csrf = htmlspecialchars($_SESSION['csrf'], ENT_QUOTES);
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="<?= $csrf ?>">
  <meta name="color-scheme" content="light dark">
  <title>Import old vault · BMNS KeyVault</title>
  <link rel="icon" href="assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="assets/app.css?v=2">
</head>
<body>
<main class="auth">
  <div class="auth-card wide">
    <h1 class="page-title">Import old vault</h1>
    <p class="tagline left">Copies accounts and their <em>already-encrypted</em> passwords from the old browser-based app into MySQL. Nothing is decrypted; sign in afterwards with the same email and master password as before.</p>

<?php if (!$enabled): ?>
    <p class="note">Import is disabled. Set <code>migration_key</code> in <code>config/config.php</code> to a long random value, then reload this page.</p>
<?php else: ?>
    <ol class="steps">
      <li>Open the <strong>old</strong> app in the browser where your passwords are visible, press F12, choose Console and run:
<pre id="snippet">const raw = localStorage.getItem('keyvault_accounts');
if (!raw) throw new Error('No old KeyVault data found on this page');
const a = document.createElement('a');
a.href = URL.createObjectURL(new Blob([JSON.stringify({accounts: JSON.parse(raw)}, null, 2)], {type: 'application/json'}));
a.download = 'bmns-keyvault-legacy-backup.json';
a.click();</pre></li>
      <li>Choose the downloaded backup file and enter your <code>migration_key</code>.</li>
    </ol>

    <form id="mig-form" novalidate>
      <label class="field"><span>Backup file (.json)</span><input id="mig-file" type="file" accept="application/json,.json" class="file"></label>
      <label class="field"><span>Migration key</span><input id="mig-key" type="password" autocomplete="off"></label>
      <p id="mig-msg" class="error" role="alert" hidden></p>
      <p id="mig-ok" class="ok" role="status" hidden></p>
      <button id="mig-btn" type="submit" class="btn btn-primary btn-block">Import</button>
    </form>
<?php endif; ?>
    <p class="back"><a href="./">← Back to KeyVault</a></p>
  </div>
</main>
<div id="toasts" class="toasts"></div>
<?php if ($enabled): ?><script src="assets/migrate.js?v=1" defer></script><?php endif; ?>
</body>
</html>
