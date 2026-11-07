<?php
declare(strict_types=1);
require __DIR__ . '/includes/bootstrap.php';
kv_security_headers(false);
header('Cache-Control: no-store');
kv_session_start();
$csrf = htmlspecialchars($_SESSION['csrf'], ENT_QUOTES);
$ico = fn(string $n, string $cls = 'ico') => '<svg class="' . $cls . '" aria-hidden="true"><use href="#i-' . $n . '"/></svg>';
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="csrf-token" content="<?= $csrf ?>">
  <meta name="color-scheme" content="light dark">
  <title>BMNS KeyVault</title>
  <link rel="icon" href="assets/favicon.svg" type="image/svg+xml">
  <link rel="stylesheet" href="assets/app.css?v=2">
</head>
<body>
<?php include __DIR__ . '/includes/icons.php'; ?>

<!-- Sign in / register -->
<main id="auth" class="auth">
  <svg class="rings" viewBox="0 0 400 400" aria-hidden="true">
    <circle cx="200" cy="200" r="190" class="r0"/><circle cx="200" cy="200" r="150" class="r0"/><circle cx="200" cy="200" r="110" class="r0"/><circle cx="200" cy="200" r="70" class="r0"/>
    <circle cx="200" cy="200" r="190" class="r1" pathLength="100"/><circle cx="200" cy="200" r="150" class="r2" pathLength="100"/><circle cx="200" cy="200" r="110" class="r1" pathLength="100"/>
  </svg>
  <div class="auth-card">
    <div class="brand brand-lg"><span class="mark"><?= $ico('lock') ?></span><span>BMNS KeyVault</span></div>
    <p class="tagline">Passwords encrypted in your browser. The server never sees your master password.</p>

    <div class="seg" role="tablist" aria-label="Account">
      <button type="button" role="tab" id="tab-login" class="seg-btn active" aria-selected="true">Sign in</button>
      <button type="button" role="tab" id="tab-register" class="seg-btn" aria-selected="false">Create vault</button>
    </div>

    <form id="auth-form" autocomplete="on" novalidate>
      <label class="field">
        <span>Email</span>
        <input id="email" type="email" name="email" autocomplete="username" placeholder="name@domain.com" required autofocus>
      </label>

      <label class="field">
        <span>Master password</span>
        <div class="input-wrap">
          <input id="master" type="password" name="password" autocomplete="current-password" required>
          <button type="button" class="icon-btn input-btn" data-toggle="master" aria-label="Show password"><?= $ico('eye') ?></button>
        </div>
        <div id="auth-meter" class="meter" data-level="0" hidden>
          <div class="meter-bar"><i></i></div>
          <span class="meter-label">None</span>
        </div>
      </label>

      <label class="field" id="confirm-field" hidden>
        <span>Confirm master password</span>
        <input id="master2" type="password" autocomplete="new-password">
      </label>

      <p id="warn" class="note" hidden>There is no password recovery. If you forget your master password, your saved data cannot be decrypted by anyone.</p>
      <p id="auth-error" class="error" role="alert" hidden></p>

      <button id="auth-submit" type="submit" class="btn btn-primary btn-block">Unlock vault</button>
    </form>
  </div>
  <p class="foot"><?= $ico('shield') ?> AES-256-GCM · PBKDF2-SHA256 · zero-knowledge</p>
</main>

<!-- Vault -->
<div id="app" class="app" hidden>
  <header class="bar">
    <div class="brand"><span class="mark"><?= $ico('lock') ?></span><span>BMNS KeyVault</span></div>
    <div class="bar-right">
      <span id="whoami" class="who"></span>
      <button id="lock-btn" class="btn btn-ghost" type="button"><?= $ico('logout') ?><span>log out</span></button>
    </div>
  </header>

  <main class="wrap">
    <section id="stats" class="stats" hidden>
      <article class="card stat glow-teal">
        <span class="stat-label">Accounts</span>
        <strong id="st-total" class="stat-num">0</strong>
        <span id="st-total-sub" class="stat-sub"></span>
        <div class="bar-track"><i id="st-bar"></i></div>
      </article>
      <article class="card stat stat-ring glow-teal">
        <svg viewBox="0 0 100 100" class="ring" aria-hidden="true"><circle class="ring-bg" cx="50" cy="50" r="40"/><circle id="st-ring" class="ring-fg" cx="50" cy="50" r="40" pathLength="100"/></svg>
        <div class="ring-text"><strong id="st-score">0%</strong><span class="stat-sub">Security score</span></div>
      </article>
      <article class="card stat glow-amber">
        <span class="stat-label">Needs attention</span>
        <strong id="st-warn" class="stat-num">0</strong>
        <span id="st-warn-sub" class="stat-sub"></span>
      </article>
      <article class="card stat">
        <span class="stat-label">Strength</span>
        <div id="st-dist" class="dist"></div>
      </article>
    </section>

    <div class="toolbar">
      <div class="search">
        <?= $ico('search') ?>
        <input id="search" type="search" placeholder="Search accounts" aria-label="Search accounts" autocomplete="off">
      </div>
      <button id="add-btn" class="btn btn-primary" type="button"><?= $ico('plus') ?><span>Add account</span></button>
    </div>

    <div class="card">
      <table class="list">
        <thead>
          <tr><th>Account</th><th>Password</th><th class="col-strength">Strength</th><th class="col-actions"><span class="sr">Actions</span></th></tr>
        </thead>
        <tbody id="rows"></tbody>
      </table>
      <div id="empty" class="empty" hidden>
        <strong id="empty-title">No accounts yet</strong>
        <span id="empty-text">Add your first account to store an encrypted password.</span>
      </div>
    </div>
    <p id="count" class="count"></p>
  </main>
</div>

<!-- Add / edit -->
<dialog id="entry-dialog">
  <form id="entry-form" method="dialog" novalidate>
    <header class="dlg-head">
      <h2 id="entry-title">New account</h2>
      <button type="button" class="icon-btn" data-close aria-label="Close"><?= $ico('plus', 'ico rot') ?></button>
    </header>
    <div class="dlg-body">
      <label class="field"><span>Account / service</span>
        <input id="f-name" type="text" maxlength="255" placeholder="e.g. GitHub" autocomplete="off" required></label>
      <label class="field"><span>Username / email</span>
        <input id="f-user" type="text" maxlength="320" placeholder="name@domain.com" autocomplete="off"></label>
      <div class="field">
        <span>Password</span>
        <div class="input-wrap">
          <input id="f-pwd" type="password" class="mono" autocomplete="new-password" required>
          <button type="button" class="icon-btn input-btn" data-toggle="f-pwd" aria-label="Show password"><?= $ico('eye') ?></button>
        </div>
        <div id="entry-meter" class="meter" data-level="0"><div class="meter-bar"><i></i></div><span class="meter-label">None</span></div>
      </div>
      <div class="gen">
        <button type="button" id="gen-btn" class="btn btn-subtle"><?= $ico('refresh') ?><span>Generate</span></button>
        <label class="gen-len"><span>Length <b id="len-out">20</b></span><input id="gen-len" type="range" min="12" max="48" value="20"></label>
        <label class="check"><input id="gen-sym" type="checkbox" checked><span>Symbols</span></label>
      </div>
      <p id="entry-error" class="error" role="alert" hidden></p>
    </div>
    <footer class="dlg-foot">
      <button type="button" class="btn btn-ghost" data-close>Cancel</button>
      <button type="submit" id="entry-save" class="btn btn-primary">Encrypt &amp; save</button>
    </footer>
  </form>
</dialog>

<!-- Delete confirm -->
<dialog id="del-dialog" class="small">
  <form method="dialog">
    <div class="dlg-body">
      <h2>Delete account?</h2>
      <p class="muted" id="del-text"></p>
    </div>
    <footer class="dlg-foot">
      <button type="button" class="btn btn-ghost" data-close>Cancel</button>
      <button type="button" id="del-confirm" class="btn btn-danger">Delete</button>
    </footer>
  </form>
</dialog>

<div id="toasts" class="toasts" aria-live="polite"></div>
<script src="assets/app.js?v=2" defer></script>
</body>
</html>
