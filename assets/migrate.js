(() => {
  'use strict';
  const $ = id => document.getElementById(id);
  const csrf = document.querySelector('meta[name="csrf-token"]').content;

  $('mig-form').addEventListener('submit', async e => {
    e.preventDefault();
    const msg = $('mig-msg'), ok = $('mig-ok'), btn = $('mig-btn');
    msg.hidden = ok.hidden = true;
    const file = $('mig-file').files[0];
    const key = $('mig-key').value;
    if (!file || !key) { msg.textContent = 'Choose the backup file and enter the migration key.'; msg.hidden = false; return; }
    btn.disabled = true;
    try {
      const backup = JSON.parse(await file.text());
      const accounts = backup.accounts || backup;
      const res = await fetch('api/migrate.php', {
        method: 'POST', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, 'X-Migration-Key': key },
        body: JSON.stringify({ accounts }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `Import failed (${res.status})`);
      ok.textContent = `Imported ${data.importedUsers} new account(s) and ${data.importedEntries} password(s). Skipped ${data.skipped}. You can now sign in.`;
      ok.hidden = false;
    } catch (err) {
      msg.textContent = err instanceof SyntaxError ? 'That file is not valid JSON.' : err.message;
      msg.hidden = false;
    } finally { btn.disabled = false; }
  });
})();
