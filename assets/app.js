(() => {
  'use strict';

  /* ---------- Crypto (identical parameters to the original app: do not change) ---------- */
  const PBKDF2_ITERATIONS = 100000;
  const VERIFIER_PLAINTEXT = 'VAULT_AUTH_VALID';

  const randomBytes = n => crypto.getRandomValues(new Uint8Array(n));
  const toHex = buf => Array.from(new Uint8Array(buf), b => b.toString(16).padStart(2, '0')).join('');
  const fromHex = hex => {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  };

  async function deriveKey(password, salt) {
    const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  }
  async function encrypt(key, text) {
    const iv = randomBytes(12);
    const data = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
    return { iv: toHex(iv), data: toHex(data) };
  }
  async function decrypt(key, { iv, data }) {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromHex(iv) }, key, fromHex(data));
    return new TextDecoder().decode(plain);
  }

  /* ---------- Helpers ---------- */
  const $ = id => document.getElementById(id);
  const csrf = document.querySelector('meta[name="csrf-token"]').content;
  const AUTO_LOCK_MS = 5 * 60 * 1000;
  const CLIPBOARD_CLEAR_MS = 30 * 1000;

  async function api(path, { method = 'GET', body } = {}) {
    const res = await fetch('api/' + path, {
      method,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf },
      body: body ? JSON.stringify(body) : undefined,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || `Request failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function toast(message, isError = false) {
    const el = document.createElement('div');
    el.className = 'toast' + (isError ? ' err' : '');
    el.textContent = message;
    $('toasts').appendChild(el);
    setTimeout(() => el.remove(), isError ? 5000 : 2600);
  }

  const setText = (el, text) => { el.textContent = text; };
  function show(el, visible) { el.hidden = !visible; }

  /* ---------- Strength ---------- */
  function strength(pwd) {
    if (!pwd) return { level: 0, label: 'None' };
    let s = 0;
    if (pwd.length >= 8) s++;
    if (pwd.length >= 12) s++;
    if (pwd.length >= 16) s++;
    if (/[A-Z]/.test(pwd)) s++;
    if (/[0-9]/.test(pwd)) s++;
    if (/[^A-Za-z0-9]/.test(pwd)) s++;
    if (s <= 1) return { level: 1, label: 'Very weak' };
    if (s === 2) return { level: 2, label: 'Weak' };
    if (s <= 4) return { level: 3, label: 'Fair' };
    if (s === 5) return { level: 4, label: 'Strong' };
    return { level: 5, label: 'Excellent' };
  }
  function paintMeter(meter, pwd) {
    const st = strength(pwd);
    meter.dataset.level = st.level;
    setText(meter.querySelector('.meter-label'), st.label);
  }

  /* ---------- State ---------- */
  let key = null;          // CryptoKey, lives only in memory
  let email = '';
  let vault = [];          // [{id, account, user, pwd}]
  let mode = 'login';
  let editingId = null;
  let pendingDeleteId = null;
  const revealed = new Set();
  let lockTimer = null;
  let clipTimer = null;

  /* ---------- Auth screen ---------- */
  function setMode(next) {
    mode = next;
    const reg = mode === 'register';
    $('tab-login').classList.toggle('active', !reg);
    $('tab-register').classList.toggle('active', reg);
    $('tab-login').setAttribute('aria-selected', String(!reg));
    $('tab-register').setAttribute('aria-selected', String(reg));
    $('auth-submit').textContent = reg ? 'Create encrypted vault' : 'Unlock vault';
    $('master').autocomplete = reg ? 'new-password' : 'current-password';
    show($('auth-meter'), reg);
    show($('confirm-field'), reg);
    show($('warn'), reg);
    show($('auth-error'), false);
    if (reg) paintMeter($('auth-meter'), $('master').value);
  }
  $('tab-login').addEventListener('click', () => setMode('login'));
  $('tab-register').addEventListener('click', () => setMode('register'));
  $('master').addEventListener('input', e => { if (mode === 'register') paintMeter($('auth-meter'), e.target.value); });

  document.addEventListener('click', e => {
    const t = e.target.closest('[data-toggle]');
    if (!t) return;
    const input = $(t.dataset.toggle);
    const hidden = input.type === 'password';
    input.type = hidden ? 'text' : 'password';
    t.querySelector('use').setAttribute('href', hidden ? '#i-eye-off' : '#i-eye');
    t.setAttribute('aria-label', hidden ? 'Hide password' : 'Show password');
  });

  function authError(msg) { setText($('auth-error'), msg); show($('auth-error'), !!msg); }

  $('auth-form').addEventListener('submit', async e => {
    e.preventDefault();
    const btn = $('auth-submit');
    const mail = $('email').value.trim().toLowerCase();
    const pw = $('master').value;
    authError('');
    if (!mail || !pw) return authError('Enter your email and master password.');
    btn.disabled = true;
    const label = btn.textContent;
    btn.textContent = 'Working…';
    try {
      if (mode === 'register') {
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(mail)) throw new Error('Enter a valid email address.');
        if (pw.length < 12) throw new Error('Use a master password of at least 12 characters.');
        if (pw !== $('master2').value) throw new Error('The two master passwords do not match.');
        const salt = randomBytes(16);
        const k = await deriveKey(pw, salt);
        const verifier = await encrypt(k, VERIFIER_PLAINTEXT);
        await api('register.php', { method: 'POST', body: {
          email: mail, saltHex: toHex(salt), verifierIvHex: verifier.iv, verifierDataHex: verifier.data } });
        key = k;
      } else {
        const ch = await api('login.php', { method: 'POST', body: { email: mail } });
        const k = await deriveKey(pw, fromHex(ch.saltHex));
        let ok = false;
        try { ok = (await decrypt(k, { iv: ch.verifierIvHex, data: ch.verifierDataHex })) === VERIFIER_PLAINTEXT; } catch { /* wrong key */ }
        if (!ok) throw new Error('Incorrect email or master password.');
        key = k;
      }
      email = mail;
      $('master').value = ''; $('master2').value = '';
      await enterVault();
    } catch (err) {
      key = null;
      authError(err.message || 'Unable to sign in.');
    } finally {
      btn.disabled = false;
      btn.textContent = label;
    }
  });

  /* ---------- Vault ---------- */
  async function enterVault() {
    setText($('whoami'), email);
    show($('auth'), false);
    show($('app'), true);
    armAutoLock();
    try {
      const { entries } = await api('entries.php');
      const results = await Promise.all(entries.map(async r => {
        try {
          return { id: r.id, account: r.account_name, user: r.account_username,
                   pwd: await decrypt(key, { iv: r.password_iv_hex, data: r.password_data_hex }) };
        } catch { return null; }
      }));
      vault = results.filter(Boolean);
      const failed = results.length - vault.length;
      if (failed) toast(`${failed} entr${failed === 1 ? 'y' : 'ies'} could not be decrypted.`, true);
    } catch (err) {
      toast(err.message, true);
    }
    render();
  }

  function lock(message) {
    try { if (message) sessionStorage.setItem('kv_notice', message); } catch { /* storage unavailable */ }
    api('logout.php', { method: 'POST' }).catch(() => {}).finally(() => location.reload());
    key = null; vault = [];
  }
  $('lock-btn').addEventListener('click', () => lock());

  function armAutoLock() {
    const reset = () => { clearTimeout(lockTimer); lockTimer = setTimeout(() => lock('Locked after 5 minutes of inactivity.'), AUTO_LOCK_MS); };
    ['pointerdown', 'keydown', 'scroll'].forEach(ev => document.addEventListener(ev, reset, { passive: true }));
    reset();
  }

  function render() {
    const q = $('search').value.trim().toLowerCase();
    const rows = $('rows');
    rows.replaceChildren();
    const list = vault.filter(v => v.account.toLowerCase().includes(q) || v.user.toLowerCase().includes(q));

    show($('empty'), list.length === 0);
    $('rows').closest('table').hidden = list.length === 0;
    setText($('empty-title'), vault.length ? 'No matches' : 'No accounts yet');
    setText($('empty-text'), vault.length ? 'Try a different search term.' : 'Add your first account to store an encrypted password.');
    setText($('count'), vault.length ? `${list.length} of ${vault.length} account${vault.length === 1 ? '' : 's'}` : '');

    renderStats();

    for (const item of list) {
      const tr = document.createElement('tr');
      const st = strength(item.pwd);
      const shown = revealed.has(item.id);

      const tdName = document.createElement('td');
      tdName.className = 'c-name';
      const acct = el('div', 'acct');
      acct.append(
        el('div', 'avatar', (item.account.trim()[0] || '?')),
        (() => { const t = el('div', 'acct-text'); t.append(el('div', 'acct-name', item.account), el('div', 'acct-user', item.user || '—')); return t; })());
      tdName.append(acct);

      const tdPw = document.createElement('td');
      tdPw.className = 'c-pw';
      tdPw.append(el('span', 'pw' + (shown ? ' shown' : ''), shown ? item.pwd : '••••••••••'));

      const tdSt = document.createElement('td');
      tdSt.className = 'col-strength';
      const tag = el('span', 'tag', st.label);
      tag.dataset.level = st.level;
      tdSt.append(tag);

      const tdAct = document.createElement('td');
      tdAct.className = 'col-actions';
      const acts = el('div', 'actions');
      acts.append(
        iconBtn(shown ? 'eye-off' : 'eye', shown ? 'Hide password' : 'Show password', () => { shown ? revealed.delete(item.id) : revealed.add(item.id); render(); }),
        iconBtn('user', 'Copy username', () => copy(item.user, 'Username copied', false), !item.user),
        iconBtn('copy', 'Copy password', () => copy(item.pwd, 'Password copied — clears in 30s', true)),
        iconBtn('edit', 'Edit', () => openEntry(item)),
        iconBtn('trash', 'Delete', () => askDelete(item), false, 'danger'));
      tdAct.append(acts);

      tr.append(tdName, tdPw, tdSt, tdAct);
      rows.append(tr);
    }
  }

  const LEVELS = ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'];
  function renderStats() {
    show($('stats'), vault.length > 0);
    if (!vault.length) return;
    const lv = vault.map(v => strength(v.pwd).level);
    const counts = [1, 2, 3, 4, 5].map(l => lv.filter(x => x === l).length);
    const seen = new Map();
    vault.forEach(v => seen.set(v.pwd, (seen.get(v.pwd) || 0) + 1));
    const reused = vault.filter(v => seen.get(v.pwd) > 1).length;
    const weak = lv.filter(x => x <= 2).length;
    const strong = lv.filter(x => x >= 4).length;
    // Score: average strength, minus a penalty for reused passwords.
    const avg = lv.reduce((a, b) => a + b, 0) / lv.length / 5;
    const score = Math.max(0, Math.round((avg - 0.25 * reused / vault.length) * 100));

    setText($('st-total'), String(vault.length));
    setText($('st-total-sub'), `${strong} strong or better`);
    $('st-bar').style.width = Math.round(strong / vault.length * 100) + '%';
    setText($('st-score'), score + '%');
    $('st-ring').style.strokeDasharray = `${score} 100`;
    setText($('st-warn'), String(weak + reused));
    setText($('st-warn-sub'), `${weak} weak · ${reused} reused`);

    const dist = $('st-dist');
    dist.replaceChildren();
    counts.forEach((n, i) => {
      const row = el('div', 'dist-row');
      row.dataset.level = i + 1;
      const track = el('div', 'bar-track'); const fill = document.createElement('i');
      fill.style.width = Math.round(n / vault.length * 100) + '%';
      track.append(fill);
      row.append(el('span', 'dist-name', LEVELS[i]), track, el('span', 'dist-n', String(n)));
      dist.append(row);
    });
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined) n.textContent = text;
    return n;
  }
  function iconBtn(icon, label, onClick, disabled = false, extra = '') {
    const b = el('button', 'icon-btn' + (extra ? ' ' + extra : ''));
    b.type = 'button'; b.title = label; b.disabled = disabled;
    b.setAttribute('aria-label', label);
    b.innerHTML = `<svg class="ico" aria-hidden="true"><use href="#i-${icon}"/></svg>`; // static markup only
    b.addEventListener('click', onClick);
    return b;
  }

  async function copy(text, message, sensitive) {
    try {
      await navigator.clipboard.writeText(text);
      toast(message);
      if (sensitive) {
        clearTimeout(clipTimer);
        clipTimer = setTimeout(() => navigator.clipboard.writeText('').catch(() => {}), CLIPBOARD_CLEAR_MS);
      }
    } catch { toast('Could not access the clipboard.', true); }
  }

  $('search').addEventListener('input', render);

  /* ---------- Add / edit ---------- */
  const entryDialog = $('entry-dialog');
  function openEntry(item) {
    editingId = item ? item.id : null;
    setText($('entry-title'), item ? 'Edit account' : 'New account');
    $('f-name').value = item ? item.account : '';
    $('f-user').value = item ? item.user : '';
    $('f-pwd').value = item ? item.pwd : '';
    $('f-pwd').type = 'password';
    paintMeter($('entry-meter'), $('f-pwd').value);
    show($('entry-error'), false);
    entryDialog.showModal();
    $('f-name').focus();
  }
  $('add-btn').addEventListener('click', () => openEntry(null));
  $('f-pwd').addEventListener('input', e => paintMeter($('entry-meter'), e.target.value));
  $('gen-len').addEventListener('input', e => setText($('len-out'), e.target.value));

  function generate(length, symbols) {
    const sets = ['abcdefghijkmnopqrstuvwxyz', 'ABCDEFGHJKLMNPQRSTUVWXYZ', '23456789'];
    if (symbols) sets.push('!@#$%^&*()-_=+[]{};:,.?');
    const all = sets.join('');
    const pick = chars => {               // unbiased pick via rejection sampling
      const limit = Math.floor(0x100000000 / chars.length) * chars.length;
      const buf = new Uint32Array(1);
      do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
      return chars[buf[0] % chars.length];
    };
    const out = sets.map(pick);           // guarantee one of each class
    while (out.length < length) out.push(pick(all));
    return shuffle(out).join('');
  }
  function shuffle(arr) {
    for (let i = arr.length - 1; i > 0; i--) {
      const limit = Math.floor(0x100000000 / (i + 1)) * (i + 1);
      const buf = new Uint32Array(1);
      do { crypto.getRandomValues(buf); } while (buf[0] >= limit);
      const j = buf[0] % (i + 1);
      [arr[i], arr[j]] = [arr[j], arr[i]];
    }
    return arr;
  }
  $('gen-btn').addEventListener('click', () => {
    const pwd = generate(Number($('gen-len').value), $('gen-sym').checked);
    $('f-pwd').value = pwd;
    $('f-pwd').type = 'text';
    paintMeter($('entry-meter'), pwd);
  });

  $('entry-form').addEventListener('submit', async e => {
    e.preventDefault();
    const account = $('f-name').value.trim();
    const user = $('f-user').value.trim();
    const pwd = $('f-pwd').value;
    if (!account || !pwd) { setText($('entry-error'), 'Account name and password are required.'); return show($('entry-error'), true); }
    const btn = $('entry-save');
    btn.disabled = true;
    try {
      const enc = await encrypt(key, pwd);
      const body = { accountName: account, accountUsername: user, passwordIvHex: enc.iv, passwordDataHex: enc.data };
      if (editingId === null) {
        const { id } = await api('entries.php', { method: 'POST', body });
        vault.unshift({ id, account, user, pwd });
      } else {
        await api('entries.php?id=' + encodeURIComponent(editingId), { method: 'PUT', body });
        const i = vault.findIndex(v => v.id === editingId);
        if (i >= 0) vault[i] = { id: editingId, account, user, pwd };
      }
      entryDialog.close();
      render();
      toast('Saved');
    } catch (err) {
      if (err.status === 401) return lock('Session expired. Please sign in again.');
      setText($('entry-error'), err.message); show($('entry-error'), true);
    } finally { btn.disabled = false; }
  });

  /* ---------- Delete ---------- */
  const delDialog = $('del-dialog');
  function askDelete(item) {
    pendingDeleteId = item.id;
    setText($('del-text'), `“${item.account}” will be permanently removed from your vault.`);
    delDialog.showModal();
  }
  $('del-confirm').addEventListener('click', async () => {
    const id = pendingDeleteId;
    try {
      await api('entries.php?id=' + encodeURIComponent(id), { method: 'DELETE' });
      vault = vault.filter(v => v.id !== id);
      revealed.delete(id);
      delDialog.close();
      render();
      toast('Deleted');
    } catch (err) {
      if (err.status === 401) return lock('Session expired. Please sign in again.');
      delDialog.close();
      toast(err.message, true);
    }
  });

  document.addEventListener('click', e => {
    if (e.target.closest('[data-close]')) e.target.closest('dialog').close();
    if (e.target instanceof HTMLDialogElement) e.target.close();   // click on backdrop
  });

  /* ---------- Boot ---------- */
  try {
    const notice = sessionStorage.getItem('kv_notice');
    if (notice) { sessionStorage.removeItem('kv_notice'); toast(notice); }
  } catch { /* storage unavailable */ }
  setMode('login');
})();
