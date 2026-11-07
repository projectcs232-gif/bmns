<?php
declare(strict_types=1);
require __DIR__ . '/../includes/bootstrap.php';
kv_api_init(['POST']);

$configured = (string) (kv_config()['migration_key'] ?? '');
if ($configured === '') {
    kv_json(403, ['error' => 'Import is disabled. Set migration_key in config/config.php first.']);
}

try {
    kv_rate_limit('migrate', 10, 900);
    $sent = $_SERVER['HTTP_X_MIGRATION_KEY'] ?? '';
    if (!is_string($sent) || !hash_equals($configured, $sent)) {
        kv_json(401, ['error' => 'Invalid migration key.']);
    }

    $accounts = kv_body()['accounts'] ?? null;
    if (!is_array($accounts) || array_is_list($accounts)) {
        kv_json(400, ['error' => 'Upload the exported keyvault_accounts JSON backup.']);
    }

    $pdo = kv_db();
    $pdo->beginTransaction();
    $users = $entries = $skipped = 0;

    foreach ($accounts as $email => $rec) {
        $email = (string) $email;
        if (!kv_text($email, 320) || !is_array($rec) || !kv_hex($rec['salt'] ?? null, 32)
            || !is_array($rec['verifier'] ?? null) || !kv_hex($rec['verifier']['iv'] ?? null, 24)
            || !kv_hex($rec['verifier']['data'] ?? null) || !is_array($rec['vault'] ?? null)) {
            $skipped++;
            continue;
        }
        $norm = kv_norm_email($email);

        $mark = $pdo->prepare('SELECT 1 FROM legacy_imports WHERE legacy_email = ?');
        $mark->execute([$norm]);
        if ($mark->fetch()) { $skipped++; continue; }

        $st = $pdo->prepare('SELECT id FROM vault_users WHERE email_normalized = ?');
        $st->execute([$norm]);
        $existing = $st->fetch();

        if ($existing) {
            $uid = (int) $existing['id'];
            $pdo->prepare('UPDATE vault_users SET salt_hex = ?, verifier_iv_hex = ?, verifier_data_hex = ? WHERE id = ?')
                ->execute([$rec['salt'], $rec['verifier']['iv'], $rec['verifier']['data'], $uid]);
        } else {
            $pdo->prepare('INSERT INTO vault_users (email, salt_hex, verifier_iv_hex, verifier_data_hex) VALUES (?, ?, ?, ?)')
                ->execute([$norm, $rec['salt'], $rec['verifier']['iv'], $rec['verifier']['data']]);
            $uid = (int) $pdo->lastInsertId();
            $users++;
        }

        $ins = $pdo->prepare('INSERT INTO vault_entries (user_id, account_name, account_username, password_iv_hex, password_data_hex) VALUES (?, ?, ?, ?, ?)');
        foreach ($rec['vault'] as $e) {
            if (!is_array($e) || !kv_text($e['account'] ?? null, 255) || !is_string($e['user'] ?? null)
                || mb_strlen($e['user']) > 320 || !is_array($e['encryptedPwd'] ?? null)
                || !kv_hex($e['encryptedPwd']['iv'] ?? null, 24) || !kv_hex($e['encryptedPwd']['data'] ?? null)) {
                $skipped++;
                continue;
            }
            $ins->execute([$uid, $e['account'], $e['user'], $e['encryptedPwd']['iv'], $e['encryptedPwd']['data']]);
            $entries++;
        }
        $pdo->prepare('INSERT INTO legacy_imports (legacy_email) VALUES (?)')->execute([$norm]);
    }

    $pdo->commit();
    kv_json(200, ['ok' => true, 'importedUsers' => $users, 'importedEntries' => $entries, 'skipped' => $skipped]);
} catch (Throwable $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    kv_fail($e, 'Import failed; nothing was changed.');
}
