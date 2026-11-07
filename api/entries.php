<?php
declare(strict_types=1);
require __DIR__ . '/../includes/bootstrap.php';
kv_api_init(['GET', 'POST', 'PUT', 'DELETE']);
$uid = kv_require_user();

try {
    kv_rate_limit('api', 300, 60, 'u' . $uid . '|' . ($_SERVER['REMOTE_ADDR'] ?? ''));
    $pdo = kv_db();
    $method = $_SERVER['REQUEST_METHOD'];

    if ($method === 'GET') {
        $st = $pdo->prepare('SELECT id, account_name, account_username, password_iv_hex, password_data_hex
                             FROM vault_entries WHERE user_id = ? ORDER BY created_at DESC, id DESC');
        $st->execute([$uid]);
        kv_json(200, ['entries' => $st->fetchAll()]);
    }

    $id = $_GET['id'] ?? '';
    if ($method !== 'POST' && !preg_match('/^\d+$/', (string) $id)) {
        kv_json(400, ['error' => 'Invalid ID.']);
    }

    if ($method === 'DELETE') {
        $st = $pdo->prepare('DELETE FROM vault_entries WHERE id = ? AND user_id = ?');
        $st->execute([$id, $uid]);
        $st->rowCount() ? kv_json(200, ['ok' => true]) : kv_json(404, ['error' => 'Credential not found.']);
    }

    $b = kv_body();
    if (!kv_text($b['accountName'] ?? null, 255)
        || !is_string($b['accountUsername'] ?? null) || mb_strlen($b['accountUsername']) > 320
        || !kv_hex($b['passwordIvHex'] ?? null, 24) || !kv_hex($b['passwordDataHex'] ?? null)) {
        kv_json(400, ['error' => 'Invalid credential details.']);
    }
    $vals = [trim($b['accountName']), trim($b['accountUsername']), $b['passwordIvHex'], $b['passwordDataHex']];

    if ($method === 'POST') {
        $pdo->prepare('INSERT INTO vault_entries (account_name, account_username, password_iv_hex, password_data_hex, user_id) VALUES (?, ?, ?, ?, ?)')
            ->execute([...$vals, $uid]);
        kv_json(201, ['id' => (int) $pdo->lastInsertId()]);
    }

    // PUT
    $st = $pdo->prepare('UPDATE vault_entries SET account_name = ?, account_username = ?, password_iv_hex = ?, password_data_hex = ? WHERE id = ? AND user_id = ?');
    $st->execute([...$vals, $id, $uid]);
    // MySQL reports 0 affected rows when nothing changed, so confirm existence separately.
    if (!$st->rowCount()) {
        $chk = $pdo->prepare('SELECT 1 FROM vault_entries WHERE id = ? AND user_id = ?');
        $chk->execute([$id, $uid]);
        if (!$chk->fetch()) {
            kv_json(404, ['error' => 'Credential not found.']);
        }
    }
    kv_json(200, ['ok' => true]);
} catch (PDOException $e) {
    kv_fail($e, 'Could not complete the request.');
}
