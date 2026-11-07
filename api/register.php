<?php
declare(strict_types=1);
require __DIR__ . '/../includes/bootstrap.php';
kv_api_init(['POST']);

try {
    kv_rate_limit('auth', 25, 900);
    $b = kv_body();
    if (!kv_email($b['email'] ?? null) || !kv_hex($b['saltHex'] ?? null, 32)
        || !kv_hex($b['verifierIvHex'] ?? null, 24) || !kv_hex($b['verifierDataHex'] ?? null)) {
        kv_json(400, ['error' => 'Invalid registration details.']);
    }
    $email = kv_norm_email($b['email']);
    $st = kv_db()->prepare('INSERT INTO vault_users (email, salt_hex, verifier_iv_hex, verifier_data_hex) VALUES (?, ?, ?, ?)');
    $st->execute([$email, $b['saltHex'], $b['verifierIvHex'], $b['verifierDataHex']]);

    session_regenerate_id(true);
    $_SESSION['uid'] = (int) kv_db()->lastInsertId();
    kv_json(201, ['ok' => true]);
} catch (PDOException $e) {
    if (kv_is_duplicate($e)) {
        kv_json(409, ['error' => 'This email already exists. Please sign in.']);
    }
    kv_fail($e, 'Could not create account.');
}
