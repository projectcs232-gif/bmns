<?php
declare(strict_types=1);
require __DIR__ . '/../includes/bootstrap.php';
kv_api_init(['POST']);

try {
    kv_rate_limit('auth', 25, 900);
    $b = kv_body();
    if (!kv_text($b['email'] ?? null, 320)) {
        kv_json(400, ['error' => 'Enter your email.']);
    }
    $email = kv_norm_email($b['email']);

    $st = kv_db()->prepare('SELECT id, salt_hex, verifier_iv_hex, verifier_data_hex FROM vault_users WHERE email_normalized = ?');
    $st->execute([$email]);
    $u = $st->fetch();

    session_regenerate_id(true);
    if ($u) {
        $_SESSION['uid'] = (int) $u['id'];
        kv_json(200, [
            'saltHex'         => $u['salt_hex'],
            'verifierIvHex'   => $u['verifier_iv_hex'],
            'verifierDataHex' => $u['verifier_data_hex'],
        ]);
    }

    // Unknown email: return a stable, random-looking challenge so the response
    // does not reveal whether an account exists. The client simply fails to
    // decrypt it and shows "incorrect email or master password".
    $h = fn(string $label): string => hash_hmac('sha256', $label . '|' . $email, kv_secret());
    $_SESSION['uid'] = 0;
    kv_json(200, [
        'saltHex'         => substr($h('salt'), 0, 32),
        'verifierIvHex'   => substr($h('iv'), 0, 24),
        'verifierDataHex' => $h('data'),
    ]);
} catch (Throwable $e) {
    kv_fail($e, 'Sign in failed.');
}
