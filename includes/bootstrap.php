<?php
declare(strict_types=1);

/**
 * Shared bootstrap: config, security headers, session, database, helpers.
 */

const KV_ROOT = __DIR__ . '/..';

ini_set('display_errors', '0');
ini_set('log_errors', '1');
error_reporting(E_ALL);

function kv_config(): array
{
    static $cfg = null;
    return $cfg ??= require KV_ROOT . '/config/config.php';
}

function kv_is_https(): bool
{
    return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
}

function kv_security_headers(bool $api): void
{
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: camera=(), microphone=(), geolocation=()');
    header("Content-Security-Policy: default-src 'self'; img-src 'self' data:; "
         . "style-src 'self'; script-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
    if ($api) {
        header('Cache-Control: no-store');
    }
}

function kv_session_start(): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        return;
    }
    session_name('kv_session');
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'secure'   => kv_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();

    $idle = max(1, (int) (kv_config()['session_idle_minutes'] ?? 30)) * 60;
    if (isset($_SESSION['last_seen']) && time() - $_SESSION['last_seen'] > $idle) {
        $_SESSION = [];
        session_regenerate_id(true);
    }
    $_SESSION['last_seen'] = time();
    if (empty($_SESSION['csrf'])) {
        $_SESSION['csrf'] = bin2hex(random_bytes(32));
    }
}

function kv_db(): PDO
{
    static $pdo = null;
    if ($pdo) {
        return $pdo;
    }
    $opts = [
        PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES   => false,
    ];
    $testDsn = getenv('KV_TEST_DSN'); // used only by the automated tests
    if ($testDsn) {
        return $pdo = new PDO($testDsn, null, null, $opts);
    }
    $c = kv_config()['db'];
    $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', $c['host'], $c['port'], $c['name']);
    return $pdo = new PDO($dsn, $c['user'], $c['pass'], $opts);
}

/** Per-installation secret (used to make unknown-account logins indistinguishable). */
function kv_secret(): string
{
    static $s = null;
    if ($s !== null) {
        return $s;
    }
    $file = KV_ROOT . '/storage/secret.key';
    if (!is_file($file)) {
        @file_put_contents($file, bin2hex(random_bytes(32)), LOCK_EX);
    }
    return $s = (string) @file_get_contents($file) ?: 'fallback-' . php_uname('n');
}

function kv_json(int $status, array $data): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_SLASHES);
    exit;
}

function kv_body(): array
{
    $raw = file_get_contents('php://input');
    $data = json_decode($raw ?: '', true);
    return is_array($data) ? $data : [];
}

/** Start an API request: headers, session, CSRF check for state-changing methods. */
function kv_api_init(array $methods): void
{
    kv_security_headers(true);
    if (!in_array($_SERVER['REQUEST_METHOD'], $methods, true)) {
        header('Allow: ' . implode(', ', $methods));
        kv_json(405, ['error' => 'Method not allowed.']);
    }
    kv_session_start();
    if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
        $sent = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
        if (!is_string($sent) || !hash_equals($_SESSION['csrf'], $sent)) {
            kv_json(403, ['error' => 'Security token mismatch. Reload the page and try again.']);
        }
    }
}

function kv_require_user(): int
{
    if (!isset($_SESSION['uid'])) {
        kv_json(401, ['error' => 'Session expired. Please log in again.']);
    }
    return (int) $_SESSION['uid'];
}

/** Fixed-window rate limiter backed by the database. */
function kv_rate_limit(string $name, int $limit, int $windowSeconds, ?string $subject = null): void
{
    $pdo = kv_db();
    $pdo->exec('CREATE TABLE IF NOT EXISTS rate_limits (
        bucket CHAR(64) NOT NULL PRIMARY KEY,
        hits INT NOT NULL,
        window_start INT NOT NULL
    )');
    $bucket = hash('sha256', $name . '|' . ($subject ?? ($_SERVER['REMOTE_ADDR'] ?? 'unknown')));
    $now = time();

    $st = $pdo->prepare('SELECT hits, window_start FROM rate_limits WHERE bucket = ?');
    $st->execute([$bucket]);
    $row = $st->fetch();

    if (!$row || $now - (int) $row['window_start'] >= $windowSeconds) {
        $pdo->prepare('DELETE FROM rate_limits WHERE bucket = ?')->execute([$bucket]);
        $pdo->prepare('INSERT INTO rate_limits (bucket, hits, window_start) VALUES (?, 1, ?)')->execute([$bucket, $now]);
        return;
    }
    if ((int) $row['hits'] >= $limit) {
        $retry = $windowSeconds - ($now - (int) $row['window_start']);
        header('Retry-After: ' . max(1, $retry));
        kv_json(429, ['error' => 'Too many attempts. Please wait a few minutes and try again.']);
    }
    $pdo->prepare('UPDATE rate_limits SET hits = hits + 1 WHERE bucket = ?')->execute([$bucket]);
}

function kv_hex(mixed $v, ?int $len = null): bool
{
    return is_string($v) && $v !== '' && ctype_xdigit($v) && strlen($v) % 2 === 0
        && ($len === null || strlen($v) === $len);
}

function kv_text(mixed $v, int $max): bool
{
    return is_string($v) && trim($v) !== '' && mb_strlen($v) <= $max;
}

function kv_email(mixed $v): bool
{
    return kv_text($v, 320) && preg_match('/^[^@\s]+@[^@\s]+\.[^@\s]+$/', $v) === 1;
}

function kv_norm_email(string $e): string
{
    return mb_strtolower(trim($e));
}

function kv_is_duplicate(PDOException $e): bool
{
    return $e->getCode() === '23000';
}

function kv_fail(PDOException|Throwable $e, string $message): never
{
    error_log('[KeyVault] ' . $e->getMessage());
    kv_json(500, ['error' => $message]);
}
