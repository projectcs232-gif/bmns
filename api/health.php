<?php
declare(strict_types=1);
require __DIR__ . '/../includes/bootstrap.php';
kv_security_headers(true);
try {
    kv_db()->query('SELECT 1');
    kv_json(200, ['status' => 'ok', 'database' => 'connected']);
} catch (Throwable $e) {
    error_log('[KeyVault] ' . $e->getMessage());
    kv_json(503, ['status' => 'error', 'database' => 'unavailable']);
}
