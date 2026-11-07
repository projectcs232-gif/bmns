<?php
declare(strict_types=1);
require __DIR__ . '/../includes/bootstrap.php';
kv_api_init(['POST']);
$_SESSION = [];
session_destroy();
kv_json(200, ['ok' => true]);
