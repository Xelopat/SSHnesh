<?php
declare(strict_types=1);

const MAX_VAULT_REQUEST = 32 * 1024 * 1024;
const MAX_REVISION = 2000000000;
const ACCOUNT_AUDIENCE = 'https://sshnesh.xelopat.ru';

function reply(int $status, array $payload): never {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    header('X-Content-Type-Options: nosniff');
    echo json_encode($payload, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
    exit;
}

function input_json(int $max): array {
    $body = file_get_contents('php://input', false, null, 0, $max + 1);
    if ($body === false || strlen($body) > $max) reply(413, ['error' => 'request_too_large']);
    try {
        $data = json_decode($body, true, 12, JSON_THROW_ON_ERROR);
    } catch (JsonException $exception) {
        reply(400, ['error' => 'invalid_json']);
    }
    if (!is_array($data)) reply(400, ['error' => 'invalid_json']);
    return $data;
}

function matches(string $pattern, mixed $value): bool {
    return is_string($value) && preg_match($pattern, $value) === 1;
}

function database(): PDO {
    $file = getenv('SSHNESH_SYNC_DB');
    $root = realpath(__DIR__ . '/public');
    $directory = $file ? realpath(dirname($file)) : false;
    if ($directory === false || !$root || strcasecmp($directory, $root) === 0 ||
        stripos($directory . DIRECTORY_SEPARATOR, $root . DIRECTORY_SEPARATOR) === 0 ||
        is_link($file)) throw new RuntimeException('Invalid database path');
    umask(0077);
    $db = new PDO('sqlite:' . $directory . DIRECTORY_SEPARATOR . basename($file));
    $db->exec('PRAGMA busy_timeout = 5000');
    $db->exec('CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY, subject TEXT NOT NULL, expires INTEGER NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS vaults (
        subject TEXT PRIMARY KEY, revision INTEGER NOT NULL, envelope TEXT NOT NULL
    )');
    $db->exec('CREATE TABLE IF NOT EXISTS grants (id TEXT PRIMARY KEY, expires INTEGER NOT NULL)');
    return $db;
}

function session_for(PDO $db): array {
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer ([a-f0-9]{64})$/D', $header, $match)) reply(401, ['error' => 'unauthorized']);
    $hash = hash('sha256', $match[1]);
    $query = $db->prepare('SELECT subject FROM sessions WHERE token_hash = ? AND expires > ?');
    $query->execute([$hash, time()]);
    $subject = $query->fetchColumn();
    if ($subject === false) reply(401, ['error' => 'unauthorized']);
    return [$hash, $subject];
}

set_exception_handler(static function (Throwable $error): void {
    error_log('SSHnesh sync failed (' . get_class($error) . ')');
    reply(500, ['error' => 'server_error']);
});
