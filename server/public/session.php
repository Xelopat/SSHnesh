<?php
declare(strict_types=1);
require __DIR__ . '/../common.php';

$method = $_SERVER['REQUEST_METHOD'];
if ($method === 'DELETE') {
    $db = database();
    [$hash] = session_for($db);
    $db->prepare('DELETE FROM sessions WHERE token_hash = ?')->execute([$hash]);
    reply(200, ['ok' => true]);
}
if ($method !== 'POST') {
    header('Allow: POST, DELETE');
    reply(405, ['error' => 'method_not_allowed']);
}
$data = input_json(4096);
if (!matches('/^[A-Za-z0-9_-]{1,1500}\.[a-f0-9]{64}$/D', $data['code'] ?? null) ||
    !matches('/^[a-f0-9]{64}$/D', $data['verifier'] ?? null)) reply(401, ['error' => 'invalid_grant']);
$secret = getenv('SSHNESH_ACCOUNT_SECRET');
if (!matches('/^[a-f0-9]{64}$/D', $secret)) throw new RuntimeException('Missing account secret');
[$payload, $signature] = explode('.', $data['code'], 2);
if (!hash_equals(hash_hmac('sha256', $payload, hex2bin($secret)), $signature))
    reply(401, ['error' => 'invalid_grant']);
$claims = json_decode((string)base64_decode(strtr($payload, '-_', '+/'), true), true);
$now = time();
if (!is_array($claims) || ($claims['aud'] ?? null) !== ACCOUNT_AUDIENCE ||
    !matches('/^[a-f0-9]{16}$/D', $claims['sub'] ?? null) ||
    !matches('/^[A-Za-z0-9_.-]{3,32}$/D', $claims['username'] ?? null) ||
    !matches('/^[a-f0-9]{32}$/D', $claims['id'] ?? null) ||
    !is_int($claims['exp'] ?? null) || $claims['exp'] <= $now || $claims['exp'] > $now + 120 ||
    !is_string($claims['challenge'] ?? null) || !hash_equals(hash('sha256', $data['verifier']), $claims['challenge']))
    reply(401, ['error' => 'invalid_grant']);

$db = database();
$token = bin2hex(random_bytes(32));
$expires = $now + 43200;
$db->beginTransaction();
$db->prepare('DELETE FROM sessions WHERE expires <= ?')->execute([$now]);
$db->prepare('DELETE FROM grants WHERE expires <= ?')->execute([$now]);
$grant = $db->prepare('INSERT INTO grants (id, expires) VALUES (?, ?) ON CONFLICT(id) DO NOTHING');
$grant->execute([$claims['id'], $claims['exp']]);
if ($grant->rowCount() !== 1) {
    $db->rollBack();
    reply(401, ['error' => 'invalid_grant']);
}
$db->prepare('INSERT INTO sessions (token_hash, subject, expires) VALUES (?, ?, ?)')
    ->execute([hash('sha256', $token), $claims['sub'], $expires]);
$db->commit();
reply(200, ['subject' => $claims['sub'], 'username' => $claims['username'], 'token' => $token, 'expires' => $expires]);
