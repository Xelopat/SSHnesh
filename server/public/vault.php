<?php
declare(strict_types=1);
require __DIR__ . '/../common.php';

$method = $_SERVER['REQUEST_METHOD'];
if ($method !== 'GET' && $method !== 'PUT') {
    header('Allow: GET, PUT');
    reply(405, ['error' => 'method_not_allowed']);
}
$db = database();
[, $subject] = session_for($db);

if ($method === 'GET') {
    $query = $db->prepare('SELECT revision, envelope FROM vaults WHERE subject = ?');
    $query->execute([$subject]);
    $row = $query->fetch(PDO::FETCH_ASSOC);
    if ($row) {
        $v = json_decode($row['envelope'], true, 12, JSON_THROW_ON_ERROR);
        $tag = '"' . (int)$row['revision'] . '-' . hash('sha256', $v['salt'] . $v['iv'] . $v['tag'] . $v['body']) . '"';
        header('ETag: ' . $tag);
        if (($_SERVER['HTTP_IF_NONE_MATCH'] ?? '') === $tag) {
            http_response_code(304);
            exit;
        }
    }
    reply(200, $row ? [
        'revision' => (int)$row['revision'],
        'vault' => json_decode($row['envelope'], true, 12, JSON_THROW_ON_ERROR),
    ] : ['revision' => 0, 'vault' => null]);
}

$data = input_json(MAX_VAULT_REQUEST);
$revision = $data['revision'] ?? null;
$vault = $data['vault'] ?? null;
if (!is_int($revision) || $revision < 0 || $revision >= MAX_REVISION || count($data) !== 2 ||
    !is_array($vault) || count($vault) !== 5 || ($vault['version'] ?? null) !== 1 ||
    !matches('/^[a-f0-9]{32}$/D', $vault['salt'] ?? null) ||
    !matches('/^[a-f0-9]{24}$/D', $vault['iv'] ?? null) ||
    !matches('/^[a-f0-9]{32}$/D', $vault['tag'] ?? null) || !is_string($vault['body'] ?? null) ||
    strlen($vault['body']) > MAX_VAULT_REQUEST - 1024 || strlen($vault['body']) < 4 ||
    strlen($vault['body']) % 4 !== 0 || base64_decode($vault['body'], true) === false)
    reply(400, ['error' => 'invalid_envelope']);

$encoded = json_encode($vault, JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
if ($revision === 0) {
    $query = $db->prepare('INSERT INTO vaults (subject, revision, envelope) VALUES (?, 1, ?) ON CONFLICT(subject) DO NOTHING');
    $query->execute([$subject, $encoded]);
} else {
    $query = $db->prepare('UPDATE vaults SET revision = revision + 1, envelope = ? WHERE subject = ? AND revision = ?');
    $query->execute([$encoded, $subject, $revision]);
}
if ($query->rowCount() !== 1) reply(409, ['error' => 'revision_conflict']);
reply(200, ['revision' => $revision + 1]);
