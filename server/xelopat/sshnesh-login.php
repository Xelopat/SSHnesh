<?php
declare(strict_types=1);
require_once __DIR__ . '/auth/lib.php';

header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');
header('X-Content-Type-Options: nosniff');
$method = $_SERVER['REQUEST_METHOD'];
if ($method !== 'POST' && $method !== 'GET') {
    http_response_code(405);
    header('Allow: GET, POST');
    exit;
}
$input = $method === 'POST' ? $_POST : $_GET;
$port = filter_var($input['port'] ?? null, FILTER_VALIDATE_INT, ['options' => ['min_range' => 1024, 'max_range' => 65535]]);
$state = $input['state'] ?? null;
$challenge = $input['challenge'] ?? null;
if ($port === false || !is_string($state) || !preg_match('/^[a-f0-9]{64}$/D', $state) ||
    !is_string($challenge) || !preg_match('/^[a-f0-9]{64}$/D', $challenge)) {
    http_response_code(400);
    exit('Откройте вход из приложения SSHnesh.');
}
$callback = 'http://127.0.0.1:' . $port;
header("Content-Security-Policy: default-src 'none'; form-action 'self' $callback; frame-ancestors 'none'; base-uri 'none'");
$next = '/sshnesh-login?' . http_build_query(['port' => $port, 'state' => $state, 'challenge' => $challenge]);
$user = auth_current_user();
if (!$user) {
    header('Location: /auth/login?next=' . rawurlencode($next), true, 303);
    exit;
}
if ($method === 'POST') {
    if (!is_string($input['csrf'] ?? null) || !csrf_check($input['csrf'])) {
        http_response_code(403);
        exit('Сессия устарела. Откройте вход из SSHnesh заново.');
    }
    $secret = getenv('SSHNESH_ACCOUNT_SECRET');
    if (!is_string($secret) || !preg_match('/^[a-f0-9]{64}$/D', $secret)) {
        http_response_code(503);
        exit('Вход в SSHnesh пока недоступен.');
    }
    $claims = ['aud' => 'https://sshnesh.xelopat.ru', 'sub' => $user['id'], 'username' => $user['username'],
        'id' => bin2hex(random_bytes(16)), 'exp' => time() + 90, 'challenge' => $challenge];
    $payload = rtrim(strtr(base64_encode(json_encode($claims, JSON_THROW_ON_ERROR)), '+/', '-_'), '=');
    $code = $payload . '.' . hash_hmac('sha256', $payload, hex2bin($secret));
    $query = http_build_query(['state' => $state, 'code' => $code]);
    header('Location: ' . $callback . '/sshnesh-callback?' . $query, true, 303);
    exit;
}
?>
<!doctype html>
<html lang="ru">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Вход в SSHnesh</title>
<main>
  <h1>Вход в SSHnesh</h1>
  <p>Подключить аккаунт <?= h($user['username']) ?> к приложению SSHnesh на этом устройстве?</p>
  <form method="post" action="/sshnesh-login">
    <input type="hidden" name="csrf" value="<?= h(csrf_token()) ?>">
    <input type="hidden" name="port" value="<?= $port ?>">
    <input type="hidden" name="state" value="<?= h($state) ?>">
    <input type="hidden" name="challenge" value="<?= h($challenge) ?>">
    <button type="submit">Подключить аккаунт</button>
  </form>
</main>
</html>
