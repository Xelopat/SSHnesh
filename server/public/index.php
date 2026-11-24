<?php
declare(strict_types=1);
require __DIR__ . '/../common.php';

header('Vary: Accept');
if (!str_contains($_SERVER['HTTP_ACCEPT'] ?? '', 'text/html')) {
    database();
    reply(200, ['service' => 'SSHnesh sync', 'status' => 'ok']);
}

$nonce = base64_encode(random_bytes(18));
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header("Content-Security-Policy: default-src 'none'; style-src 'nonce-$nonce'; frame-ancestors 'none'; base-uri 'none'");
?>
<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SSHnesh</title>
  <style nonce="<?= htmlspecialchars($nonce, ENT_QUOTES, 'UTF-8') ?>">
    body { margin: 0; min-height: 100svh; box-sizing: border-box; padding: 24px; display: grid; place-items: center; background: #151518; color: #efeff1; font: 16px/1.55 system-ui, sans-serif; }
    main { box-sizing: border-box; width: min(100%, 600px); padding: clamp(24px, 6vw, 40px); border: 1px solid #333340; border-radius: 8px; background: #1e1e25; box-shadow: 0 18px 40px #0004; }
    h1 { margin: 0; font-size: clamp(32px, 7vw, 48px); letter-spacing: -.035em; }
    p { margin: 8px 0 24px; color: #9496a8; }
    nav { display: flex; flex-wrap: wrap; gap: 12px; }
    a { border: 1px solid #575767; border-radius: 6px; padding: 9px 14px; color: #efeff1; text-decoration: none; }
    a:hover, a:focus-visible { border-color: #f9c940; }
    .download { background: #f9c940; color: #151518; border-color: transparent; font-weight: 700; }
    .download:hover, .download:focus-visible { background: #ffd65c; }
    .downloads { display: grid; gap: 8px; margin-bottom: 20px; }
    .download { display: flex; justify-content: space-between; align-items: baseline; gap: 8px; flex-wrap: wrap; }
    .download small { font-weight: 500; }
    li + li { margin-top: 6px; }
    code { overflow-wrap: anywhere; }
  </style>
</head>
<body>
  <main>
    <h1>SSHnesh</h1>
    <p>SSH и SFTP для Windows, Linux и Android. В настольных сборках MCP уже встроен.</p>
    <h2>Скачать SSHnesh</h2>
    <nav class="downloads" aria-label="Скачать SSHnesh">
      <a class="download" href="/downloads/0.1.2/SSHnesh-0.1.2-native-win-x64.zip" download>Windows x64 <small>ZIP · 4,81 МБ</small></a>
      <a class="download" href="/downloads/0.1.2/SSHnesh-0.1.2-native-linux-amd64.deb" download>Linux amd64 <small>DEB · 4,10 МБ</small></a>
      <a class="download" href="/downloads/0.1.2/SSHnesh-0.1.2-native-android-arm64.apk" download>Android ARM64 <small>APK · 14,60 МБ</small></a>
    </nav>
    <p>Чтобы открывать хранилище без повторного ввода мастер-пароля, отметьте «Запомнить на этом устройстве» при открытии хранилища. В настройках можно выбрать «Забыть ключ».</p>
    <p>При переходе с Electron откройте старое приложение и сохраните последние изменения в облаке. Затем откройте тот же аккаунт в новой версии и скачайте хранилище.</p>
    <h2>Подключить к Codex</h2>
    <ol>
      <li>Запустите настольный SSHnesh. В карточке сервера откройте «Учётки» и настройте <code>debug</code>.</li>
      <li>В SSHnesh нажмите «MCP → Скопировать команду для Codex» и выполните её в PowerShell или терминале.</li>
      <li>Откройте новый чат и попросите: «Покажи серверы из SSHnesh».</li>
    </ol>
    <p>Если сервер уже открыт в SSHnesh, можно сказать: «Посмотри ошибки на текущем сервере».</p>
    <p>Если настраиваете MCP вручную, укажите полный путь к SSHnesh как команду, а <code>--mcp</code> как аргумент. Node.js для этого не нужен. На Android MCP пока недоступен.</p>
    <nav aria-label="Ссылки проекта">
      <a href="https://github.com/Xelopat/SSHnesh">Проект на GitHub</a>
    </nav>
  </main>
</body>
</html>
