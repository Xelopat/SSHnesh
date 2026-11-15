const assert = require('node:assert/strict');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { spawn, execFileSync } = require('node:child_process');
const { randomUUID } = require('node:crypto');
const { _electron: electron } = require('playwright');
const { Client } = require('@modelcontextprotocol/sdk/client/index.js');
const { Server: SshServer } = require('ssh2');
const { StdioClientTransport } = require('@modelcontextprotocol/sdk/client/stdio.js');
const { address } = require('../src/wire.cjs');

const root = path.resolve(__dirname, '..');
const distribution = process.env.SSHASH_TEST_WSL || 'Ubuntu';
const id = randomUUID();
const work = '/tmp/sshash-lab.' + id;
const profile = fs.mkdtempSync(path.join(os.tmpdir(), 'sshash-e2e-'));
const agent = '//./pipe/sshash-test-agent-' + id;
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let server, proxy, listener, sshPort, app, transport, mcp, labScript, operator, passwordServer;
let serverLog = '';
const agentSockets = new Set();
const proxySockets = new Set();
const passwordClients = new Set();
const failAfter = 12000;
const screenshot = path.join(root, 'test-artifacts', 'windows-mcp.png');

function wsl(args, options = {}) {
  return execFileSync('wsl.exe', ['-d', distribution, ...args], {
    encoding: 'utf8', windowsHide: true, timeout: 20000, stdio: ['ignore', 'pipe', 'pipe'], ...options,
  }).replace(/\0/g, '').trim();
}
function lab(action, ...args) {
  return wsl(['-u', 'root', '--', 'sh', labScript, work, operator, String(sshPort), action, ...args]);
}
async function waitFor(fn, label, timeout = failAfter) {
  const end = Date.now() + timeout;
  while (Date.now() < end) {
    const value = await fn();
    if (value) return value;
    await sleep(50);
  }
  throw Error('Timed out: ' + label);
}
function startServer(key) {
  serverLog = '';
  server = spawn('wsl.exe', ['-d', distribution, '-u', 'root', '--', 'sh', labScript, work,
    operator, String(sshPort), 'serve', key], { windowsHide: true });
  server.stdout.resume();
  server.stderr.on('data', data => { serverLog = (serverLog + data.toString()).slice(-4000); });
  return waitFor(() => {
    if (server.exitCode !== null) throw Error('sshd exited: ' + server.exitCode);
    try { return Boolean(wsl(['--exec', 'cat', work + '/sshd.pid'])); } catch { return false; }
  }, 'sshd listening');
}
function forward(socket, args, sockets) {
  sockets.add(socket);
  const relay = spawn('wsl.exe', ['-d', distribution, ...args], { windowsHide: true });
  relay.stderr.resume();
  socket.pipe(relay.stdin);
  relay.stdout.pipe(socket);
  relay.stdin.on('error', () => socket.destroy());
  relay.on('error', () => socket.destroy());
  relay.on('close', () => socket.destroy());
  socket.on('error', () => socket.destroy());
  socket.on('close', () => { sockets.delete(socket); relay.kill(); });
}
function listen(server, endpoint) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(endpoint, resolve);
  });
}
function report(message) { console.log('PASS ' + message); }

async function main() {
  assert.equal(process.platform, 'win32');
  labScript = wsl(['--exec', 'wslpath', '-a', path.join(__dirname, 'lab.sh')]);
  operator = wsl(['--', 'id', '-un']);
  sshPort = 32000 + Math.floor(Math.random() * 16000);
  lab('setup');
  await startServer('a');

  // Both listeners and both ends of the test SSH route are local. Agent contains just the disposable identity.
  proxy = net.createServer(socket => forward(socket, ['--', 'nc', '127.0.0.1', String(sshPort)], proxySockets));
  await listen(proxy, { port: 0, host: '127.0.0.1' });
  listener = net.createServer(socket => forward(socket, ['-u', 'root', '--', 'nc', '-U', work + '/agent.sock'], agentSockets));
  await listen(listener, agent);

  app = await electron.launch({
    args: [root], timeout: 30000,
    env: { ...process.env, SSHASH_TEST_LAUNCH: '1', SSHASH_TEST_PROFILE: profile, SSHASH_TEST_AGENT: agent },
  });
  const page = await app.firstWindow();
  const failures = [];
  page.on('pageerror', error => failures.push(error.message));
  page.on('console', msg => { if (msg.type() === 'error') failures.push(msg.text()); });
  page.setDefaultTimeout(failAfter);
  const ui = (...args) => page.evaluate(([method, values]) => window.sshash[method](...values), [args[0], args.slice(1)]);
  const snapshot = () => ui('state');
  const getSession = async sid => (await snapshot()).sessions.find(s => s.id === sid);
  const action = name => page.getByRole('button', { name, exact: true });
  const activePane = () => page.locator('.term-pane:not([hidden])');
  const hasLine = value => page.locator('.term-pane:not([hidden]) .xterm-rows > div').getByText(value, { exact: true }).count();
  const typeLine = async line => {
    await activePane().locator('textarea').focus();
    await page.keyboard.insertText(line);
    await page.keyboard.press('Enter');
  };
  assert.equal(await page.title(), 'SSHnesh');
  await page.getByRole('heading', { name: 'Серверы' }).waitFor();
  const homeNav = page.getByRole('navigation', { name: 'Разделы главной' });
  assert.equal(await homeNav.getByRole('button', { name: 'Известные хосты' }).count(), 0);
  await homeNav.getByRole('button', { name: 'Ключи' }).click();
  await page.getByText('Импортируйте файл приватного SSH-ключа.').waitFor();
  await homeNav.getByRole('button', { name: 'Серверы' }).click();
  await action('+ Добавить сервер').click();
  const form = page.locator('#host-form');
  await form.getByLabel('Название').fill('Тестовый сервер');
  await form.getByLabel('Группа').fill('Лаборатория');
  await form.getByLabel('Адрес').fill('127.0.0.1');
  await form.getByLabel('Порт').fill(String(proxy.address().port));
  await form.getByLabel('Пользователь').fill(operator);
  await action('Сохранить').click();
  const host = await waitFor(async () => (await snapshot()).hosts[0], 'saved host');
  await page.getByRole('button', { name: /Тестовый сервер.*@127/ }).click();
  await page.getByRole('heading', { name: 'Первое подключение' }).waitFor();
  const initial = await waitFor(async () => (await snapshot()).sessions[0]?.trust, 'host fingerprint');
  assert.ok(labFingerprint('a').includes(initial.fingerprint));
  await action('Доверять ключу').click();
  const first = await waitFor(async () => {
    const current = (await snapshot()).sessions[0];
    if (current?.error) throw Error(current.error + '\n' + serverLog.replace(/\0/g, ''));
    return current?.state === 'ready' && current;
  }, 'SSH ready');
  await typeLine("printf '%s\\n' 'Привет 世界'");
  await waitFor(() => hasLine('Привет 世界'), 'rendered Unicode');
  const size = await page.evaluate(() => document.querySelector('#foot-term').textContent.match(/(\d+)×(\d+)/).slice(1));
  await typeLine('stty size');
  await waitFor(() => hasLine(size[1] + ' ' + size[0]), 'remote PTY resize');
  report('Windows UI, real OpenSSH, fingerprint, Unicode and PTY resize');
  assert.equal(await homeNav.isVisible(), false);
  await page.getByRole('tab', { name: 'Главная' }).click();

  await page.getByRole('tab', { name: 'SFTP', exact: true }).click();
  assert.equal(await homeNav.isVisible(), false);
  await page.getByLabel('SSH-сеанс для SFTP').selectOption(first.generation);
  const fileStatus = page.locator('#file-error');
  await waitFor(async () => {
    const text = await fileStatus.textContent();
    if (text?.includes('Не удалось')) throw Error(text);
    return (await page.getByLabel('Удалённый путь').inputValue()) !== '.';
  }, 'initial SFTP directory');
  await page.getByLabel('Удалённый путь').fill(work + '/files');
  await action('Перейти').click();
  await waitFor(async () => {
    const text = await fileStatus.textContent();
    if (text?.includes('Не удалось')) throw Error(text);
    return text === 'Каталог пуст.';
  }, 'empty SFTP directory');
  const local = path.join(profile, 'sftp-local');
  const inbox = path.join(local, 'Скачано');
  const source = path.join(local, 'sftp-hello.txt');
  const download = path.join(inbox, 'sftp-hello.txt');
  fs.mkdirSync(inbox, { recursive: true });
  fs.writeFileSync(source, 'Проверка SFTP\n', 'utf8');
  // Replace only the native directory picker. Drag events, SSH and transfers stay real.
  await app.evaluate(({ dialog }, dir) => {
    dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [dir] });
  }, local);
  await action('Выбрать папку…').click();
  const localPane = page.getByRole('region', { name: 'Локальная панель' });
  const remotePane = page.getByRole('region', { name: 'Панель сервера' });
  const localRow = localPane.getByRole('row', { name: /sftp-hello.txt/ });
  const remoteRow = remotePane.getByRole('row', { name: /sftp-hello.txt/ });
  await localRow.dragTo(remotePane.locator('.file-scroll'), { targetPosition: { x: 50, y: 80 } });
  await remoteRow.waitFor();
  await action('Отправить на сервер · sftp-hello.txt').click();
  await page.getByText(/Не удалось отправить файл/).waitFor();
  await localPane.getByRole('button', { name: '▸ Скачано' }).click();
  await localPane.getByText('Каталог пуст.').waitFor();
  await remoteRow.dragTo(localPane.locator('.file-scroll'), { targetPosition: { x: 50, y: 80 } });
  await waitFor(() => fs.existsSync(download), 'SFTP download');
  assert.deepEqual(fs.readFileSync(download), fs.readFileSync(source));
  await localRow.waitFor();
  fs.mkdirSync(path.dirname(screenshot), { recursive: true });
  await page.screenshot({ path: path.join(path.dirname(screenshot), 'windows-sftp.png') });
  await action('Скачать в локальную папку · sftp-hello.txt').click();
  await page.getByText('В локальной папке уже есть файл с таким именем.').waitFor();
  await assert.rejects(ui('listLocal', await ui('chooseLocal'), '..'), /вне выбранной папки/);
  assert.equal(wsl(['--exec', 'cat', work + '/files/sftp-hello.txt']), 'Проверка SFTP');
  assert.deepEqual(fs.readFileSync(download), fs.readFileSync(source));
  report('two-pane SFTP, drag/drop both ways, byte equality, refused overwrites and local folder scope');
  await page.getByRole('tab', { name: 'Тестовый сервер' }).click();
  await action('MCP').click();
  await action('Настройка').click();
  const config = await app.evaluate(async ({ clipboard }) => JSON.parse(await clipboard.readText()).mcpServers.sshash);
  await app.evaluate(({ clipboard }) => clipboard.clear());
  await checkInvalidProof(config.env.SSHASH_MCP_TOKEN);
  transport = new StdioClientTransport({ ...config, stderr: 'pipe' });
  mcp = new Client({ name: 'sshash-e2e', version: '1.0.0' });
  await mcp.connect(transport);
  assert.equal((await mcp.listTools()).tools.length, 5);
  const call = async (name, args = {}, options) => {
    const response = await mcp.callTool({ name, arguments: args }, undefined, options);
    if (response.isError) throw Error(response.content[0].text);
    return JSON.parse(response.content[0].text);
  };
  const list = () => call('list_shared_sessions');
  assert.deepEqual(await list(), []);
  await action('Включить').click();
  await action('Передать MCP').click();
  const [bindingWithTarget] = await list();
  const { target, ...binding } = bindingWithTarget;
  assert.equal(binding.sessionId, first.id);
  const request = (fields, ms = 15000) => ({ ...binding, requestId: randomUUID(), expiresAt: Date.now() + ms, ...fields });
  const send = args => call('request_terminal_input', args);
  const pending = args => waitFor(async () =>
    (await snapshot()).mcp.pending.find(p => p.requestId === args.requestId), 'visible pending request');

  const another = await ui('connect', host.id);
  await waitFor(async () => (await getSession(another)).state === 'ready', 'second tab ready');
  const tabs = page.getByRole('tab', { name: 'Тестовый сервер' });
  await tabs.nth(1).click();
  const a = request({ text: 'echo mcp-hello-42' });
  const approval = send(a);
  await pending(a);
  await page.getByRole('button', { name: 'MCP 1', exact: true }).click();
  await page.getByRole('tab', { name: 'Главная' }).click();
  await page.getByRole('heading', { name: 'Серверы' }).waitFor();
  assert.equal((await list())[0].sessionId, first.id);
  await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows()[0].minimize());
  assert.equal((await list())[0].sessionId, first.id);
  await app.evaluate(({ BrowserWindow }) => {
    const window = BrowserWindow.getAllWindows()[0];
    window.restore();
    window.focus();
  });
  await tabs.nth(0).click();
  assert.equal(await page.locator('#mcp-panel').isVisible(), false);
  await page.screenshot({ path: path.join(path.dirname(screenshot), 'windows-terminal.png') });
  await page.getByRole('button', { name: 'MCP 1', exact: true }).click();
  await page.screenshot({ path: screenshot });
  await tabs.nth(1).click();
  await action('Отправить в PTY').click();
  assert.equal((await approval).status, 'sent');
  await assert.rejects(send(a), /использован/);
  assert.equal(await hasLine('mcp-hello-42'), 0);
  await tabs.nth(0).click();
  await waitFor(() => hasLine('mcp-hello-42'), 'approved command in correct tab');
  const renderedLine = activePane().locator('.xterm-rows > div').getByText('mcp-hello-42', { exact: true });
  const cell = await renderedLine.boundingBox();
  assert.ok(cell);
  await page.mouse.dblclick(cell.x + cell.width * 0.4, cell.y + cell.height / 2);
  await page.keyboard.press('Control+Shift+c');
  await waitFor(async () => (await app.evaluate(({ clipboard }) => clipboard.readText())).includes('hello'), 'terminal clipboard copy');
  await app.evaluate(({ clipboard }) => clipboard.clear());
  report('authenticated stdio MCP, explicit share, minimize, exact approval, tab isolation, deduplication and terminal copy');

  const output = request({ maxChars: 1024 });
  const outputResult = call('request_terminal_output', output);
  const preview = await pending(output);
  assert.match(preview.draft, /mcp-hello-42/);
  assert.doesNotMatch(preview.draft, /Привет/);
  await page.getByRole('textbox', { name: 'Редактируемый фрагмент вывода' }).fill('mcp-hello-42 [edited]');
  await action('Передать вывод').click();
  const released = await outputResult;
  assert.equal(released.output, 'mcp-hello-42 [edited]');
  assert.match(released.warning, /НЕДОВЕРЕННЫЕ/);
  report('new output only, editable review, exact released value');

  const denied = request({ text: 'touch ' + work + '/denied' });
  const denyResult = send(denied);
  await pending(denied);
  await action('Отклонить').click();
  assert.equal((await denyResult).status, 'denied');

  const cancelled = request({ text: 'echo NEVER-CANCELLED-91' });
  const cancelResult = send(cancelled);
  await pending(cancelled);
  assert.equal((await call('cancel_request', { requestId: cancelled.requestId })).status, 'cancelled');
  assert.equal((await cancelResult).status, 'cancelled');
  await assert.rejects(ui('decide', cancelled.requestId, true), /завершён/);

  const nativeCancel = request({ text: 'echo NEVER-NATIVE-92' });
  const controller = new AbortController();
  const abortResult = call('request_terminal_input', nativeCancel, { signal: controller.signal }).catch(error => error);
  await pending(nativeCancel);
  controller.abort();
  assert.ok(await abortResult instanceof Error);
  await waitFor(async () => (await snapshot()).mcp.history.some(item =>
    item.requestId === nativeCancel.requestId && item.status === 'cancelled'), 'MCP protocol cancellation');

  const expired = request({ text: 'echo NEVER-EXPIRED-93' }, 850);
  const expiredResult = send(expired);
  await pending(expired);
  assert.equal((await expiredResult).status, 'expired');
  await assert.rejects(ui('decide', expired.requestId, true), /завершён/);
  await typeLine('echo after-cancel-barrier');
  await waitFor(() => hasLine('after-cancel-barrier'), 'terminal ordering barrier');
  for (const marker of ['NEVER-CANCELLED-91', 'NEVER-NATIVE-92', 'NEVER-EXPIRED-93']) assert.equal(await hasLine(marker), 0);
  report('denial, tool and protocol cancellation, expiration and late-approval rejection');

  const interrupted = request({ text: 'echo NEVER-REVOKED-94' });
  const disconnectResult = send(interrupted);
  await pending(interrupted);
  for (const socket of proxySockets) socket.destroy();
  assert.equal((await disconnectResult).status, 'revoked');
  assert.deepEqual(await list(), []);
  await waitFor(async () => (await getSession(first.id)).state !== 'ready', 'remote connection lost');
  await ui('reconnect', first.id);
  const next = await waitFor(async () => {
    const s = await getSession(first.id);
    return s.state === 'ready' && s;
  }, 'reconnect');
  assert.notEqual(next.generation, first.generation);
  assert.deepEqual(await list(), []);
  await assert.rejects(send(interrupted), /отозвано/);
  await ui('share', first.id, next.generation);
  const renewed = (await list())[0];
  const disabled = send({
    sessionId: renewed.sessionId, generation: renewed.generation, grantId: renewed.grantId,
    requestId: randomUUID(), expiresAt: Date.now() + 10000, text: 'echo NEVER-DISABLED-95',
  });
  await waitFor(async () => (await snapshot()).mcp.pending[0], 'pending before disable');
  await action('Выключить').click();
  assert.equal((await disabled).status, 'revoked');
  assert.deepEqual(await list(), []);
  report('transport break, new generation, revoked permission, no re-share, explicit MCP shutdown');

  await ui('disconnect', first.id);
  lab('stop');
  await waitFor(() => server.exitCode !== null, 'old sshd stopped');
  await startServer('b');
  await ui('reconnect', first.id);
  await page.getByRole('heading', { name: 'Ключ сервера изменился' }).waitFor();
  const changed = (await getSession(first.id)).trust;
  assert.equal(changed.known, initial.fingerprint);
  assert.notEqual(changed.fingerprint, initial.fingerprint);
  assert.ok(labFingerprint('b').includes(changed.fingerprint));
  await action('Отклонить ключ').click();
  assert.equal((await getSession(first.id)).state, 'error');
  await action('Подключить снова').click();
  await page.getByRole('heading', { name: 'Ключ сервера изменился' }).waitFor();
  await action('Заменить проверенный ключ').click();
  await waitFor(async () => (await getSession(first.id)).state === 'ready', 'verified replacement');
  assert.deepEqual(failures, []);
  report('changed host key blocked, rejection persisted, explicit replacement and clean renderer');
  await page.getByRole('tab', { name: 'Главная' }).click();
  await homeNav.getByRole('button', { name: 'Журнал MCP' }).click();
  await page.locator('#home-history').getByText('Отправлено в PTY', { exact: true }).waitFor();
  report('home-only sidebar and MCP history');

  const keyPath = path.join(profile, 'imported');
  fs.writeFileSync(keyPath, wsl(['-u', 'root', '--exec', 'cat', work + '/imported']) + '\n');
  const password = 'synthetic-secret';
  passwordServer = new SshServer({ hostKeys: [wsl(['-u', 'root', '--exec', 'cat', work + '/host-a']) + '\n'] }, client => {
    passwordClients.add(client);
    client.on('error', () => {});
    client.on('close', () => passwordClients.delete(client));
    client.on('authentication', ctx => {
      if (ctx.method === 'password' && ctx.username === 'operator' && ctx.password === password) ctx.accept();
      else ctx.reject(['password']);
    });
    client.on('ready', () => client.on('session', accept => {
      const session = accept();
      session.on('pty', accept => accept());
      session.on('shell', accept => accept().write('Password accepted\r\n'));
    }));
  });
  await listen(passwordServer, { host: '127.0.0.1', port: 0 });
  const passwordPort = passwordServer.address().port;

  // Let the real password dialog open. Substitute only the key picker and key passphrase.
  async function mockKeyImport() {
    const modulePath = path.join(root, 'src', 'credentials.cjs');
    await app.evaluate(({ dialog }, { modulePath, keyPath }) => {
      const credentials = process.getBuiltinModule('node:module').createRequire(modulePath)(modulePath);
      const original = credentials.askSecret;
      credentials.askSecret = (...args) => args[1].includes('фраза')
        ? Promise.resolve(Buffer.from('lab-key-phrase')) : original(...args);
      dialog.showOpenDialog = async () => ({ canceled: false, filePaths: [keyPath] });
    }, { modulePath, keyPath });
  }
  await mockKeyImport();
  await homeNav.getByRole('button', { name: 'Ключи' }).click();
  await action('+ Импортировать ключ').click();
  await page.getByText('imported', { exact: true }).waitFor();
  await action('Копировать публичный').click();
  await waitFor(async () => /^ssh-ed25519 AAAA/.test(await app.evaluate(({ clipboard }) => clipboard.readText())), 'public key copy');
  await app.evaluate(({ clipboard }) => clipboard.clear());
  await page.screenshot({ path: path.join(path.dirname(screenshot), 'windows-home.png') });
  const { keys } = await snapshot();
  const keyHost = await ui('save', { label: 'Вход по ключу', group: host.group, host: host.host, port: host.port,
    username: host.username, auth: 'key', keyId: keys[0].id });
  await homeNav.getByRole('button', { name: 'Серверы' }).click();
  await action('+ Добавить сервер').click();
  await form.getByLabel('Название').fill('Парольный сервер');
  await form.getByLabel('Группа').fill('Лаборатория');
  await form.getByLabel('Адрес').fill('127.0.0.1');
  await form.getByLabel('Порт').fill(String(passwordPort));
  await form.getByLabel('Пользователь').fill('operator');
  await form.getByLabel('Способ входа').selectOption('password');
  await page.screenshot({ path: path.join(path.dirname(screenshot), 'windows-auth.png') });
  await action('Сохранить и ввести пароль…').click();
  const driveDialog = require('node:util').promisify(require('node:child_process').execFile);
  const mainPid = await app.evaluate(() => process.pid);
  const native = await driveDialog('powershell.exe', ['-NoProfile', '-File', path.join(__dirname, 'secret-dialog.ps1'),
    '-Mode', 'accept', '-AppPid', String(mainPid)], { windowsHide: true, timeout: 40000 })
    .catch(async error => {
      const hosts = (await snapshot()).hosts.map(({ auth, hasPassword }) => ({ auth, hasPassword }));
      throw Error(error.message + '\nForm: ' + await page.locator('#form-error').textContent() + '\nSaved host methods: ' + JSON.stringify(hosts));
    });
  assert.match(native.stdout, /PASS visible masked Windows dialog accepted input/);
  await form.waitFor({ state: 'hidden' });
  const account = (await snapshot()).hosts.find(h => h.auth === 'password');
  assert.equal(account.hasPassword, true);
  assert.equal((await snapshot()).keys[0].unlocked, true);
  const vault = fs.readFileSync(path.join(profile, 'credentials.json'), 'utf8');
  const stateJson = JSON.stringify(await snapshot());
  for (const marker of [password, 'OPENSSH PRIVATE KEY', 'lab-key-phrase']) {
    assert.ok(!vault.includes(marker) && !stateJson.includes(marker));
  }
  assert.doesNotMatch(stateJson, /"cipher"/);
  fs.unlinkSync(keyPath);
  await mcp.close();
  mcp = undefined;
  await app.close();
  app = await electron.launch({
    args: [root], timeout: 30000, env: { ...process.env, SSHASH_TEST_LAUNCH: '1', SSHASH_TEST_PROFILE: profile },
  });
  const reopened = await app.firstWindow();
  const after = (...args) => reopened.evaluate(([method, values]) => window.sshash[method](...values), [args[0], args.slice(1)]);
  await reopened.getByRole('heading', { name: 'Серверы' }).waitFor();
  assert.equal((await after('state')).keys[0].unlocked, false);
  await mockKeyImport();
  const keySession = await after('connect', keyHost);
  const ready = async id => waitFor(async () => {
    const item = (await after('state')).sessions.find(s => s.id === id);
    if (item?.error) throw Error(item.error);
    return item?.state === 'ready';
  }, 'credential-backed session');
  await ready(keySession);
  const passSession = await after('connect', account.id);
  const trust = await waitFor(async () => (await after('state')).sessions.find(s => s.id === passSession)?.trust, 'password host key');
  const passGeneration = (await after('state')).sessions.find(s => s.id === passSession).generation;
  await after('verify', passSession, passGeneration, trust.fingerprint, true);
  await ready(passSession);
  await after('clearPassword', account.id);
  await after('removeKey', keys[0].id);
  const removed = JSON.parse(fs.readFileSync(path.join(profile, 'credentials.json')));
  assert.deepEqual(removed, { keys: {}, passwords: {} });
  report('encrypted vault, import of passphrase-protected key, password and key logins after restart, and removal');

  const silent = net.createServer(socket => socket.end());
  await listen(silent, { host: '127.0.0.1', port: 0 });
  try {
    const id = await after('save', { label: 'TCP only', group: 'Lab', host: '127.0.0.1',
      port: silent.address().port, username: 'operator', auth: 'agent' });
    const sid = await after('connect', id);
    const error = await waitFor(async () => (await after('state')).sessions.find(s => s.id === sid)?.error,
      'connection closed before SSH greeting');
    assert.match(error, /до получения приветствия SSH.*До проверки пароля/);
    report('TCP close before the SSH greeting has its own diagnostic');
  } finally { silent.close(); }
  console.log('Screenshot ' + screenshot);
}

function labFingerprint(key) {
  return wsl(['--', 'ssh-keygen', '-lf', work + '/host-' + key + '.pub']);
}

async function checkInvalidProof(token) {
  const reply = await new Promise((resolve, reject) => {
    const socket = net.createConnection(address(token));
    let text = '';
    const timer = setTimeout(() => { socket.destroy(); reject(Error('Invalid proof timed out')); }, 5000);
    socket.on('connect', () => socket.write(JSON.stringify({ hello: '1'.repeat(64) }) + '\n'));
    socket.on('data', data => {
      text += data;
      if (text.includes('\n')) socket.write(JSON.stringify({ proof: '0'.repeat(64) }) + '\n');
    });
    socket.on('error', reject);
    socket.on('close', () => { clearTimeout(timer); resolve(text); });
  });
  assert.doesNotMatch(reply, /"ready"/);
  assert.match(reply, /"server"/);
}

main().catch(error => { console.error(error); process.exitCode = 1; }).finally(async () => {
  await mcp?.close().catch(() => {});
  await app?.close().catch(() => {});
  for (const socket of [...agentSockets, ...proxySockets]) socket.destroy();
  for (const client of passwordClients) client.end();
  passwordServer?.close();
  listener?.close();
  proxy?.close();
  if (labScript && operator) {
    try { lab('stop'); } catch {}
    try { lab('clean'); } catch {}
  }
  server?.kill();
  try { fs.rmSync(profile, { recursive: true, force: true, maxRetries: 3 }); } catch {}
});
