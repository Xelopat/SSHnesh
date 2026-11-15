const { app, BrowserWindow, ipcMain, session, clipboard, safeStorage, protocol, net, dialog } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { randomUUID } = require('node:crypto');
const { isIP } = require('node:net');
const { z } = require('zod/v4');
const { Sessions, target } = require('./sessions.cjs');
const credentialsApi = require('./credentials.cjs');
const { Access } = require('./access.cjs');
const { startLocal } = require('./local.cjs');
const { fileRoutes } = require('./files.cjs');
const { nonce, valid } = require('./wire.cjs');

const home = 'sshash://app/index.html';
protocol.registerSchemesAsPrivileged([{ scheme: 'sshash', privileges: { standard: true, secure: true } }]);
const testLaunch = !app.isPackaged && process.env.SSHASH_TEST_LAUNCH === '1';
if (testLaunch && process.env.SSHASH_TEST_PROFILE) app.setPath('userData', process.env.SSHASH_TEST_PROFILE);
else if (!app.commandLine.hasSwitch('user-data-dir')) {
  // Keep the existing address book, DPAPI vault and MCP pairing after the rename.
  app.setPath('userData', path.join(app.getPath('appData'), 'sshash'));
}
const primary = app.requestSingleInstanceLock();
if (!primary) app.exit(0);

const profile = z.strictObject({
  id: z.uuid().optional(), label: z.string().trim().min(1).max(64),
  group: z.string().trim().min(1).max(48),
  host: z.string().trim().toLowerCase().max(253).refine(h => isIP(h) || /^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(h)),
  port: z.int().min(1).max(65535), username: z.string().trim().regex(/^[a-zA-Z0-9_.@-]{1,64}$/),
  auth: z.enum(['agent', 'password', 'key']).default('agent'),
  keyId: z.string().regex(/^[A-Za-z0-9_-]{43}$/).optional(),
});

function storage(file, initial, parse) {
  let data = initial;
  try {
    data = parse(JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  return {
    get data() { return data; },
    update(edit) {
      const next = structuredClone(data);
      edit(next);
      const temp = file + '.tmp-' + randomUUID();
      try {
        fs.writeFileSync(temp, JSON.stringify(next, null, 2), { mode: 0o600, flag: 'wx' });
        fs.renameSync(temp, file);
        data = next;
      } finally { fs.rmSync(temp, { force: true }); }
    },
  };
}

function pairing(file) {
  if (!safeStorage.isEncryptionAvailable() ||
      (process.platform === 'linux' && safeStorage.getSelectedStorageBackend() === 'basic_text'))
    return { token: nonce(), persistent: false };
  try {
    const token = safeStorage.decryptString(fs.readFileSync(file));
    if (!valid(token)) throw Error('Повреждён ключ сопряжения MCP.');
    return { token, persistent: true };
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  const token = nonce();
  fs.writeFileSync(file, safeStorage.encryptString(token), { mode: 0o600, flag: 'wx' });
  return { token, persistent: true };
}

let window, stopLocal, sessions, credentials;
const shutdown = new AbortController();
if (primary) app.whenReady().then(() => {
  const files = {
    '/index.html': path.join(__dirname, 'ui', 'index.html'),
    '/app.css': path.join(__dirname, '..', 'build', 'ui.css'),
    '/app.js': path.join(__dirname, '..', 'build', 'ui.js'),
  };
  protocol.handle('sshash', request => {
    const url = new URL(request.url);
    const file = url.host === 'app' && Object.hasOwn(files, url.pathname) && files[url.pathname];
    return file ? net.fetch(pathToFileURL(file).href) : new Response(null, { status: 404 });
  });
  session.defaultSession.setPermissionRequestHandler((_contents, _permission, answer) => answer(false));
  session.defaultSession.setPermissionCheckHandler(() => false);

  const userData = app.getPath('userData');
  fs.mkdirSync(userData, { recursive: true, mode: 0o700 });
  const store = storage(path.join(userData, 'servers.json'), { hosts: [], hostKeys: {} },
    data => z.object({ hosts: z.array(profile.extend({ id: z.uuid() })), hostKeys: z.record(z.string(), z.string()) }).parse(data));
  const cipher = z.string().min(1);
  const vault = storage(path.join(userData, 'credentials.json'), { keys: {}, passwords: {} },
    data => z.object({
      keys: z.record(z.string().regex(/^[A-Za-z0-9_-]{43}$/), z.object({
        id: z.string(), name: z.string(), type: z.string(), publicBlob: z.string(), protected: z.boolean(), cipher,
      })),
      passwords: z.record(z.uuid(), z.object({ target: z.string(), cipher })),
    }).parse(data));
  credentials = new credentialsApi.Credentials({ store: vault, encryption: {
    available: () => safeStorage.isEncryptionAvailable() &&
      (process.platform !== 'linux' || safeStorage.getSelectedStorageBackend() !== 'basic_text'),
    encrypt: value => safeStorage.encryptString(value),
    decrypt: value => safeStorage.decryptString(value),
  } });
  const { token, persistent } = pairing(path.join(userData, 'pairing.dat'));
  const root = app.isPackaged ? process.resourcesPath : path.join(__dirname, '..');
  const bridge = path.join(root, ...(app.isPackaged ? ['bridge'] : ['build', 'bridge']), 'sshash-pipe.exe');
  const command = process.platform === 'win32' ? 'node.exe' : 'node';
  const script = path.join(root, ...(app.isPackaged ? [] : ['build']), 'sshash-mcp.cjs');
  let asking = false;
  async function ask(title) {
    if (asking) throw Error('Завершите ввод в уже открытом окне SSHnesh.');
    if (process.platform !== 'win32') throw Error('Ввод пароля и парольной фразы в приложении доступен на Windows.');
    asking = true;
    try {
      const handle = window.getNativeWindowHandle();
      const owner = handle.readBigInt64LE().toString();
      return await credentialsApi.askSecret(bridge, title, shutdown.signal, owner);
    } finally { asking = false; }
  }

  let clientCount = 0;
  let localError = '';
  const agentAddress = () => testLaunch && process.env.SSHASH_TEST_AGENT
    ? process.env.SSHASH_TEST_AGENT
    : process.platform === 'win32' ? '//./pipe/openssh-ssh-agent' : process.env.SSH_AUTH_SOCK;
  const access = new Access({ sessions: null, change: publish });
  sessions = new Sessions({
    store, change: publish, revoke: id => access.revoke(id),
    authenticate: host => credentials.authentication(host, agentAddress),
    output: (connection, data) => {
      access.append(connection, data);
      if (window && !window.isDestroyed()) window.webContents.send('term:data', connection.id, connection.generation, new Uint8Array(data));
    },
  });
  access.sessions = sessions;
  function snapshot() {
    return {
      hosts: store.data.hosts.map(host => ({ ...host, hasPassword: credentials.hasPassword(host) })),
      keys: credentials.list(), sessions: sessions.snapshot(), mcp: access.snapshot(), clientCount, localError, persistent,
    };
  }
  function publish() {
    if (window && !window.isDestroyed()) window.webContents.send('state:changed', snapshot());
  }
  stopLocal = startLocal({
    token, helper: bridge,
    onCall: (peer, method, args) => access.call(peer, method, args),
    onClose: peer => access.closed(peer),
    onCount: count => { clientCount = count; publish(); },
    onError: error => {
      localError = error.message;
      access.enabled = false;
      if (access.grant) access.revoke(access.grant.sessionId);
      publish();
    },
  });

  function allowed(event) {
    return window && !window.isDestroyed() && event.sender === window.webContents &&
      event.senderFrame === window.webContents.mainFrame && event.senderFrame.url === home;
  }
  function route(channel, fn) {
    ipcMain.handle(channel, (event, ...args) => {
      if (!allowed(event)) throw Error('Недоверенный источник.');
      return fn(...args);
    });
  }
  route('state:get', snapshot);
  const findHost = id => store.data.hosts.find(item => item.id === id);
  const keyId = id => z.string().regex(/^[A-Za-z0-9_-]{43}$/).parse(id);
  route('key:import', async () => {
    const result = await dialog.showOpenDialog(window, { title: 'Импортировать приватный SSH-ключ', properties: ['openFile'] });
    if (result.canceled || !result.filePaths[0]) return;
    if (await credentials.import(result.filePaths[0], () => ask('Парольная фраза SSH-ключа'))) publish();
  });
  route('key:remove', id => { credentials.remove(keyId(id)); publish(); });
  route('key:copy-public', id => clipboard.writeText(credentials.publicKey(keyId(id))));
  route('host:password', async id => {
    const host = findHost(id);
    if (!host || host.auth !== 'password') throw Error('Сначала выберите вход по паролю и сохраните сервер.');
    const secret = await ask('Пароль · ' + target(host));
    if (!secret) return false;
    const current = findHost(id);
    if (!current || current.auth !== 'password' || target(current) !== target(host)) {
      secret.fill(0);
      throw Error('Настройки сервера изменились. Повторите ввод.');
    }
    credentials.setPassword(current, secret);
    publish();
    return true;
  });
  route('host:clear-password', id => {
    if (!findHost(id)) throw Error('Сервер удалён.');
    credentials.removePassword(id);
    publish();
  });
  route('host:save', raw => {
    const value = profile.parse(raw);
    const host = { ...value, id: value.id ?? randomUUID() };
    if (host.auth !== 'key') delete host.keyId;
    if (host.auth === 'key' && !host.keyId) throw Error('Выберите SSH-ключ.');
    const old = findHost(host.id);
    if (old && (target(old) !== target(host) || host.auth !== 'password')) credentials.removePassword(host.id);
    store.update(data => {
      const index = data.hosts.findIndex(item => item.id === host.id);
      if (index >= 0) data.hosts[index] = host;
      else {
        if (data.hosts.length >= 256) throw Error('Достигнут лимит сохранённых серверов.');
        data.hosts.push(host);
      }
    });
    publish();
    return host.id;
  });
  route('host:delete', id => {
    if (!findHost(id)) return;
    credentials.removePassword(id);
    store.update(data => { data.hosts = data.hosts.filter(host => host.id !== id); });
    publish();
  });
  async function connect(hostId, sessionId) {
    const host = findHost(hostId);
    if (!host) throw Error('Сервер удалён.');
    if (host.auth === 'key') {
      if (!await credentials.unlock(host.keyId, () => ask('Парольная фраза SSH-ключа'))) return null;
      const current = findHost(hostId);
      if (!current || target(host) !== target(current) || current.auth !== host.auth || current.keyId !== host.keyId)
        throw Error('Настройки сервера изменились. Подключитесь заново.');
      if (sessionId && !sessions.items.has(sessionId)) return null;
    }
    return sessions.connect(host, sessionId);
  }
  route('ssh:connect', id => connect(id));
  route('ssh:reconnect', id => {
    const old = sessions.items.get(id);
    if (!old) throw Error('Вкладка закрыта.');
    return connect(old.host.id, id);
  });
  route('ssh:disconnect', id => sessions.disconnect(id));
  route('ssh:remove', id => sessions.remove(id));
  route('ssh:verify', (...args) => sessions.verify(...args));
  ipcMain.on('ssh:input', (event, ...args) => { if (allowed(event)) sessions.input(...args); });
  ipcMain.on('ssh:resize', (event, ...args) => { if (allowed(event)) sessions.resize(...args); });
  route('mcp:enable', value => {
    if (value === true && localError) throw Error(localError);
    access.enabled = value === true;
    if (!access.enabled && access.grant) access.revoke(access.grant.sessionId);
    publish();
  });
  route('mcp:share', (id, generation) => access.share(id, generation));
  route('mcp:revoke', () => { if (access.grant) access.revoke(access.grant.sessionId); });
  route('mcp:decide', (...args) => access.decide(...args));
  fileRoutes(route, sessions, () => window);
  route('mcp:config', () => {
    clipboard.writeText(JSON.stringify({ mcpServers: { sshash: { command, args: [script], env: { SSHASH_MCP_TOKEN: token } } } }, null, 2));
  });
  route('term:copy', text => { if (typeof text === 'string' && text.length <= 1000000) clipboard.writeText(text); });

  window = new BrowserWindow({
    title: 'SSHnesh', width: 1280, height: 800, minWidth: 940, minHeight: 580,
    backgroundColor: '#0b1017', autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), sandbox: true, contextIsolation: true, nodeIntegration: false, devTools: testLaunch },
  });
  window.removeMenu();
  window.webContents.on('will-navigate', event => event.preventDefault());
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.webContents.on('will-attach-webview', event => event.preventDefault());
  window.loadURL(home);
}).catch(error => {
  dialog.showErrorBox('SSHnesh', error.message);
  app.exit(1);
});

app.on('second-instance', () => {
  if (window?.isMinimized()) window.restore();
  window?.focus();
});
app.on('window-all-closed', () => app.quit());
app.on('before-quit', () => {
  shutdown.abort();
  stopLocal?.();
  for (const id of sessions?.items.keys() ?? []) sessions.disconnect(id);
  credentials?.clear();
});
