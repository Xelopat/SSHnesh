const { app, BrowserWindow, ipcMain, session, clipboard, safeStorage, protocol, net, dialog, shell } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { randomUUID } = require('node:crypto');
const { isIP } = require('node:net');
const { z } = require('zod/v4');
const { Sessions, target } = require('./sessions.cjs');
const credentialsApi = require('./credentials.cjs');
const { Access, defaultApprovalMode } = require('./access.cjs');
const { startLocal } = require('./local.cjs');
const { fileRoutes } = require('./files.cjs');
const { Sync, checkpointSchema } = require('./sync.cjs');
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
  sudo: z.boolean().optional(),
});
const server = profile.pick({ id: true, label: true, group: true, host: true, port: true })
  .extend({ accountId: z.uuid().optional() });
const account = profile.pick({ id: true, label: true, username: true, auth: true, keyId: true, sudo: true });
const hostProfile = z.union([server, profile]);

function storage(file, initial, parse) {
  let data;
  try {
    data = parse(JSON.parse(fs.readFileSync(file, 'utf8')));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    data = typeof initial === 'function' ? initial() : initial;
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
  const hosts = z.array(z.union([server.extend({ id: z.uuid() }), profile.extend({ id: z.uuid() })])).max(256);
  const accounts = z.array(account.extend({ id: z.uuid() })).max(256);
  const serverSchema = z.object({ hosts, accounts: accounts.default([]), hostKeys: z.record(z.string(), z.string()) });
  const approvalMode = z.enum(['manual', 'all']);
  const settingsSchema = z.object({ approvalMode: approvalMode.default(defaultApprovalMode), chatApproval: z.boolean().default(false) });
  const settings = storage(path.join(userData, 'settings.json'), settingsSchema.parse({}),
    data => settingsSchema.parse(data));
  const keyIdSchema = z.string().regex(/^[A-Za-z0-9_-]{43}$/);
  const privateKey = z.object({ id: keyIdSchema, name: z.string().max(120), type: z.string(),
    comment: z.string().optional(), publicBlob: z.base64(), protected: z.boolean() });
  const passwordEntry = z.object({ target: z.string() });
  const keyMap = entry => z.record(keyIdSchema, entry).refine(items => Object.keys(items).length <= 64);
  const passwordMap = entry => z.record(z.uuid(), entry).refine(items => Object.keys(items).length <= 512);
  const cipher = z.string().min(1);
  const vaultSchema = z.object({
    keys: keyMap(privateKey.extend({ cipher })),
    passwords: passwordMap(passwordEntry.extend({ cipher })),
  });
  const portableSchema = z.strictObject({
    hosts, accounts: accounts.default([]), keys: keyMap(privateKey.extend({ secret: z.base64().min(4).max(174764) })),
    passwords: passwordMap(passwordEntry.extend({ secret: z.base64().min(4).max(21848) })),
  }).refine(data => new Set(data.hosts.map(host => host.id)).size === data.hosts.length &&
    new Set([...data.hosts, ...data.accounts].map(item => item.id)).size === data.hosts.length + data.accounts.length &&
    Object.entries(data.keys).every(([id, key]) => id === key.id) &&
    Object.entries(data.passwords).every(([id, entry]) => [...data.hosts, ...data.accounts].some(item =>
      item.id === id && item.auth === 'password' && entry.target === credentialsApi.passwordTarget(item))));
  const workspaceSchema = z.object({ servers: serverSchema, vault: vaultSchema, checkpoint: checkpointSchema.optional() });
  const workspace = storage(path.join(userData, 'workspace.json'), () => ({
    servers: storage(path.join(userData, 'servers.json'), { hosts: [], accounts: [], hostKeys: {} }, serverSchema.parse).data,
    vault: storage(path.join(userData, 'credentials.json'), { keys: {}, passwords: {} }, vaultSchema.parse).data,
  }), workspaceSchema.parse);
  const localStore = field => ({
    get data() { return workspace.data[field]; },
    update: edit => workspace.update(next => { edit(next[field]); }),
  });
  const store = localStore('servers');
  const vault = localStore('vault');
  credentials = new credentialsApi.Credentials({ store: vault, encryption: {
    available: () => safeStorage.isEncryptionAvailable() &&
      (process.platform !== 'linux' || safeStorage.getSelectedStorageBackend() !== 'basic_text'),
    encrypt: value => safeStorage.encryptString(value),
    decrypt: value => safeStorage.decryptString(value),
  } });
  const sync = new Sync({ workspace, credentials, publish, signal: shutdown.signal,
    parseVault: data => {
      const parsed = portableSchema.safeParse(data);
      if (!parsed.success) throw Error('Формат облачного хранилища повреждён или не поддерживается.');
      return parsed.data;
    },
    openExternal: url => shell.openExternal(url),
    resolveConflict: async ({ kind, local, remote }) => {
      const answer = await dialog.showMessageBox(window, { type: 'warning', title: 'Синхронизация',
        message: { host: 'Конфликт в настройках сервера', account: 'Конфликт учёток', key: 'Конфликт SSH-ключа' }[kind],
        detail: 'На устройстве: ' + (local ?? 'удалено') + '\nНа сервере синхронизации: ' + (remote ?? 'удалено'),
        buttons: ['Отмена', 'Выбрать локальную', 'Выбрать облачную'], defaultId: 0, cancelId: 0 });
      return [null, 'local', 'remote'][answer.response];
    },
  });
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
  let sharePrompt;
  function cancelSharePrompt() {
    if (!sharePrompt) return;
    sharePrompt.accepted = false;
    sharePrompt.cancel.abort();
  }
  const agentAddress = () => testLaunch && process.env.SSHASH_TEST_AGENT
    ? process.env.SSHASH_TEST_AGENT
    : process.platform === 'win32' ? '//./pipe/openssh-ssh-agent' : process.env.SSH_AUTH_SOCK;
  const access = new Access({ sessions: null, change: publish, approvalMode: settings.data.approvalMode });
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
      accounts: store.data.accounts.map(item => ({ ...item, hasPassword: credentials.hasPassword(item) })),
      keys: credentials.list(), sessions: sessions.snapshot(), mcp: { ...access.snapshot(), chatApproval: settings.data.chatApproval }, sync: sync.snapshot(),
      clientCount, localError, persistent,
    };
  }
  function publish() {
    const grant = access.grant;
    const shared = grant && sessions.items.get(grant.sessionId);
    if (shared && !grant.privileged && needsPrivilegeApproval(shared.host)) access.revoke(shared.id);
    if (window && !window.isDestroyed()) window.webContents.send('state:changed', snapshot());
  }
  stopLocal = startLocal({
    token, helper: bridge,
    onCall: (peer, method, args) => {
      if (method === 'available') return access.enabled ? [...sessions.items.values()].filter(item => sessions.writable(item))
        .map(({ id, generation, host }) => ({ sessionId: id, generation, target: target(host), account: host.accountLabel,
          privileged: needsPrivilegeApproval(host) })) : [];
      if (method === 'request-share') {
        const { sessionId, generation, challenge } = z.strictObject({
          sessionId: z.uuid(), generation: z.uuid(), challenge: z.uuid().optional(),
        }).parse(args);
        return shareSession(sessionId, generation, peer, challenge);
      }
      if (method === 'share-decision') {
        const decision = z.strictObject({ challenge: z.uuid(), accept: z.boolean() }).parse(args);
        if (settings.data.chatApproval && sharePrompt?.peer === peer && sharePrompt.challenge === decision.challenge &&
            !sharePrompt.signal.aborted) {
          sharePrompt.accepted = decision.accept;
          sharePrompt.cancel.abort();
        }
        return { status: 'received' };
      }
      if (method === 'cancel-share') {
        if (sharePrompt?.peer === peer && sharePrompt.challenge === args?.challenge) cancelSharePrompt();
        return { status: 'received' };
      }
      if (method === 'input-decision') {
        const { requestId, accept } = z.strictObject({ requestId: z.uuid(), accept: z.boolean() }).parse(args);
        if (settings.data.chatApproval && access.requests.get(requestId)?.peer === peer)
          return access.decide(requestId, accept);
        return { status: 'not_pending' };
      }
      if (method === 'status') return { ...access.call(peer, method, args), chatApproval: settings.data.chatApproval,
        privileged: Boolean(access.grant?.privileged) };
      return access.call(peer, method, args);
    },
    onClose: peer => {
      access.closed(peer);
      if (sharePrompt?.peer === peer) cancelSharePrompt();
    },
    onCount: count => { clientCount = count; publish(); },
    onError: error => {
      localError = error.message;
      access.enabled = false;
      cancelSharePrompt();
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
  route('sync:login', () => sync.login());
  route('sync:logout', () => sync.logout());
  route('sync:transfer', (direction, password) => sync.transfer(direction, password));
  const findHost = id => store.data.hosts.find(item => item.id === id);
  const findAccount = id => store.data.accounts.find(item => item.id === id);
  route('host:migrate-account', id => {
    const old = findHost(id);
    if (!old?.username) throw Error('На сервере уже используется отдельная учётка.');
    const { username, auth, keyId, sudo, ...host } = old;
    const item = { id: randomUUID(), label: (username + ' · ' + host.label).slice(0, 64), username, auth, keyId, sudo };
    const previous = vault.data;
    workspace.update(data => {
      if (data.servers.accounts.length >= 256) throw Error('Достигнут лимит учёток.');
      data.servers.accounts.push(item);
      data.servers.hosts[data.servers.hosts.findIndex(entry => entry.id === id)] = { ...host, accountId: item.id };
      const saved = data.vault.passwords[id];
      if (saved?.target === credentialsApi.passwordTarget(old))
        data.vault.passwords[item.id] = { cipher: saved.cipher, target: credentialsApi.passwordTarget(item) };
      delete data.vault.passwords[id];
    });
    credentials.refreshAfterSync(previous);
    publish();
  });
  const keyId = id => z.string().regex(/^[A-Za-z0-9_-]{43}$/).parse(id);
  route('key:generate', async label => {
    const name = z.string().trim().min(1).max(120).refine(text => !/[\p{Cc}\p{Cf}]/u.test(text)).safeParse(label);
    if (!name.success) throw Error('Укажите название ключа от 1 до 120 символов.');
    await credentials.generate(name.data);
    publish();
  });
  route('key:import', async () => {
    const result = await dialog.showOpenDialog(window, { title: 'Импортировать приватный SSH-ключ', properties: ['openFile'] });
    if (result.canceled || !result.filePaths[0]) return;
    if (await credentials.import(result.filePaths[0], () => ask('Парольная фраза SSH-ключа'))) publish();
  });
  route('key:remove', id => { credentials.remove(keyId(id)); publish(); });
  route('key:copy-public', id => clipboard.writeText(credentials.publicKey(keyId(id))));
  async function setPassword(find, id) {
    const item = find(id);
    if (item?.auth !== 'password') throw Error('Сначала сохраните настройки входа по паролю.');
    const secret = await ask('Пароль · ' + (item.host ? target(item) : item.label + ' · ' + item.username));
    if (!secret) return false;
    const current = find(id);
    if (!current || current.auth !== 'password' || credentialsApi.passwordTarget(current) !== credentialsApi.passwordTarget(item)) {
      secret.fill(0);
      throw Error('Настройки сервера изменились. Повторите ввод.');
    }
    credentials.setPassword(current, secret);
    publish();
    return true;
  }
  route('host:password', id => setPassword(findHost, id));
  route('account:password', id => setPassword(findAccount, id));
  route('account:clear-password', id => {
    if (!findAccount(id)) throw Error('Учётка удалена.');
    credentials.removePassword(id);
    publish();
  });
  route('host:clear-password', id => {
    if (!findHost(id)) throw Error('Сервер удалён.');
    credentials.removePassword(id);
    publish();
  });
  route('host:save', raw => {
    const value = hostProfile.parse(raw);
    const host = { ...value, id: value.id ?? randomUUID() };
    if (host.auth !== 'key') delete host.keyId;
    if (host.auth === 'key' && !host.keyId) throw Error('Выберите SSH-ключ.');
    if (host.accountId && !findAccount(host.accountId)) throw Error('Выберите сохранённую учётку.');
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
  route('account:save', raw => {
    const value = account.parse(raw);
    const item = { ...value, id: value.id ?? randomUUID() };
    if (item.auth !== 'key') delete item.keyId;
    if (item.auth === 'key' && !item.keyId) throw Error('Выберите SSH-ключ.');
    const old = findAccount(item.id);
    if (old && (old.username !== item.username || item.auth !== 'password')) credentials.removePassword(item.id);
    store.update(data => {
      const index = data.accounts.findIndex(entry => entry.id === item.id);
      if (index >= 0) data.accounts[index] = item;
      else {
        if (data.accounts.length >= 256) throw Error('Достигнут лимит учёток.');
        data.accounts.push(item);
      }
    });
    if (old && !old.sudo && item.sudo)
      for (const active of sessions.items.values()) if (active.host.credentialId === item.id) access.revoke(active.id);
    publish();
    return item.id;
  });
  route('account:delete', id => {
    if (!findAccount(id)) return;
    if (store.data.hosts.some(host => host.accountId === id)) throw Error('Сначала выберите другую учётку в настройках серверов, где она используется по умолчанию.');
    credentials.removePassword(id);
    store.update(data => { data.accounts = data.accounts.filter(item => item.id !== id); });
    publish();
  });
  route('host:delete', id => {
    if (!findHost(id)) return;
    credentials.removePassword(id);
    store.update(data => { data.hosts = data.hosts.filter(host => host.id !== id); });
    publish();
  });
  function connectionProfile(hostId, accountId) {
    const host = findHost(hostId);
    if (!host) return null;
    const selectedId = accountId ?? host.accountId;
    if (!selectedId) {
      if (!host.username) throw Error('Выберите учётку для подключения.');
      return host;
    }
    const item = findAccount(selectedId);
    if (!item) return null;
    const { username, auth, keyId, sudo } = item;
    return { ...host, username, auth, keyId, sudo, credentialId: item.id, accountLabel: item.label };
  }
  async function connect(hostId, accountId, sessionId) {
    const host = connectionProfile(hostId, accountId);
    if (!host) throw Error('Сервер удалён.');
    if (host.auth === 'key') {
      if (!await credentials.unlock(host.keyId, () => ask('Парольная фраза SSH-ключа'))) return null;
      const current = connectionProfile(hostId, accountId);
      if (!current || target(host) !== target(current) || current.auth !== host.auth || current.keyId !== host.keyId)
        throw Error('Настройки сервера изменились. Подключитесь заново.');
      if (sessionId && !sessions.items.has(sessionId)) return null;
    }
    return sessions.connect(host, sessionId);
  }
  route('ssh:connect', (id, accountId) => connect(id, accountId));
  route('ssh:reconnect', id => {
    const old = sessions.items.get(id);
    if (!old) throw Error('Вкладка закрыта.');
    return connect(old.host.id, old.host.credentialId, id);
  });
  route('ssh:disconnect', id => sessions.disconnect(id));
  route('ssh:remove', id => sessions.remove(id));
  route('ssh:verify', (...args) => sessions.verify(...args));
  ipcMain.on('ssh:input', (event, ...args) => { if (allowed(event)) sessions.input(...args); });
  ipcMain.on('ssh:resize', (event, ...args) => { if (allowed(event)) sessions.resize(...args); });
  route('mcp:enable', value => {
    if (value === true && localError) throw Error(localError);
    access.enabled = value === true;
    if (!access.enabled) cancelSharePrompt();
    if (!access.enabled && access.grant) access.revoke(access.grant.sessionId);
    publish();
  });
  function needsPrivilegeApproval(host) {
    return host.username.toLowerCase() === 'root' ||
      Boolean(host.sudo || (host.credentialId ? findAccount(host.credentialId)?.sudo : findHost(host.id)?.sudo));
  }
  async function shareSession(id, generation, peer, challenge) {
    const item = sessions.items.get(id);
    if (!access.enabled || item?.generation !== generation || !sessions.writable(item))
      throw Error('Включите MCP и выберите открытое SSH-соединение.');
    if (access.grant?.sessionId === id && access.grant.generation === generation &&
        (!peer || !access.grant.peer || access.grant.peer === peer))
      return { status: 'shared', ...access.binding() };
    if (sharePrompt) throw Error('Сначала завершите ожидающее подтверждение.');
    const privileged = needsPrivilegeApproval(item.host);
    if (privileged || peer) {
      const cancel = new AbortController();
      const signal = AbortSignal.any([cancel.signal, shutdown.signal, AbortSignal.timeout(85000)]);
      const prompt = { peer, cancel, challenge, signal, accepted: false };
      sharePrompt = prompt;
      try {
        const answer = await dialog.showMessageBox(window, {
          type: privileged ? 'warning' : 'question', title: 'Доступ MCP',
          message: (privileged ? 'Разрешить агенту доступ к sudo/root на эту SSH-сессию?' : 'Передать агенту SSH-сессию?'),
          detail: target(item.host) + (privileged ? '\nАгент сможет отправлять команды до отключения или отзыва доступа.' : ''),
          buttons: ['Отмена', 'Разрешить'], defaultId: 0, cancelId: 0, signal,
        });
        if (!prompt.accepted && (answer.response !== 1 || signal.aborted)) return { status: 'denied' };
      } finally { sharePrompt = undefined; }
    }
    if (privileged !== needsPrivilegeApproval(item.host)) throw Error('Права учётки изменились. Запросите доступ заново.');
    access.share(id, generation, privileged, privileged ? peer : undefined);
    return { status: 'shared', ...access.binding() };
  }
  route('mcp:share', (id, generation) => shareSession(id, generation));
  route('mcp:chat-approval', value => {
    const enabled = z.boolean().parse(value);
    settings.update(data => { data.chatApproval = enabled; });
    publish();
  });
  route('mcp:approval-mode', value => {
    const mode = approvalMode.parse(value);
    if (settings.data.approvalMode === mode) return;
    settings.update(data => { data.approvalMode = mode; });
    access.approvalMode = mode;
    publish();
  });
  route('mcp:revoke', () => { cancelSharePrompt(); if (access.grant) access.revoke(access.grant.sessionId); });
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
