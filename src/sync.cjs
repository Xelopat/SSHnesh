const { createCipheriv, createDecipheriv, createHash, randomBytes, scrypt, timingSafeEqual } = require('node:crypto');
const { createServer } = require('node:http');
const { isDeepStrictEqual, promisify } = require('node:util');
const { z } = require('zod/v4');

const account = 'https://xelopat.ru/sshnesh-login';
const api = 'https://sshnesh.xelopat.ru';
const maxBody = 32 * 1024 * 1024;
const subject = z.string().regex(/^[a-f0-9]{16}$/);
const revision = z.int().nonnegative().max(2_000_000_000);
const sessionSchema = z.strictObject({ subject, username: z.string().min(1).max(32),
  token: z.string().regex(/^[a-f0-9]{64}$/), expires: z.int().positive() });
const envelopeSchema = z.strictObject({ version: z.literal(1), salt: z.string().regex(/^[a-f0-9]{32}$/),
  iv: z.string().regex(/^[a-f0-9]{24}$/), tag: z.string().regex(/^[a-f0-9]{32}$/),
  body: z.string().min(4).max(maxBody - 1024).refine(body => body.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(body)) });
const remoteSchema = z.union([
  z.strictObject({ revision: z.literal(0), vault: z.null() }),
  z.strictObject({ revision: revision.min(1), vault: envelopeSchema }),
]);
const checkpointSchema = z.strictObject({ subject, revision: revision.min(1), vault: envelopeSchema });
const emptyVault = { hosts: [], keys: {}, passwords: {} };
const derive = promisify(scrypt);
const digest = value => createHash('sha256').update(value).digest('hex');
const keyFor = (password, salt) => derive(password, Buffer.from(salt, 'hex'), 32,
  { N: 2 ** 17, r: 8, p: 1, maxmem: 160 * 1024 * 1024 });
const context = (owner, rev) => Buffer.from(JSON.stringify(['sshnesh-vault', 1, owner, rev]));

function seal(data, key, salt, owner, rev) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(context(owner, rev));
  const plaintext = Buffer.from(JSON.stringify(data));
  try {
    const body = Buffer.concat([cipher.update(plaintext), cipher.final()]).toString('base64');
    if (body.length > maxBody - 1024) throw Error('Хранилище слишком большое для синхронизации.');
    return { version: 1, salt, iv: iv.toString('hex'), tag: cipher.getAuthTag().toString('hex'), body };
  } finally { plaintext.fill(0); }
}

function open(vault, key, owner, rev) {
  const cipher = createDecipheriv('aes-256-gcm', key, Buffer.from(vault.iv, 'hex'));
  cipher.setAAD(context(owner, rev));
  cipher.setAuthTag(Buffer.from(vault.tag, 'hex'));
  const bytes = cipher.update(Buffer.from(vault.body, 'base64'));
  try {
    cipher.final();
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw Error('Не удалось открыть хранилище. Проверьте мастер-пароль.');
  } finally { bytes.fill(0); }
}

async function mergeVaults(base, local, remote, resolveConflict) {
  const asHosts = value => new Map(value.hosts.map(host => [host.id, { host, password: value.passwords[host.id] }]));
  const asKeys = value => new Map(Object.entries(value.keys));
  const result = { hosts: [], keys: {}, passwords: {} };
  for (const [kind, index] of [['host', asHosts], ['key', asKeys]]) {
    const before = index(base);
    const here = index(local);
    const there = index(remote);
    for (const id of new Set([...here.keys(), ...there.keys()])) {
      const old = before.get(id);
      const left = here.get(id);
      const right = there.get(id);
      let chosen;
      if (isDeepStrictEqual(left, right) || isDeepStrictEqual(right, old)) chosen = left;
      else if (isDeepStrictEqual(left, old)) chosen = right;
      else {
        const summary = record => {
          if (!record) return null;
          if (kind === 'key') return [record.name, record.type].join(' · ');
          const { label, group, username, host, port, auth } = record.host;
          return label + ' · ' + group + '\n' + username + '@' + host + ':' + port +
            ' · ' + ({ agent: 'SSH-агент', password: 'пароль', key: 'SSH-ключ' })[auth];
        };
        const choice = await resolveConflict({ kind, local: summary(left), remote: summary(right) });
        if (choice !== 'local' && choice !== 'remote') return null;
        chosen = choice === 'local' ? left : right;
      }
      if (!chosen) continue;
      if (kind === 'key') result.keys[id] = chosen;
      else {
        result.hosts.push(chosen.host);
        if (chosen.password) result.passwords[id] = chosen.password;
      }
    }
  }
  return result;
}

async function authorize(openExternal, signal) {
  signal.throwIfAborted();
  const state = randomBytes(32).toString('hex');
  const verifier = randomBytes(32).toString('hex');
  const server = createServer();
  try {
    const response = await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.on('request', (req, res) => {
        const origin = '127.0.0.1:' + server.address().port;
        const url = URL.parse(req.url, 'http://' + origin);
        if (!url) return res.writeHead(400).end();
        const returned = url.searchParams.get('state') ?? '';
        const code = url.searchParams.get('code') ?? '';
        if (req.method !== 'GET' || req.headers.host !== origin || url.origin !== 'http://' + origin ||
            url.pathname !== '/sshnesh-callback' || !/^[a-f0-9]{64}$/.test(returned) ||
            !timingSafeEqual(Buffer.from(returned), Buffer.from(state)) ||
            !/^[A-Za-z0-9_-]{1,1500}\.[a-f0-9]{64}$/.test(code)) {
          res.writeHead(400).end();
          return;
        }
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store',
          'Referrer-Policy': 'no-referrer' }).end('Вернитесь в SSHnesh, чтобы завершить вход.', () => resolve(code));
      });
      server.listen({ host: '127.0.0.1', port: 0, signal }, () => {
        const url = new URL(account);
        url.search = new URLSearchParams({ port: String(server.address().port), state, challenge: digest(verifier) });
        Promise.resolve().then(() => openExternal(url.href)).catch(reject);
      });
      server.once('close', () => reject(Error('Вход прерван.')));
    });
    return { code: response, verifier };
  } finally { server.close(); server.closeAllConnections(); }
}

class Sync {
  session = null;
  busy = false;

  constructor({ workspace, credentials, parseVault, publish, openExternal, resolveConflict, signal, fetcher = fetch }) {
    Object.assign(this, { workspace, credentials, parseVault, publish, openExternal, resolveConflict, signal, fetcher });
  }

  snapshot() {
    return { username: this.session?.username ?? null, busy: this.busy };
  }

  async run(operation) {
    if (this.busy) throw Error('Дождитесь завершения синхронизации.');
    this.busy = true;
    this.publish();
    try { return await operation(); }
    finally { this.busy = false; this.publish(); }
  }

  async request(path, { method = 'GET', data, authenticated = true } = {}) {
    const token = authenticated && this.session?.token;
    if (authenticated && !token) throw Error('Сначала войдите в аккаунт xelopat.ru.');
    const headers = { Accept: 'application/json' };
    if (token) headers.Authorization = 'Bearer ' + token;
    if (data) headers['Content-Type'] = 'application/json';
    const res = await this.fetcher(api + '/' + path + '.php', { method, headers, redirect: 'error',
      signal: AbortSignal.any([this.signal, AbortSignal.timeout(45000)]),
      body: data && JSON.stringify(data) }).catch(() => { throw Error('Сервер синхронизации недоступен.'); });
    if (!res.ok) {
      await res.body?.cancel();
      if (res.status === 401 && authenticated) this.session = null;
      if (res.status === 401) throw Error('Войдите в аккаунт xelopat.ru заново.');
      if (res.status === 409) throw Error('На сервере уже другая версия. Сначала скачайте её.');
      throw Error('Ошибка сервера синхронизации (' + res.status + ').');
    }
    const parts = [];
    let size = 0;
    for await (const bytes of res.body) {
      size += bytes.length;
      if (size > maxBody) throw Error('Ответ сервера синхронизации слишком большой.');
      parts.push(bytes);
    }
    return JSON.parse(Buffer.concat(parts).toString('utf8'));
  }

  login() {
    return this.run(async () => {
      const cancel = new AbortController();
      const signal = AbortSignal.any([cancel.signal, this.signal, AbortSignal.timeout(180000)]);
      try {
        const data = await authorize(this.openExternal, signal);
        this.session = sessionSchema.parse(await this.request('session', { method: 'POST', data, authenticated: false }));
      } finally { cancel.abort(); }
    });
  }

  logout() {
    return this.run(async () => {
      try {
        if (this.session) await this.request('session', { method: 'DELETE' });
      } finally { this.session = null; }
    });
  }

  transfer(direction, password) {
    return this.run(async () => {
      if (!['pull', 'push'].includes(direction)) throw Error('Некорректная операция синхронизации.');
      if (typeof password !== 'string' || !password || Buffer.byteLength(password) > 1024)
        throw Error('Введите мастер-пароль длиной до 1024 байт.');
      const remote = remoteSchema.parse(await this.request('vault'));
      const owner = this.session.subject;
      const checkpoint = this.workspace.data.checkpoint;
      const knownRevision = checkpoint?.subject === owner ? checkpoint.revision : 0;
      if (remote.revision < knownRevision) throw Error('Сервер вернул более старую ревизию хранилища.');
      if (direction === 'pull' && !remote.revision) throw Error('Облачное хранилище ещё пустое.');
      if (direction === 'push' && remote.revision !== knownRevision)
        throw Error('Сначала скачайте актуальную версию хранилища на это устройство.');
      if (!remote.revision && [...password].length < 16) throw Error('Задайте мастер-пароль от 16 символов.');
      const salt = remote.vault?.salt ?? randomBytes(16).toString('hex');
      const key = await keyFor(password, salt);
      try {
        const downloaded = remote.vault && this.parseVault(open(remote.vault, key, owner, remote.revision));
        const previous = this.workspace.data;
        const local = this.parseVault({ hosts: previous.servers.hosts, ...this.credentials.exportSync() });
        if (direction === 'pull') {
          const base = !knownRevision ? emptyVault : knownRevision === remote.revision ? downloaded :
            this.parseVault(open(checkpoint.vault, key, owner, knownRevision));
          const merged = await mergeVaults(base, local, downloaded, this.resolveConflict);
          if (!merged) return false;
          if (this.workspace.data !== previous) throw Error('Локальное хранилище изменилось. Повторите скачивание.');
          const { hosts, ...secrets } = this.parseVault(merged);
          const vault = this.credentials.importSync(secrets, local);
          this.workspace.update(value => {
            value.servers.hosts = hosts;
            value.vault = vault;
            value.checkpoint = { subject: owner, revision: remote.revision, vault: remote.vault };
          });
          this.credentials.refreshAfterSync(previous.vault);
        } else {
          const nextRevision = remote.revision + 1;
          const vault = seal(local, key, salt, owner, nextRevision);
          const uploaded = await this.request('vault', { method: 'PUT', data: { revision: remote.revision, vault } });
          if (uploaded.revision !== nextRevision) throw Error('Сервер вернул неверную ревизию.');
          this.workspace.update(value => { value.checkpoint = { subject: owner, revision: nextRevision, vault }; });
        }
        return true;
      } finally { key.fill(0); }
    });
  }
}

module.exports = { Sync, checkpointSchema, mergeVaults };
