const fs = require('node:fs/promises');
const path = require('node:path');
const { spawn } = require('node:child_process');
const { createHash } = require('node:crypto');
const { isDeepStrictEqual, promisify } = require('node:util');
const { BaseAgent, utils } = require('ssh2');

async function askSecret(helper, title, signal, owner) {
  if (process.platform !== 'win32') throw Error('Ввод пароля и парольной фразы в приложении доступен на Windows.');
  return new Promise((resolve, reject) => {
    const proc = spawn(helper, ['--secret', title, owner], { stdio: ['ignore', 'pipe', 'ignore'], signal });
    const chunks = [];
    let size = 0;
    const timeout = setTimeout(() => proc.kill(), 180000);
    proc.stdout.on('data', chunk => {
      chunks.push(chunk);
      size += chunk.length;
      if (size > 16384) proc.kill();
    });
    proc.on('error', () => reject(Error('Не удалось открыть окно ввода SSHnesh.')));
    proc.on('close', (code, signal) => {
      clearTimeout(timeout);
      const secret = code === 0 && size > 0 && size <= 16384 ? Buffer.concat(chunks) : null;
      for (const chunk of chunks) chunk.fill(0);
      if (signal || size > 16384 || (code === 0 && !secret) || (code !== 0 && code !== 1))
        reject(Error('Окно ввода SSHnesh завершилось. Повторите ввод.'));
      else resolve(secret);
    });
  });
}

const targetId = host => JSON.stringify(host.credentialId || !host.host ? [host.username] : [host.host, host.port, host.username]);
const passwordId = host => host.credentialId ?? host.id;
const limit = 128 * 1024;
const generateKeyPair = promisify(utils.generateKeyPair);
class Credentials {
  #keys = new Map();
  #passwords = new Map();

  constructor({ store, encryption }) {
    this.store = store;
    this.encryption = encryption;
  }

  #seal(bytes) {
    if (!this.encryption.available()) throw Error('Системное шифрование недоступно. Хранилище ключей не изменено.');
    return this.encryption.encrypt(bytes.toString('base64')).toString('base64');
  }

  #open(cipher) {
    if (!this.encryption.available()) throw Error('Разблокируйте системное хранилище и повторите.');
    try { return Buffer.from(this.encryption.decrypt(Buffer.from(cipher, 'base64')), 'base64'); }
    catch { throw Error('Не удалось открыть хранилище текущего пользователя. Задайте пароль или импортируйте ключ заново.'); }
  }

  exportSync() {
    const read = cipher => {
      const bytes = this.#open(cipher);
      try { return bytes.toString('base64'); }
      finally { bytes.fill(0); }
    };
    return {
      keys: Object.fromEntries(Object.entries(this.store.data.keys).map(([id, { cipher, ...key }]) =>
        [id, { ...key, secret: read(cipher) }])),
      passwords: Object.fromEntries(Object.entries(this.store.data.passwords).map(([id, { cipher, target }]) =>
        [id, { target, secret: read(cipher) }])),
    };
  }

  importSync(secrets, current) {
    const seal = secret => {
      const bytes = Buffer.from(secret, 'base64');
      try { return this.#seal(bytes); }
      finally { bytes.fill(0); }
    };
    return {
      keys: Object.fromEntries(Object.entries(secrets.keys).map(([id, { secret, ...key }]) =>
        [id, isDeepStrictEqual(secrets.keys[id], current.keys[id]) ? this.store.data.keys[id] :
          { ...key, cipher: seal(secret) }])),
      passwords: Object.fromEntries(Object.entries(secrets.passwords).map(([id, { secret, target }]) =>
        [id, isDeepStrictEqual(secrets.passwords[id], current.passwords[id]) ? this.store.data.passwords[id] :
          { target, cipher: seal(secret) }])),
    };
  }

  refreshAfterSync(previous) {
    for (const id of this.#keys.keys())
      if (previous.keys[id]?.cipher !== this.store.data.keys[id]?.cipher) this.#keys.delete(id);
    for (const id of this.#passwords.keys())
      if (previous.passwords[id]?.cipher !== this.store.data.passwords[id]?.cipher) this.#clearPassword(id);
  }

  list() {
    return Object.values(this.store.data.keys).map(({ id, name, type, protected: locked }) =>
      ({ id, name, type, protected: locked, unlocked: this.#keys.has(id) }));
  }

  publicKey(id) {
    const entry = this.store.data.keys[id];
    if (!entry) throw Error('Ключ удалён из хранилища.');
    return entry.type + ' ' + entry.publicBlob;
  }

  async import(file, prompt) {
    const handle = await fs.open(file, 'r');
    const bytes = Buffer.alloc(limit + 1);
    try {
      const stat = await handle.stat();
      if (!stat.isFile() || stat.size > limit) throw Error('Выберите файл приватного ключа размером до 128 КБ.');
      let bytesRead = 0;
      while (bytesRead < bytes.length) {
        const read = await handle.read(bytes, bytesRead, bytes.length - bytesRead);
        if (!read.bytesRead) break;
        bytesRead += read.bytesRead;
      }
      if (bytesRead > limit) throw Error('Размер файла превышает 128 КБ.');
      const raw = bytes.subarray(0, bytesRead);
      const parsed = await this.#parse(raw, prompt);
      if (!parsed) return false;
      const name = path.basename(file).replace(/[\p{Cc}\p{Cf}]/gu, '').slice(0, 120) || parsed.key.type;
      this.#saveKey(name, raw, parsed);
      return true;
    } finally {
      bytes.fill(0);
      await handle.close();
    }
  }

  async generate(name) {
    const pair = await generateKeyPair('ed25519');
    const raw = Buffer.from(pair.private);
    try {
      const parsed = await this.#parse(raw);
      this.#saveKey(name, raw, parsed);
    } finally { raw.fill(0); }
  }

  #saveKey(name, raw, { key, protected: protectedKey }) {
    const { id, publicKey } = this.#identity(key);
    if (!this.store.data.keys[id] && Object.keys(this.store.data.keys).length >= 64)
      throw Error('Достигнут лимит в 64 ключа.');
    const entry = { id, name, type: publicKey.type, publicBlob: publicKey.getPublicSSH().toString('base64'),
      protected: protectedKey, cipher: this.#seal(raw) };
    this.store.update(data => { data.keys[id] = entry; });
    this.#keys.set(id, { key, publicKey });
  }

  async #parse(raw, prompt) {
    let key = utils.parseKey(raw);
    const protectedKey = key instanceof Error && /no passphrase given/i.test(key.message);
    if (protectedKey) {
      const passphrase = await prompt?.();
      if (!passphrase) return null;
      try { key = utils.parseKey(raw, passphrase); }
      finally { passphrase.fill(0); }
      if (key instanceof Error) throw Error('Не удалось разблокировать ключ. Проверьте парольную фразу и формат файла.');
    }
    if (key instanceof Error || Array.isArray(key) || !key.isPrivateKey())
      throw Error('Выберите один приватный ключ в поддерживаемом формате OpenSSH, PEM или PPK.');
    return { key, protected: protectedKey };
  }

  #identity(key) {
    const blob = key.getPublicSSH();
    return { id: createHash('sha256').update(blob).digest('base64url'), publicKey: utils.parseKey(blob) };
  }

  async unlock(id, prompt) {
    if (this.#keys.has(id)) return true;
    const entry = this.store.data.keys[id];
    if (!entry) throw Error('Выберите сохранённый ключ в настройках сервера.');
    const raw = this.#open(entry.cipher);
    try {
      const parsed = await this.#parse(raw, prompt);
      if (!parsed) return false;
      const identity = this.#identity(parsed.key);
      if (identity.id !== id || this.store.data.keys[id]?.cipher !== entry.cipher)
        throw Error('Ключ изменился. Выберите его заново.');
      this.#keys.set(id, { key: parsed.key, publicKey: identity.publicKey });
      return true;
    } finally { raw.fill(0); }
  }

  remove(id) {
    this.store.update(data => { delete data.keys[id]; });
    this.#keys.delete(id);
  }
  #clearPassword(id) {
    this.#passwords.get(id)?.secret.fill(0);
    this.#passwords.delete(id);
  }
  hasPassword(host) { return this.store.data.passwords[passwordId(host)]?.target === targetId(host); }
  setPassword(host, secret) {
    const id = passwordId(host);
    try {
      const entry = { target: targetId(host), cipher: this.#seal(secret) };
      this.store.update(data => { data.passwords[id] = entry; });
      this.#clearPassword(id);
      this.#passwords.set(id, { target: entry.target, secret });
    } catch (error) {
      secret.fill(0);
      throw error;
    }
  }
  removePassword(id) {
    if (Object.hasOwn(this.store.data.passwords, id))
      this.store.update(data => { delete data.passwords[id]; });
    this.#clearPassword(id);
  }
  loadPassword(host) {
    const id = passwordId(host);
    if (!this.hasPassword(host)) return false;
    if (this.#passwords.get(id)?.target !== targetId(host)) {
      this.#clearPassword(id);
      this.#passwords.set(id, { target: targetId(host), secret: this.#open(this.store.data.passwords[id].cipher) });
    }
    return true;
  }
  clear() {
    this.#keys.clear();
    for (const id of this.#passwords.keys()) this.#clearPassword(id);
  }

  authentication(host, systemAgent) {
    if (host.auth === 'password') {
      const id = passwordId(host);
      if (!this.loadPassword(host)) throw Error('Откройте настройки сервера и задайте пароль.');
      let attempted = false;
      return { authHandler: () => {
        if (attempted || !this.hasPassword(host) || !this.#passwords.has(id)) return false;
        attempted = true;
        return { type: 'password', username: host.username, password: this.#passwords.get(id).secret };
      } };
    }
    if (host.auth === 'key') {
      if (!this.#keys.has(host.keyId)) throw Error('Импортируйте выбранный ключ заново через раздел «Ключи».');
      const lookup = () => this.#keys.get(host.keyId);
      // ssh2 receives only the public identity and signatures from this in-process agent.
      const agent = new class extends BaseAgent {
        getIdentities(callback) { const entry = lookup(); callback(null, entry ? [entry.publicKey] : []); }
        sign(_publicKey, data, options, callback) {
          const result = lookup()?.key.sign(data, options?.hash);
          if (!result || result instanceof Error) callback(Error('Ключ недоступен для подписи.'));
          else callback(null, result);
        }
      }();
      return { agent, authHandler: ['agent'] };
    }
    const agent = systemAgent();
    if (!agent) throw Error('Запустите системный SSH-агент и загрузите в него ключ.');
    return { agent, authHandler: ['agent'] };
  }
}

module.exports = { Credentials, askSecret, passwordTarget: targetId };
