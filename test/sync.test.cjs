const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs/promises');
const { generateKeyPairSync, randomBytes } = require('node:crypto');
const { createServer } = require('node:net');
const { spawn } = require('node:child_process');
const { once } = require('node:events');
const { join, resolve } = require('node:path');
const { tmpdir } = require('node:os');
const { Sync } = require('../src/sync.cjs');
const { Credentials } = require('../src/credentials.cjs');

const root = resolve(__dirname, '..');
const master = 'test master password for both devices';
const firstId = '0123456789abcdef';
const otherId = 'fedcba9876543210';
const secret = 'unique-test-ssh-password';
const hostA = { id: 'a', label: 'SSH password server A', host: 'a.test', port: 22, group: 'Test', username: 'user', auth: 'password' };
const hostB = { ...hostA, id: 'b', host: 'b.test', label: 'Workstation B', auth: 'agent' };

async function listenPort() {
  const listener = createServer();
  listener.listen(0, '127.0.0.1');
  await once(listener, 'listening');
  const port = listener.address().port;
  await new Promise(resolve => listener.close(resolve));
  return port;
}

test('central login, encrypted push and pull, three-way merge, conflicts and account isolation', { timeout: 45000 }, async () => {
  const directory = await fs.mkdtemp(join(tmpdir(), 'sshnesh-sync-'));
  const children = [];
  let usedGrant;
  try {
    const database = join(directory, 'sync.sqlite');
    const accountRoot = join(directory, 'website');
    await fs.mkdir(join(accountRoot, 'auth'), { recursive: true });
    await fs.copyFile(join(root, 'server/xelopat/sshnesh-login.php'), join(accountRoot, 'sshnesh-login.php'));
    await fs.writeFile(join(accountRoot, 'auth/lib.php'), `<?php
      function auth_current_user() {
        if (!isset($_SERVER['HTTP_X_TEST_USER'])) return null;
        return ['id' => $_SERVER['HTTP_X_TEST_USER'], 'username' => 'test-user'];
      }
      function csrf_token() { return 'test-csrf'; }
      function csrf_check($token) { return $token === csrf_token(); }
      function h($text) { return htmlspecialchars($text, ENT_QUOTES); }
    `);
    const env = { ...process.env, SSHNESH_SYNC_DB: database, SSHNESH_ACCOUNT_SECRET: randomBytes(32).toString('hex') };
    async function start(docroot) {
      const port = await listenPort();
      const options = process.env.PHP_EXTENSION_DIR ?
        ['-d', 'extension_dir=' + process.env.PHP_EXTENSION_DIR, '-d', 'extension=pdo_sqlite'] : [];
      const child = spawn(process.env.PHP_BIN || 'php', [...options, '-S', '127.0.0.1:' + port, '-t', docroot],
        { env, stdio: ['ignore', 'ignore', 'pipe'], windowsHide: true });
      children.push(child);
      await Promise.race([once(child.stderr, 'data'), once(child, 'exit').then(() => { throw Error('PHP did not start'); })]);
      return 'http://127.0.0.1:' + port;
    }
    const server = await start(join(root, 'server/public'));
    const site = await start(accountRoot);
    const fetchApi = (url, options) => fetch(server + new URL(url).pathname, options);
    async function browser(url, owner) {
      const query = new URL(url).search;
      const callback = site + '/sshnesh-login.php' + query;
      const anonymous = await fetch(callback, { redirect: 'manual' });
      assert.match(anonymous.headers.get('location'), /^\/auth\/login\?next=/);
      const headers = { 'X-Test-User': owner };
      const page = await fetch(callback, { headers });
      assert.match(await page.text(), /test-user/);
      const body = new URLSearchParams(query);
      const badCsrf = await fetch(callback, { method: 'POST', headers, body });
      assert.equal(badCsrf.status, 403);
      body.set('csrf', 'test-csrf');
      const done = await fetch(callback, { method: 'POST', headers, body });
      assert.equal(done.status, 200);
      assert.match(await done.text(), /SSHnesh/);
    }

    const makeDevice = (owner = firstId, initial = [], choices = []) => {
      const workspace = {
        data: { servers: { hosts: initial }, vault: { keys: {}, passwords: {} } },
        update(edit) { const next = structuredClone(this.data); edit(next); this.data = next; },
      };
      const credentials = new Credentials({
        store: { get data() { return workspace.data.vault; }, update(edit) { workspace.update(next => edit(next.vault)); } },
        // Use an isolated test keyring fixture. No OS keyring or user account is accessed.
        encryption: { available: () => true, encrypt: value => Buffer.from('test:' + value), decrypt: bytes => bytes.toString().slice(5) },
      });
      const sync = new Sync({ workspace, credentials, parseVault: value => value, publish() {},
        fetcher: async (url, options) => {
          if (url.endsWith('session.php') && options.method === 'POST') {
            usedGrant = JSON.parse(options.body);
            const wrong = await fetchApi(url, { ...options, body: JSON.stringify({ ...usedGrant, verifier: '0'.repeat(64) }) });
            assert.equal(wrong.status, 401);
          }
          return fetchApi(url, options);
        },
        openExternal: url => browser(url, owner), resolveConflict: async () => choices.shift(),
        signal: new AbortController().signal,
      });
      return { sync, workspace, credentials };
    };
    const left = makeDevice(firstId, [hostA]);
    const right = makeDevice(firstId, [], [null, 'local']);
    const other = makeDevice(otherId);
    await left.sync.login();
    assert.equal(left.sync.snapshot().username, 'test-user');
    const replay = await left.sync.request('session', { method: 'POST', data: usedGrant, authenticated: false }).catch(error => error);
    assert.match(replay.message, /заново/);
    left.credentials.setPassword(hostA, Buffer.from(secret));
    const keyPath = join(directory, 'test-key.pem');
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs1', format: 'pem' }, publicKeyEncoding: { type: 'spki', format: 'pem' } });
    await fs.writeFile(keyPath, privateKey);
    await left.credentials.import(keyPath, () => assert.fail('Test key has no passphrase'));
    const [key] = left.credentials.list();
    await left.sync.transfer('push', master);
    const cloud = await left.sync.request('vault');
    assert.equal(cloud.revision, 1);
    assert.ok(cloud.vault.body.length > 0);
    assert.equal((await fs.readFile(database)).includes(secret), false);
    assert.equal((await fs.readFile(database)).includes(hostA.label), false);
    assert.equal((await fs.readFile(database)).includes('BEGIN RSA PRIVATE KEY'), false);
    await right.sync.login();
    await assert.rejects(right.sync.transfer('pull', 'wrong master password'), /мастер-пароль/);
    assert.deepEqual(right.workspace.data.servers.hosts, []);
    await right.sync.transfer('pull', master);
    assert.deepEqual(right.workspace.data.servers.hosts, [hostA]);
    assert.equal(right.credentials.hasPassword(hostA), true);
    assert.equal(await right.credentials.unlock(key.id, () => assert.fail('Test key has no passphrase')), true);
    assert.equal(right.credentials.publicKey(key.id), left.credentials.publicKey(key.id));
    await other.sync.login();
    assert.deepEqual(await other.sync.request('vault'), { revision: 0, vault: null });
    await assert.rejects(left.sync.request('vault', { method: 'PUT', data: { revision: 0, vault: cloud.vault } }), /другая версия/);

    left.workspace.update(value => { value.servers.hosts[0].group = 'New group'; });
    right.workspace.update(value => { value.servers.hosts.push(hostB); });
    await left.sync.transfer('push', master);
    await assert.rejects(right.sync.transfer('push', master), /актуальную версию/);
    await right.sync.transfer('pull', master);
    assert.deepEqual(right.workspace.data.servers.hosts, [{ ...hostA, group: 'New group' }, hostB]);
    await right.sync.transfer('push', master);
    await left.sync.transfer('pull', master);
    assert.deepEqual(left.workspace.data.servers.hosts, right.workspace.data.servers.hosts);

    // Concurrent edit versus deletion. Cancelling leaves the local copy and checkpoint intact.
    right.workspace.update(value => { value.servers.hosts[0].label = 'Local edit'; });
    left.workspace.update(value => { value.servers.hosts.shift(); delete value.vault.passwords[hostA.id]; });
    await left.sync.transfer('push', master);
    const before = right.workspace.data;
    assert.equal(await right.sync.transfer('pull', master), false);
    assert.equal(right.workspace.data, before);
    assert.equal(await right.sync.transfer('pull', master), true);
    assert.equal(right.workspace.data.servers.hosts[0].label, 'Local edit');
    assert.equal(right.credentials.hasPassword(hostA), true);
    await right.sync.logout();
    await assert.rejects(right.sync.request('vault'), /Сначала войдите/);
  } finally {
    for (const child of children) {
      if (child.exitCode !== null || !child.pid) continue;
      child.kill();
      await once(child, 'exit');
    }
    await fs.rm(directory, { recursive: true, force: true, maxRetries: 3 });
  }
});
