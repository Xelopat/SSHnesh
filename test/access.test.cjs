const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { Access } = require('../src/access.cjs');

function fixture(approvalMode = 'manual') {
  const writes = [];
  const session = {
    id: randomUUID(), generation: randomUUID(), host: { host: 'localhost', username: 'test', port: 22 },
    stream: { write: value => writes.push(value) },
  };
  const sessions = { items: new Map([[session.id, session]]), writable: s => Boolean(s?.stream) };
  const access = new Access({ sessions, change() {}, approvalMode });
  access.enabled = true;
  access.share(session.id, session.generation);
  const { target, ...binding } = access.binding();
  const args = () => ({ ...binding, requestId: randomUUID(), expiresAt: Date.now() + 5000 });
  return { access, session, sessions, args, writes };
}

test('cancel, deny, duplicate and stale approval never write', async () => {
  const { access, args, writes } = fixture();
  const a = { ...args(), text: 'echo cancel' };
  const pending = access.call('p', 'send', a);
  assert.equal(access.call('other', 'cancel', a && { requestId: a.requestId }).status, 'not_pending');
  assert.equal(access.call('p', 'cancel', { requestId: a.requestId }).status, 'cancelled');
  assert.equal((await pending).status, 'cancelled');
  assert.throws(() => access.decide(a.requestId, true), /завершён/);
  assert.throws(() => access.call('p', 'send', a), /использован/);
  const b = { ...args(), text: 'echo deny' };
  const denied = access.call('p', 'send', b);
  access.decide(b.requestId, false);
  assert.equal((await denied).status, 'denied');
  assert.deepEqual(writes, []);
});

test('expired absolute deadline and late approval are rejected', async () => {
  const { access, args, writes } = fixture();
  const expired = { ...args(), text: 'echo old', expiresAt: Date.now() - 1 };
  assert.equal((await access.call('p', 'send', expired)).status, 'expired');
  const waiting = { ...args(), text: 'echo old', expiresAt: Date.now() + 30 };
  const pending = access.call('p', 'send', waiting);
  // Block the event loop so the decision runs before the queued expiry callback.
  const until = Date.now() + 40;
  while (Date.now() < until) {}
  assert.equal(access.decide(waiting.requestId, true).status, 'expired');
  assert.equal((await pending).status, 'expired');
  assert.deepEqual(writes, []);
});

test('generation replacement invalidates a pending command', async () => {
  const { access, args, writes, session, sessions } = fixture();
  const a = { ...args(), text: 'echo other' };
  const pending = access.call('p', 'send', a);
  sessions.items.set(session.id, { ...session, generation: randomUUID() });
  assert.equal(access.decide(a.requestId, true).status, 'revoked');
  assert.equal((await pending).status, 'revoked');
  assert.deepEqual(writes, []);
});

test('writes once, cancel after send cannot imply stopped', async () => {
  const { access, args, writes } = fixture();
  const a = { ...args(), text: 'echo café' };
  const pending = access.call('p', 'send', a);
  access.decide(a.requestId, true);
  assert.equal((await pending).status, 'sent');
  assert.equal(access.call('p', 'cancel', { requestId: a.requestId }).status, 'not_pending');
  assert.throws(() => access.call('p', 'send', a), /использован/);
  assert.deepEqual(writes, ['echo café\r']);
});

test('UTF-8 output is bounded and always released automatically', async () => {
  const { access, args, session } = fixture();
  const bytes = Buffer.from('секрет\r\n');
  access.append(session, bytes.subarray(0, 1));
  access.append(session, bytes.subarray(1));
  const read = maxChars => access.call('p', 'output', { ...args(), maxChars });
  const result = await read(3);
  assert.equal(result.output, 'сек');
  assert.match(result.warning, /НЕДОВЕРЕННЫЕ/);
  assert.equal((await read(128)).output, 'рет\n');
  assert.equal((await read(128)).output, '');
  assert.deepEqual(access.snapshot().pending, []);
});

test('blocked SSH stream does not enqueue an approved command', async () => {
  const { access, args, writes, session } = fixture();
  session.stream.writableNeedDrain = true;
  const a = { ...args(), text: 'echo blocked' };
  const pending = access.call('p', 'send', a);
  access.decide(a.requestId, true);
  assert.equal((await pending).status, 'busy');
  assert.deepEqual(writes, []);
});

test('manual input stays pending while new output is released and the setting changes', async () => {
  const { access, args, session, writes } = fixture();
  access.append(session, Buffer.from('\x1b[31mhello\x1b[0m\r\n'));
  const input = { ...args(), text: 'echo manual' };
  const pending = access.call('p', 'send', input);
  const result = await access.call('p', 'output', { ...args(), maxChars: 64 });
  assert.equal(result.status, 'released');
  assert.equal(result.output, 'hello\n');
  assert.match(result.warning, /НЕДОВЕРЕННЫЕ/);
  assert.equal(access.snapshot().history[0].automatic, true);
  assert.deepEqual(access.snapshot().pending.map(request => request.requestId), [input.requestId]);
  access.approvalMode = 'all';
  access.decide(input.requestId, false);
  assert.equal((await pending).status, 'denied');
  assert.deepEqual(writes, []);
});

test('auto input sends once and checks the expiry, connection and stream before writing', async () => {
  const { access, args, session, writes } = fixture('all');
  assert.equal(access.call('p', 'status').approvalMode, 'all');
  const command = { ...args(), text: 'echo automatic' };
  assert.equal((await access.call('p', 'send', command)).status, 'sent');
  assert.throws(() => access.call('p', 'send', command), /использован/);
  assert.equal(access.snapshot().history[0].automatic, true);
  assert.deepEqual(access.snapshot().pending, []);
  assert.equal((await access.call('p', 'send', {
    ...args(), text: 'echo expired', expiresAt: Date.now() - 1,
  })).status, 'expired');
  session.stream.writableNeedDrain = true;
  assert.equal((await access.call('p', 'send', { ...args(), text: 'echo busy' })).status, 'busy');
  access.revoke(session.id);
  assert.throws(() => access.call('p', 'send', { ...args(), text: 'echo revoked' }), /отозвано/);
  assert.deepEqual(writes, ['echo automatic\r']);
});
