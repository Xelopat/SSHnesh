const { test } = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { Access } = require('../src/access.cjs');

function fixture() {
  const writes = [];
  const session = {
    id: randomUUID(), generation: randomUUID(), host: { host: 'localhost', username: 'test', port: 22 },
    stream: { write: value => writes.push(value) },
  };
  const sessions = { items: new Map([[session.id, session]]), writable: s => Boolean(s?.stream) };
  const access = new Access({ sessions, change() {} });
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

test('UTF-8 output is bounded, edited and released only on approval', async () => {
  const { access, args, session } = fixture();
  const bytes = Buffer.from('секрет\r\n');
  access.append(session, bytes.subarray(0, 1));
  access.append(session, bytes.subarray(1));
  const a = { ...args(), maxChars: 128 };
  const pending = access.call('p', 'output', a);
  assert.equal(access.snapshot().pending[0].draft, 'секрет\n');
  access.decide(a.requestId, true, '[скрыто]');
  const result = await pending;
  assert.equal(result.output, '[скрыто]');
  assert.match(result.warning, /НЕДОВЕРЕННЫЕ/);
  const b = { ...args(), maxChars: 128 };
  const next = access.call('p', 'output', b);
  assert.equal(access.snapshot().pending[0].draft, '');
  access.closed('p');
  assert.equal((await next).status, 'cancelled');
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
