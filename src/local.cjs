const fs = require('node:fs');
const net = require('node:net');
const { spawn } = require('node:child_process');
const readline = require('node:readline');
const { randomUUID } = require('node:crypto');
const { nonce, valid, name, directory, address, proof, matches, receive } = require('./wire.cjs');

function startLocal({ token, helper, onCall, onClose, onError, onCount }) {
  const peers = new Set();
  let authenticated = 0;
  let stopped = false;
  let cleanup;

  function attach(write, destroy) {
    const id = randomUUID();
    const peer = { close };
    let client, server, verified, closed;
    peers.add(peer);
    const timer = setTimeout(close, 3000);
    function close() {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      peers.delete(peer);
      destroy();
      if (verified) {
        onClose(id);
        onCount(--authenticated);
      }
    }
    const send = packet => {
      if (!closed) write(Buffer.from(JSON.stringify(packet) + '\n'));
    };
    const data = receive(packet => {
      if (!client) {
        if (!valid(packet?.hello)) return close();
        client = packet.hello;
        server = nonce();
        return send({ server, proof: proof(token, 'server', client, server) });
      }
      if (!verified) {
        if (!matches(proof(token, 'client', client, server), packet?.proof)) return close();
        clearTimeout(timer);
        verified = true;
        onCount(++authenticated);
        return send({ ready: true });
      }
      if (typeof packet?.id !== 'string' || packet.id.length > 100 ||
          typeof packet.method !== 'string') return close();
      Promise.resolve().then(() => !closed && onCall(id, packet.method, packet.args, packet.id))
        .then(result => send({ id: packet.id, result }),
          error => send({ id: packet.id, error: error.message }));
    }, close);
    return { data, close };
  }

  function fail(error) {
    if (stopped) return;
    for (const peer of peers) peer.close();
    onError(error);
  }

  if (process.platform === 'win32') {
    const child = spawn(helper, [name(token)], { stdio: ['pipe', 'pipe', 'pipe'], windowsHide: true });
    const connections = new Map();
    let stderr = '';
    child.stderr.setEncoding('utf8').on('data', data => { stderr = (stderr + data).slice(-400); });
    child.stdin.on('error', fail);
    child.on('error', fail);
    child.on('exit', code => fail(Error('Локальный канал завершился (' + code + '). ' + stderr)));
    function send(id, kind, bytes) {
      if (!child.stdin.destroyed) {
        if (child.stdin.writableLength > 256 * 1024) {
          child.kill();
          return;
        }
        child.stdin.write(JSON.stringify({ id, kind, bytes: bytes?.toString('base64') }) + '\n');
      }
    }
    readline.createInterface({ input: child.stdout }).on('line', line => {
      try {
        const { id, kind, bytes } = JSON.parse(line);
        if (kind === 'open') {
          connections.set(id, attach(data => send(id, 'data', data), () => send(id, 'close')));
        } else if (kind === 'data') {
          connections.get(id)?.data(Buffer.from(bytes, 'base64'));
        } else if (kind === 'close') {
          connections.get(id)?.close();
          connections.delete(id);
        }
      } catch (error) { fail(error); }
    });
    cleanup = () => child.kill();
  } else {
    const dir = directory(token);
    const server = net.createServer(socket => {
      if (peers.size >= 12) return socket.destroy();
      const peer = attach(bytes => {
        if (socket.writableLength > 256 * 1024) socket.destroy();
        else socket.write(bytes);
      }, () => socket.destroy());
      socket.on('data', peer.data).on('error', peer.close).on('close', peer.close);
    });
    let bound = false;
    cleanup = () => {
      server.close();
      if (bound) {
        try { fs.rmdirSync(dir); } catch { /* directory stays private */ }
      }
    };
    try {
      try { fs.mkdirSync(dir, { mode: 0o700 }); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const stat = fs.lstatSync(dir);
        if (!stat.isDirectory() || stat.uid !== process.getuid() || (stat.mode & 0o077))
          throw Error('Небезопасные права каталога MCP.');
      }
      server.on('error', fail);
      server.listen(address(token), () => { bound = true; });
    } catch (error) { queueMicrotask(() => fail(error)); }
  }
  return () => {
    stopped = true;
    for (const peer of peers) peer.close();
    cleanup();
  };
}
module.exports = { startLocal };
