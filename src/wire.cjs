const { createHash, createHmac, timingSafeEqual, randomBytes } = require('node:crypto');
const { join } = require('node:path');
const { tmpdir } = require('node:os');
const { StringDecoder } = require('node:string_decoder');

const nonce = () => randomBytes(32).toString('hex');
const valid = value => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const name = token => 'sshash-' + createHash('sha256').update(token).digest('hex').slice(0, 32);
const directory = token => join(tmpdir(), name(token));
const address = token => process.platform === 'win32'
  ? '//./pipe/' + name(token) : join(directory(token), 'mcp.sock');
const proof = (token, role, client, server) =>
  createHmac('sha256', Buffer.from(token, 'hex')).update(role + ':' + client + ':' + server).digest('hex');
const matches = (expected, value) =>
  valid(value) && timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(value, 'hex'));

function receive(onPacket, onInvalid) {
  const decoder = new StringDecoder('utf8');
  let input = '';
  let failed = false;
  return bytes => {
    if (failed) return;
    input += decoder.write(bytes);
    try {
      let end;
      while ((end = input.indexOf('\n')) >= 0) {
        if (end > 96 * 1024) throw Error('Frame too large');
        const line = input.slice(0, end);
        input = input.slice(end + 1);
        onPacket(JSON.parse(line));
      }
      if (input.length > 96 * 1024) throw Error('Frame too large');
    } catch {
      failed = true;
      onInvalid();
    }
  };
}

module.exports = { nonce, valid, name, directory, address, proof, matches, receive };
