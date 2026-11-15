const { Client, utils } = require('ssh2');
const { createHash, randomUUID } = require('node:crypto');

function target({ username, host, port }) {
  return username + '@' + (host.includes(':') ? '[' + host + ']' : host) + ':' + port;
}

class Sessions {
  items = new Map();

  constructor({ store, change, output, revoke, authenticate }) {
    Object.assign(this, { store, change, output, revoke, authenticate });
  }

  snapshot() {
    return [...this.items.values()].map(({ id, generation, host, state, error, trust }) =>
      ({ id, generation, host, state, error, trust }));
  }

  connect(host, id = randomUUID()) {
    if (this.items.size >= 32 && !this.items.has(id)) throw Error('Закройте лишние вкладки.');
    this.disconnect(id);
    const client = new Client();
    const session = { id, generation: randomUUID(), host, state: 'connecting', client };
    this.items.set(id, session);
    const live = () => this.items.get(id) === session && session.state !== 'closed' && session.state !== 'error';
    const endpoint = JSON.stringify([host.host, host.port]);
    const finish = error => { if (live()) this.disconnect(id, error); };
    client.on('error', error => {
      if (error.level === 'protocol' && error.message === 'Connection lost before handshake') {
        finish('TCP-соединение с ' + target(host) + ' закрылось до получения приветствия SSH. ' +
          'До проверки пароля дело не дошло. Сверьте SSH-порт и маршрут (VPN, bastion, прокси). ' +
          'Если адрес верный, проверьте журнал sshd и ограничения по IP или числу подключений.');
        return;
      }
      const hint = error.level === 'client-authentication'
        ? 'Проверьте пользователя, выбранный способ входа и разрешения на сервере.'
        : 'Проверьте адрес, порт и доступность SSH.';
      finish((session.state === 'host-key' ? 'Проверка ключа завершилась.' : 'Ошибка SSH.') + ' ' + hint + ' ' + error.message);
    });
    client.on('close', () => finish(session.state === 'host-key' ? 'Срок проверки ключа истёк. Подключитесь снова.' : undefined));
    client.on('end', () => finish());
    client.on('ready', () => {
      if (!live()) return;
      client.shell({ term: 'xterm-256color', cols: 100, rows: 30 }, (error, stream) => {
        if (!live()) return stream?.destroy();
        if (error) return finish('Сервер не открыл PTY: ' + error.message);
        session.stream = stream;
        stream.on('error', error => finish('Ошибка PTY: ' + error.message));
        stream.on('close', () => finish());
        for (const source of [stream, stream.stderr]) {
          source.on('data', data => {
            if (live()) this.output(session, data);
          });
        }
        session.state = 'ready';
        this.change();
      });
    });
    this.change();

    try {
      client.connect({
        host: host.host, port: host.port, username: host.username,
        ...this.authenticate(host), agentForward: false,
        readyTimeout: 120000, keepaliveInterval: 10000, keepaliveCountMax: 2,
        hostVerifier: (key, verify) => {
          if (!live()) return verify(false);
          const fingerprint = 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
          const known = this.store.data.hostKeys[endpoint];
          if (known === fingerprint) return verify(true);
          const rekey = session.state === 'ready';
          if (rekey) {
            this.revoke(id);
            // Reconnect explicitly before considering a replacement key.
            queueMicrotask(() => finish('Ключ изменился во время сеанса. Подключитесь заново и проверьте fingerprint.'));
            return verify(false);
          }
          const parsed = utils.parseKey(key);
          session.state = 'host-key';
          session.trust = { fingerprint, known, algorithm: parsed.type || 'SSH', target: target(host) };
          session.verify = accepted => {
            delete session.verify;
            delete session.trust;
            if (!accepted) return finish('Ключ сервера отклонён. Сверьте fingerprint и подключитесь снова.');
            this.store.update(data => { data.hostKeys[endpoint] = fingerprint; });
            session.state = 'connecting';
            this.change();
            verify(true);
          };
          this.change();
        },
      });
    } catch (error) { finish(error.message); }
    return id;
  }

  verify(id, generation, fingerprint, accepted) {
    const session = this.items.get(id);
    if (session?.generation !== generation || session.trust?.fingerprint !== fingerprint)
      throw Error('Запрос проверки больше не действует.');
    try { session.verify(accepted === true); }
    catch (error) {
      this.disconnect(id, 'Не удалось сохранить ключ: ' + error.message);
      throw error;
    }
  }

  disconnect(id, error) {
    const session = this.items.get(id);
    if (!session || ['closed', 'error'].includes(session.state)) return;
    session.state = error ? 'error' : 'closed';
    session.error = error;
    delete session.trust;
    delete session.verify;
    this.revoke(id);
    session.client.destroy();
    this.change();
  }

  remove(id) {
    this.disconnect(id);
    this.items.delete(id);
    this.change();
  }

  writable(session) {
    return session?.state === 'ready' && session.stream?.writable && !session.stream.destroyed;
  }

  input(id, generation, text) {
    const session = this.items.get(id);
    if (session?.generation === generation && this.writable(session) &&
        typeof text === 'string' && text.length <= 65536 && !session.stream.writableNeedDrain)
      session.stream.write(text);
  }

  resize(id, generation, cols, rows) {
    const session = this.items.get(id);
    if (session?.generation === generation && this.writable(session) &&
        [cols, rows].every(n => Number.isInteger(n) && n > 0 && n <= 1000))
      session.stream.setWindow(rows, cols, 0, 0);
  }
}

module.exports = { Sessions, target };
