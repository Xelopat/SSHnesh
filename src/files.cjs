const { dialog } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { randomUUID } = require('node:crypto');
const { pipeline } = require('node:stream/promises');

const remotePath = value => {
  if (typeof value !== 'string' || value.length > 4096 || !value || value.includes('\0'))
    throw Error('Укажите корректный удалённый путь.');
  return value;
};
const call = (object, method, ...args) =>
  new Promise((resolve, reject) => {
    object[method](...args, (error, value) => error ? reject(error) : resolve(value));
  });

function fileRoutes(route, sessions, owner) {
  let localRoot;
  let scope;
  let transferring = false;
  const localPath = async (expected, relative, directory = true) => {
    if (!localRoot || expected !== scope || typeof relative !== 'string' ||
        relative.length > 4096 || path.isAbsolute(relative) || relative.includes('\0') ||
        (process.platform === 'win32' && relative.includes(':')))
      throw Error('Выберите локальную папку заново.');
    const inside = candidate => {
      const remainder = path.relative(localRoot, candidate);
      return remainder !== '..' && !remainder.startsWith('..' + path.sep) && !path.isAbsolute(remainder);
    };
    const candidate = path.resolve(localRoot, relative);
    if (!inside(candidate)) throw Error('Путь находится вне выбранной папки.');
    const full = await fs.promises.realpath(candidate);
    if (expected !== scope || !inside(full)) throw Error('Путь находится вне выбранной папки.');
    const stat = await fs.promises.lstat(full);
    if (expected !== scope || !(directory ? stat.isDirectory() : stat.isFile()))
      throw Error('Выберите ' + (directory ? 'папку.' : 'обычный файл.'));
    return full;
  };

  route('files:choose-local', async () => {
    const { canceled, filePaths } = await dialog.showOpenDialog(owner(), {
      title: 'Выбрать локальную папку для обмена файлами', properties: ['openDirectory'],
    });
    if (canceled || !filePaths[0]) return null;
    localRoot = await fs.promises.realpath(filePaths[0]);
    scope = randomUUID();
    return scope;
  });
  route('files:local-list', async (expected, relative) => {
    const full = await localPath(expected, relative);
    const list = await fs.promises.readdir(full, { withFileTypes: true });
    if (expected !== scope) throw Error('Локальная папка изменилась.');
    return {
      dir: path.relative(localRoot, full).split(path.sep).join('/'), label: full, truncated: list.length > 5000,
      entries: list.slice(0, 5000).map(entry => ({
        name: entry.name, kind: entry.isDirectory() ? 'dir' : entry.isFile() ? 'file' : entry.isSymbolicLink() ? 'link' : 'other',
      })),
    };
  });
  function lookup(id, generation) {
    const session = sessions.items.get(id);
    if (session?.generation !== generation || !sessions.writable(session))
      throw Error('SSH-сеанс завершён. Выберите подключённый терминал.');
    return session;
  }

  async function channel(id, generation) {
    const session = lookup(id, generation);
    if (!session.sftp) {
      session.sftp = call(session.client, 'sftp').then(sftp => {
        const reset = () => { delete session.sftp; };
        sftp.on('error', reset);
        sftp.once('close', reset);
        return sftp;
      }, error => {
        delete session.sftp;
        throw Error('Не удалось открыть SFTP. Проверьте, что сервер разрешает подсистему sftp. ' + error.message);
      });
    }
    const sftp = await session.sftp;
    lookup(id, generation);
    return sftp;
  }

  route('files:list', async (id, generation, dir) => {
    const sftp = await channel(id, generation);
    const full = await call(sftp, 'realpath', remotePath(dir));
    const list = await call(sftp, 'readdir', full);
    lookup(id, generation);
    const entries = list.filter(entry => entry.filename !== '.' && entry.filename !== '..' && !entry.filename.includes('/'));
    return {
      dir: full, truncated: entries.length > 5000,
      entries: entries.slice(0, 5000).map(({ filename, attrs }) => ({
        name: filename, kind: attrs.isDirectory() ? 'dir' : attrs.isFile() ? 'file' : attrs.isSymbolicLink() ? 'link' : 'other',
        bytes: attrs.size, modified: attrs.mtime,
      })),
    };
  });

  route('files:transfer', async (direction, id, generation, expected, local, remote) => {
    if (direction !== 'upload' && direction !== 'download') throw Error('Укажите направление передачи.');
    if (transferring) throw Error('Дождитесь завершения текущей передачи.');
    transferring = true;
    try {
      const uploading = direction === 'upload';
      const sftp = await channel(id, generation);
      remote = remotePath(remote);
      const full = await localPath(expected, local, !uploading);
      lookup(id, generation);
      if (uploading) {
        const destination = path.posix.join(remote, path.basename(full));
        try {
          await pipeline(fs.createReadStream(full), sftp.createWriteStream(destination, { flags: 'wx', mode: 0o600 }));
        } catch (error) {
          throw Error('Не удалось отправить файл. Проверьте права и наличие файла с таким именем. При обрыве может остаться часть файла. ' + error.message);
        }
      } else {
        const name = path.posix.basename(remote);
        if (!name || name === '.' || name === '..' || /[\p{Cc}\p{Cf}]/u.test(name) ||
            (process.platform === 'win32' && (/[<>:"\\|?*]|[. ]$/.test(name) ||
              /^(con|prn|aux|nul|conin\$|conout\$|com[1-9¹²³]|lpt[1-9¹²³])(?:\s*\.|$)/i.test(name))))
          throw Error('Имя файла несовместимо с локальной файловой системой. Переименуйте файл на сервере.');
        if (!(await call(sftp, 'lstat', remote)).isFile()) throw Error('Выберите обычный файл для скачивания.');
        const dir = await localPath(expected, local);
        lookup(id, generation);
        const temp = path.join(dir, '.sshash-' + randomUUID() + '.part');
        try {
          await pipeline(sftp.createReadStream(remote), fs.createWriteStream(temp, { flags: 'wx', mode: 0o600 }));
          lookup(id, generation);
          if (await localPath(expected, local) !== dir) throw Error('Папка назначения изменилась.');
          try { await fs.promises.link(temp, path.join(dir, name)); }
          catch (error) {
            if (error.code === 'EEXIST') throw Error('В локальной папке уже есть файл с таким именем.');
            throw error;
          }
        } finally {
          await fs.promises.rm(temp, { force: true });
        }
      }
    } finally {
      transferring = false;
    }
  });
}

module.exports = { fileRoutes };
