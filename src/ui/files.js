export function setupFiles({ api, $, el, button, endpoint }) {
  let scope, binding, drag, busy = false, options = [];
  const select = $('file-session');
  const transferStatus = $('file-transfer-status');
  const hint = transferStatus.textContent;
  const nameSafe = name => name.replace(/[\p{Cc}\p{Cf}]/gu, c => '⟦U+' + c.codePointAt(0).toString(16).toUpperCase() + '⟧');
  const join = (dir, name) => dir.endsWith('/') ? dir + name : dir ? dir + '/' + name : name;
  const formatSize = new Intl.NumberFormat('ru-RU');
  const local = panel('local');
  const remote = panel('remote');

  function panel(side) {
    const isLocal = side === 'local';
    return {
      side, isLocal, root: $(side + '-pane'), dir: null, version: 0,
      input: $(isLocal ? 'local-path' : 'file-path'),
      browser: $(isLocal ? 'local-browser' : 'file-browser'),
      empty: $(isLocal ? 'local-empty' : 'file-empty'),
      rows: $(isLocal ? 'local-list' : 'file-list'),
      status: $(isLocal ? 'local-status' : 'file-error'),
    };
  }

  function show(panel, enabled) {
    panel.browser.hidden = !enabled;
    panel.empty.hidden = enabled;
    if (!enabled) {
      ++panel.version;
      panel.dir = null;
      panel.rows.replaceChildren();
    }
  }

  async function load(panel, dir) {
    const index = ++panel.version;
    panel.dir = null;
    panel.status.textContent = 'Чтение каталога…';
    panel.status.classList.remove('error');
    panel.rows.replaceChildren();
    try {
      const result = panel.isLocal ? await api.listLocal(scope, dir) :
        await api.listFiles(binding.id, binding.generation, dir);
      if (panel.version !== index) return;
      panel.dir = result.dir;
      if (panel.isLocal) {
        panel.input.textContent = result.label;
        panel.input.title = result.label;
        $('local-up').disabled = !result.dir;
      } else panel.input.value = result.dir;
      panel.status.textContent = result.truncated ? 'Показаны первые 5000 записей.' : result.entries.length ? '' : 'Каталог пуст.';
      const ordered = result.entries.sort((a, b) =>
        Number(b.kind === 'dir') - Number(a.kind === 'dir') || a.name.localeCompare(b.name));
      const fragment = document.createDocumentFragment();
      for (const entry of ordered) fragment.append(fileRow(panel, entry));
      panel.rows.append(fragment);
    } catch (error) {
      if (panel.version !== index) return;
      panel.status.classList.add('error');
      panel.status.textContent = 'Не удалось открыть каталог. Проверьте путь и права. ' + message(error);
    }
  }

  function message(error) {
    return error.message.replace(/^Error invoking remote method '[^']+': Error: /, '');
  }

  function fileRow(panel, entry) {
    const row = el('tr');
    const name = el('td');
    const actions = el('td');
    const display = nameSafe(entry.name);
    const file = join(panel.dir, entry.name);
    if (entry.kind === 'dir') {
      name.append(button('▸ ' + display, () => load(panel, file), 'file-folder'));
    } else {
      name.textContent = display + (entry.kind === 'link' ? ' ↗' : '');
    }
    if (entry.kind === 'file') {
      row.draggable = true;
      row.classList.add('file-draggable');
      row.addEventListener('dragstart', event => {
        if (busy || !scope || !binding || local.dir === null || remote.dir === null) return event.preventDefault();
        drag = { panel, file, name: display, version: panel.version, scope, binding };
        event.dataTransfer.setData('application/x-sshash-file', 'file');
        event.dataTransfer.effectAllowed = 'copy';
        row.classList.add('file-dragging');
      });
      row.addEventListener('dragend', () => {
        drag = undefined;
        row.classList.remove('file-dragging');
        clearDrop();
      });
      const verb = panel.isLocal ? 'Отправить на сервер' : 'Скачать в локальную папку';
      actions.append(button(panel.isLocal ? '→' : '←', () => transfer(panel, file, display), 'file-icon file-copy', verb + ' · ' + display));
    }
    row.append(name);
    if (!panel.isLocal) row.append(el('td', entry.kind === 'file' ? formatSize.format(entry.bytes) + ' Б' : '—', 'file-size'));
    row.append(actions);
    return row;
  }

  function clearDrop() {
    for (const panel of [local, remote]) panel.root.classList.remove('drop-target');
  }
  for (const panel of [local, remote]) {
    const accepts = event => drag && drag.panel !== panel && drag.scope === scope && drag.binding === binding &&
      drag.version === drag.panel.version && panel.dir !== null && !busy &&
      event.dataTransfer.types.includes('application/x-sshash-file');
    panel.root.addEventListener('dragover', event => {
      if (!accepts(event)) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'copy';
      panel.root.classList.add('drop-target');
    });
    panel.root.addEventListener('dragleave', event => {
      if (!panel.root.contains(event.relatedTarget)) panel.root.classList.remove('drop-target');
    });
    panel.root.addEventListener('drop', event => {
      event.preventDefault();
      clearDrop();
      if (!accepts(event)) return;
      const source = drag;
      drag = undefined;
      void transfer(source.panel, source.file, source.name);
    });
  }

  async function transfer(source, file, name) {
    if (busy) return;
    if (!scope || !binding || local.dir === null || remote.dir === null) {
      transferStatus.textContent = 'Откройте локальную папку и каталог сервера.';
      return;
    }
    const uploading = source.isLocal;
    const destination = uploading ? remote : local;
    const version = destination.version;
    const { id, generation } = binding;
    busy = true;
    transferStatus.classList.remove('error');
    transferStatus.textContent = 'Передача · ' + name;
    try {
      await api.transferFile(uploading ? 'upload' : 'download', id, generation, scope,
        uploading ? file : local.dir, uploading ? remote.dir : file);
      transferStatus.textContent = (uploading ? 'Отправлено · ' : 'Скачано · ') + name;
      if (destination.version === version) await load(destination, destination.dir);
    } catch (error) {
      transferStatus.classList.add('error');
      transferStatus.textContent = message(error);
    } finally {
      busy = false;
    }
  }

  $('local-choose').onclick = button('Выбрать папку', async () => {
    const chosen = await api.chooseLocal();
    if (!chosen) return;
    scope = chosen;
    show(local, true);
    await load(local, '');
  }).onclick;
  $('local-up').onclick = () => {
    if (local.dir) load(local, local.dir.split('/').slice(0, -1).join('/'));
  };
  $('local-refresh').onclick = () => load(local, local.dir ?? '');
  $('file-path-form').onsubmit = event => { event.preventDefault(); if (binding) load(remote, remote.input.value); };
  $('file-up').onclick = () => { if (remote.dir) load(remote, join(remote.dir, '..')); };
  $('file-refresh').onclick = () => { if (binding) load(remote, remote.dir ?? remote.input.value); };
  select.onchange = () => {
    binding = options.find(s => s.generation === select.value);
    show(remote, Boolean(binding));
    remote.input.value = '.';
    if (!busy) {
      transferStatus.classList.remove('error');
      transferStatus.textContent = hint;
    }
    if (binding) load(remote, '.');
  };

  let optionsKey;
  return sessions => {
    options = sessions.filter(s => s.state === 'ready');
    if (binding && !options.some(s => s.generation === binding.generation)) {
      binding = undefined;
      show(remote, false);
    }
    const key = options.map(s => s.generation).join(',');
    if (key === optionsKey) return;
    optionsKey = key;
    const placeholder = el('option', options.length ? 'Выбрать SSH-сеанс…' : 'Нет подключённых сеансов');
    placeholder.value = '';
    select.replaceChildren(placeholder, ...options.map(session => {
      const option = el('option', session.host.label + ' · ' + endpoint(session.host) + ' · ' + session.id.slice(0, 8));
      option.value = session.generation;
      return option;
    }));
    select.value = binding?.generation ?? '';
  };
}
