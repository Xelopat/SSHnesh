import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import { setupFiles } from './files.js';
import './app.css';

const api = window.sshash;
const $ = id => document.getElementById(id);
const stateText = { ready: 'Подключено', connecting: 'Подключение', 'host-key': 'Проверка ключа', closed: 'Отключено', error: 'Ошибка' };
const stateTone = { ready: 'good', connecting: 'wait', 'host-key': 'wait', error: 'bad' };
const actionText = {
  sent: 'Отправлено в PTY', released: 'Вывод передан', cancelled: 'Отменено', denied: 'Отклонено',
  expired: 'Срок истёк', revoked: 'Доступ отозван', uncertain: 'Результат неизвестен', busy: 'Канал занят',
};
let state, selected, editing, noticeTimer, view = 'home', mcpOpen = false;
let homeSection = 'servers';
const panes = new Map();
const groupsClosed = new Set();
const idPart = id => id.slice(0, 8);
const endpoint = host => host.username + '@' + (host.host.includes(':') ? '[' + host.host + ']' : host.host) + ':' + host.port;
const selectedSession = () => state?.sessions.find(s => s.id === selected);
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function notify(text) {
  const notice = $('notice');
  notice.textContent = text;
  notice.hidden = false;
  clearTimeout(noticeTimer);
  noticeTimer = setTimeout(() => { notice.hidden = true; }, 5000);
}
function safe(fn) {
  return async (...args) => {
    try { return await fn(...args); }
    catch (error) { notify(error.message.replace(/^Error invoking remote method '[^']+': Error: /, '')); }
  };
}
function button(label, fn, className, title) {
  const node = el('button', label, className);
  node.type = 'button';
  node.onclick = safe(fn);
  if (title) {
    node.title = title;
    node.setAttribute('aria-label', title);
  }
  return node;
}
const renderFiles = setupFiles({ api, $, el, button, endpoint });
let renderedHosts;
function renderHosts() {
  const filter = $('search').value.trim().toLowerCase();
  const selectedHost = selectedSession()?.host.id;
  const matches = state.hosts.filter(host =>
    [host.label, host.group, endpoint(host)].some(value => value.toLowerCase().includes(filter)));
  const signature = JSON.stringify([filter, selectedHost, matches]);
  if (signature === renderedHosts) return;
  renderedHosts = signature;
  const groups = Map.groupBy(matches, host => host.group);
  const entries = [];
  for (const [group, hosts] of groups) {
    const details = el('details');
    details.className = 'server-group';
    details.open = Boolean(filter) || !groupsClosed.has(group);
    details.ontoggle = () => {
      if (filter) return;
      if (details.open) groupsClosed.delete(group);
      else groupsClosed.add(group);
    };
    const heading = el('summary');
    heading.append(el('span', group), el('span', String(hosts.length), 'server-count'));
    details.append(heading);
    const list = el('ul', undefined, 'server-list');
    for (const host of hosts) {
      const row = el('li', undefined, 'server-row' + (selectedHost === host.id ? ' selected' : ''));
      const address = el('span', endpoint(host), 'server-address');
      const actions = el('div', undefined, 'server-actions');
      actions.append(button('Подключить', async () => {
        const id = await api.connect(host.id);
        if (id) { selected = id; view = 'terminal'; render(); }
      }, 'primary', 'Подключить · ' + host.label),
      button('Настроить', () => edit(host), 'server-edit', 'Настроить ' + host.label));
      row.append(el('strong', host.label, 'server-name'), address, actions);
      list.append(row);
    }
    details.append(list);
    entries.push(details);
  }
  $('hosts').replaceChildren(...(entries.length ? entries : [el('p', filter ? 'Серверы не найдены' : 'Добавьте первый сервер.', 'muted')]));
}

function renderKeys() {
  const nodes = state.keys.map(key => {
    const row = el('div', undefined, 'key-row');
    const details = el('div', undefined, 'key-details');
    details.append(el('strong', key.name), el('p', key.type + (key.protected ? key.unlocked ? ' · разблокирован' : ' · защищён фразой' : ''), 'muted'));
    row.append(details, button('Копировать публичный', async () => {
      await api.copyPublicKey(key.id);
      notify('Публичный ключ скопирован.');
    }), button('Удалить', async () => {
      if (confirm('Удалить ключ из хранилища SSHnesh?')) await api.removeKey(key.id);
    }, 'danger'));
    return row;
  });
  $('key-list').replaceChildren(...(nodes.length ? nodes : [el('p', 'Импортируйте файл приватного SSH-ключа.', 'muted')]));
}

$('import-key').onclick = safe(async () => {
  $('import-key').disabled = true;
  try { await api.importKey(); }
  finally { $('import-key').disabled = false; }
});
const homeButtons = [...$('home-nav').querySelectorAll('button')];
for (const node of homeButtons) node.onclick = () => {
  homeSection = node.dataset.section;
  renderHome();
};
function renderHome() {
  for (const node of homeButtons) {
    const active = node.dataset.section === homeSection;
    if (active) node.setAttribute('aria-current', 'page');
    else node.removeAttribute('aria-current');
    $(node.getAttribute('aria-controls')).hidden = !active;
  }
  if (homeSection === 'keys' && state) renderKeys();
  if (homeSection === 'sync' && state) renderSync();
}

function renderSync() {
  const { username, busy } = state.sync;
  $('sync-account').textContent = username ? 'Аккаунт · ' + username : busy ? 'Завершите вход в браузере.' : 'Войдите в аккаунт xelopat.ru.';
  $('sync-login').hidden = Boolean(username);
  $('sync-logout').hidden = !username;
  $('sync-form').hidden = !username;
  for (const control of $('home-sync').querySelectorAll('button, input')) control.disabled = busy;
}

async function syncAction(action, message) {
  const status = $('sync-message');
  status.hidden = true;
  try {
    if (await action() === false) return;
    status.className = 'muted';
    status.textContent = message;
  } catch (error) {
    status.className = 'error';
    status.textContent = error.message.replace(/^Error invoking remote method '[^']+': (?:Error: )?/, '');
  }
  status.hidden = false;
}

$('sync-login').onclick = () => syncAction(api.syncLogin, 'Вход выполнен.');
$('sync-logout').onclick = () => syncAction(api.syncLogout, 'Вы вышли из синхронизации.');
$('sync-form').onsubmit = event => {
  event.preventDefault();
  const direction = event.submitter?.value ?? 'pull';
  const input = $('sync-password');
  const password = input.value;
  input.value = '';
  return syncAction(() => api.syncTransfer(direction, password),
    direction === 'pull' ? 'Локальные и облачные данные объединены.' : 'Хранилище сохранено на сервере.');
};

function authFields() {
  const auth = $('host-auth').value;
  const key = $('host-key-select');
  const password = auth === 'password';
  const host = editing && state.hosts.find(host => host.id === editing.id);
  const fields = $('host-form').elements;
  const stored = host?.hasPassword && host.host === fields.host.value.trim().toLowerCase() &&
    host.port === Number(fields.port.value) && host.username === fields.username.value.trim();
  $('host-key-field').hidden = auth !== 'key';
  key.disabled = auth !== 'key';
  key.required = auth === 'key';
  $('save-password').hidden = !password || !stored;
  $('save-host').textContent = password && !stored ? 'Сохранить и ввести пароль…' : 'Сохранить';
  $('forget-password').hidden = !password || !stored;
  $('host-auth-info').textContent = password
    ? stored ? 'Пароль сохранён в защищённом хранилище.' : 'Введите пароль в отдельном окне после сохранения настроек.'
    : auth === 'key' ? 'Добавляйте приватные ключи в разделе «Ключи».' : 'Используются ключи из системного SSH-агента.';
}
$('host-auth').onchange = authFields;
for (const name of ['host', 'port', 'username']) $('host-form').elements[name].addEventListener('input', authFields);
$('forget-password').onclick = safe(async () => {
  if (editing) await api.clearPassword(editing.id);
  authFields();
});

function edit(host) {
  editing = host;
  const form = $('host-form');
  form.reset();
  $('host-title').textContent = host ? 'Настроить сервер' : 'Добавить сервер';
  $('form-error').textContent = '';
  $('delete-host').hidden = !host;
  if (host) for (const key of ['label', 'group', 'host', 'port', 'username', 'auth']) form.elements[key].value = host[key];
  const keySelect = $('host-key-select');
  keySelect.replaceChildren(new Option('Выбрать ключ…', ''), ...state.keys.map(key => new Option(key.name + ' · ' + key.type, key.id)));
  if (host?.keyId && !state.keys.some(key => key.id === host.keyId))
    keySelect.append(new Option('Удалённый ключ', host.keyId));
  keySelect.value = host?.keyId ?? '';
  authFields();
  $('groups').replaceChildren(...[...new Set(state.hosts.map(h => h.group))].map(group => el('option', group)));
  $('host-dialog').showModal();
  form.elements.label.focus();
}
$('close-dialog').onclick = () => $('host-dialog').close();
$('add').onclick = safe(() => edit());
$('delete-host').onclick = safe(async () => {
  if (!confirm('Удалить «' + editing.label + '» из списка серверов?')) return;
  await api.deleteHost(editing.id);
  $('host-dialog').close();
});
$('host-form').onsubmit = async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  const submit = event.submitter;
  for (const button of form.querySelectorAll('button')) button.disabled = true;
  try {
    const id = await api.save({ ...values, id: editing?.id, port: Number(values.port) });
    editing = { id };
    const needsPassword = values.auth === 'password' &&
      !(await api.state()).hosts.find(host => host.id === id)?.hasPassword;
    if ((needsPassword || submit?.id === 'save-password') && !await api.setPassword(id)) {
      $('form-error').textContent = 'Настройки сохранены. Ввод пароля отменён.';
      return;
    }
    $('host-dialog').close();
  } catch (error) { $('form-error').textContent = error.message.replace(/^Error invoking remote method '[^']+': Error: /, ''); }
  finally {
    for (const button of form.querySelectorAll('button')) button.disabled = false;
    authFields();
  }
};

function pane(id, generation) {
  const existing = panes.get(id);
  if (existing?.generation === generation) return existing;
  if (existing) { existing.term.dispose(); existing.node.remove(); }
  const term = new Terminal({
    fontFamily: "'Cascadia Mono', Consolas, monospace", fontSize: 14, lineHeight: 1.16,
    cursorBlink: true, scrollback: 3000, allowProposedApi: true, windowOptions: {},
    theme: { background: '#090d13', foreground: '#dde6f0', cursor: '#46dfc0', selectionBackground: '#265353' },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new Unicode11Addon());
  term.unicode.activeVersion = '11';
  const node = el('div', undefined, 'term-pane');
  node.hidden = true;
  $('terminal').prepend(node);
  term.open(node);
  term.onData(text => api.input(id, generation, text));
  term.onResize(({ cols, rows }) => api.resize(id, generation, cols, rows));
  term.attachCustomKeyEventHandler(event => {
    if (event.type !== 'keydown' || !event.ctrlKey || event.altKey) return true;
    if (event.key.toLowerCase() === 'c' && (event.shiftKey || term.hasSelection())) {
      safe(() => api.copy(term.getSelection()))();
      return false;
    }
    return true;
  });
  const created = { node, term, fit, generation };
  panes.set(id, created);
  return created;
}

function fitSelected() {
  const s = selectedSession();
  const active = panes.get(selected);
  if (!s || !active || active.node.hidden) return;
  active.fit.fit();
  api.resize(s.id, s.generation, active.term.cols, active.term.rows);
  $('foot-term').textContent = 'xterm-256color · UTF-8 · ' + active.term.cols + '×' + active.term.rows;
}
new ResizeObserver(fitSelected).observe($('terminal'));

function renderSessions() {
  const current = selectedSession();
  for (const [id, item] of panes) {
    if (!state.sessions.some(s => s.id === id)) {
      item.term.dispose();
      item.node.remove();
      panes.delete(id);
    }
  }
  function fixedTab(label, page) {
    const tab = button(label, () => { view = page; render(); }, 'fixed-tab' + (view === page ? ' active' : ''));
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-selected', String(view === page));
    return tab;
  }
  const tabs = state.sessions.map(s => {
    const active = view === 'terminal' && s.id === selected;
    const row = el('div', undefined, 'tab' + (active ? ' active' : ''));
    const tab = button(s.host.label, () => { view = 'terminal'; selected = s.id; render(); panes.get(s.id)?.term.focus(); }, 'indicator ' + (stateTone[s.state] ?? ''));
    tab.setAttribute('role', 'tab');
    tab.setAttribute('aria-selected', String(active));
    tab.title = endpoint(s.host);
    row.append(tab, button('×', () => api.remove(s.id), undefined, 'Закрыть вкладку ' + s.host.label));
    pane(s.id, s.generation).node.hidden = !active;
    return row;
  });
  $('tabs').replaceChildren(fixedTab('Главная', 'home'), fixedTab('SFTP', 'files'), ...tabs,
    button('+', () => { view = 'home'; homeSection = 'servers'; render(); $('search').focus(); }, 'icon new-tab', 'Выбрать сервер для новой вкладки'));
  const bar = $('sessionbar');
  const message = $('session-message');
  bar.hidden = !current;
  message.hidden = true;
  if (!current) return;
  const { id, generation, host, state: status, trust } = current;
  const shared = state.mcp.shared?.sessionId === id;
  const controls = [el('span', stateText[status], 'indicator ' + (stateTone[status] ?? '')), el('span', endpoint(host), 'ellipsis muted')];
  if (status === 'ready') {
    const share = button(shared ? 'Доступ открыт' : 'Передать MCP', async () => {
      if (state.mcp.shared && !confirm('Заменить переданную сессию на ' + endpoint(host) + '?')) return;
      await api.share(id, generation);
      mcpOpen = true;
      render();
    }, shared ? '' : 'primary');
    share.disabled = shared || !state.mcp.enabled;
    share.title = !state.mcp.enabled ? 'Включите MCP в правой панели' : 'Доступ к конкретному соединению';
    controls.push(share, button('Отключить', () => api.disconnect(id)));
  } else if (status === 'error' || status === 'closed') controls.push(button('Подключить снова', () => api.reconnect(id)));
  else controls.push(button('Прервать', () => api.disconnect(id)));
  bar.replaceChildren(...controls);
  if (trust) {
    const actions = el('div', undefined, 'actions');
    actions.append(button('Отклонить ключ', () => api.verify(id, generation, trust.fingerprint, false)),
      button(trust.known ? 'Заменить проверенный ключ' : 'Доверять ключу',
        () => api.verify(id, generation, trust.fingerprint, true), 'primary'));
    message.replaceChildren(el('h2', trust.known ? 'Ключ сервера изменился' : 'Первое подключение'),
      el('p', 'Сверьте fingerprint с администратором или через консоль сервера. ' + trust.target),
      el('code', trust.algorithm + ' · ' + trust.fingerprint, 'warn'));
    if (trust.known) message.append(el('p', 'Сохранённый ключ · ' + trust.known));
    message.append(actions);
    message.hidden = false;
  } else if (current.error || status === 'closed') {
    message.replaceChildren(el('h2', stateText[status]), el('p', current.error || 'SSH-сеанс завершён. Для нового подключения используйте кнопку вверху.'));
    message.hidden = false;
  }
  $('foot-ssh').textContent = 'SSH · ' + stateText[status] + ' · ' + endpoint(host);
  fitSelected();
}

function renderMcp() {
  const { enabled, approvalMode, shared, pending, history } = state.mcp;
  $('mcp-badge').textContent = pending.length ? ' ' + pending.length : '';
  $('toggle-mcp').classList.toggle('has-requests', pending.length > 0);
  const indicator = $('mcp-status');
  indicator.className = 'indicator ' + (enabled ? 'good' : state.localError ? 'bad' : '');
  indicator.textContent = state.localError ? 'Ошибка канала' : enabled ? 'Включён · клиентов ' + state.clientCount : 'Выключен';
  $('enable').textContent = enabled ? 'Выключить' : 'Включить';
  $('mcp-approval-mode').value = approvalMode;
  $('foot-mcp').textContent = 'MCP · ' + (shared ? '1 сессия передана' : enabled ? 'Включён' : 'Выключен');
  const card = el('div', undefined, 'card');
  if (shared) {
    card.append(el('strong', shared.target), el('span', 'Сессия ' + idPart(shared.sessionId) + ' · соединение ' + idPart(shared.generation), 'muted'),
      button('Отозвать', api.revoke));
  } else {
    card.append(el('p', state.localError || 'Передайте подключённую вкладку из панели терминала.', state.localError ? 'error' : 'muted'));
  }
  $('shared').replaceChildren(card);

  $('pending-count').textContent = pending.length || '';
  const list = $('pending');
  const hadPending = Boolean(list.querySelector('.pending-card'));
  const oldNodes = new Map([...list.children].map(node => [node.dataset.id, node]));
  const nodes = pending.map(request => {
    const { requestId, target, sessionId, generation, expiresAt, text } = request;
    if (oldNodes.has(requestId)) return oldNodes.get(requestId);
    const node = el('article', undefined, 'card pending-card');
    node.dataset.id = requestId;
    const clock = el('span', undefined, 'muted');
    clock.dataset.deadline = expiresAt;
    clock.textContent = 'До ' + new Date(expiresAt).toLocaleTimeString('ru-RU');
    node.append(el('strong', 'Ввод в терминал', 'warn'),
      el('span', target, 'request-target'), el('span', 'Сессия ' + idPart(sessionId) + ' · соединение ' + idPart(generation), 'muted'), clock,
      el('pre', text), el('p', 'Текст и Enter попадут в текущий PTY. Проверьте, что в терминале открыт нужный процесс и строка ввода пуста.', 'muted'));
    const actions = el('div', undefined, 'actions');
    actions.append(button('Отклонить', () => api.decide(requestId, false)),
      button('Отправить в PTY', () => api.decide(requestId, true), 'primary'));
    node.append(actions);
    return node;
  });
  if (!nodes.length) list.replaceChildren(el('p', 'Нет ожидающих запросов', 'muted'));
  else {
    for (const node of [...list.children]) if (!nodes.includes(node)) node.remove();
    for (const node of nodes) if (!node.isConnected) list.append(node);
    if (mcpOpen && !hadPending) $('mcp-content').scrollTop = 0;
  }
  renderHistory($('history'), history);
  renderHistory($('home-history'), history);
}

function renderHistory(historyList, history) {
  const expanded = new Set([...historyList.querySelectorAll('details[open]')].map(node => node.dataset.id));
  historyList.replaceChildren(...(history.length ? history.map(item => {
    const row = el('details', undefined, 'card history');
    row.dataset.id = item.requestId;
    row.open = expanded.has(item.requestId);
    const summary = el('summary');
    const label = actionText[item.status] ?? item.status;
    summary.append(el('span', label + (item.automatic ? ' · авто' : ''), ['sent', 'released'].includes(item.status) ? 'good-text' : 'warn'),
      el('small', new Date(item.at).toLocaleTimeString('ru-RU')));
    row.append(summary, el('p', (item.method === 'send' ? 'Ввод · ' : 'Вывод · ') + item.target, 'muted'),
      el('p', 'Сессия ' + idPart(item.sessionId) + ' · соединение ' + idPart(item.generation), 'muted'),
      el('p', item.requestId, 'muted'));
    if (item.status === 'sent' || item.status === 'uncertain') row.append(el('p', 'Результат выполнения неизвестен.', 'muted'));
    if (item.status === 'released') row.append(el('p', 'Передано символов · ' + item.chars, 'muted'));
    return row;
  }) : [el('p', 'Действий пока нет', 'muted')]));
}
$('enable').onclick = safe(() => api.enable(!state.mcp.enabled));
$('mcp-approval-mode').onchange = safe(async ({ currentTarget: select }) => {
  select.disabled = true;
  try { await api.setApprovalMode(select.value); }
  finally {
    select.value = state.mcp.approvalMode;
    select.disabled = false;
  }
});
$('toggle-mcp').onclick = () => {
  mcpOpen = !mcpOpen;
  render();
  if (mcpOpen && state.mcp.pending.length) $('mcp-content').scrollTop = 0;
};
$('config').onclick = safe(async () => {
  await api.config();
  notify('Конфигурация с ключом сопряжения скопирована. Вставьте её в настройки локального MCP-клиента.' +
    (state.persistent ? '' : ' После перезапуска потребуется скопировать снова.'));
});
$('search').oninput = () => { if (state) renderHosts(); };
function render() {
  if (!state) return;
  if (!selectedSession()) selected = state.sessions.at(-1)?.id;
  if (!selected && view === 'terminal') view = 'home';
  $('home').hidden = view !== 'home';
  $('files').hidden = view !== 'files';
  $('workspace').hidden = view !== 'terminal';
  $('mcp-panel').hidden = !mcpOpen;
  $('toggle-mcp').setAttribute('aria-expanded', String(mcpOpen));
  document.querySelector('main').classList.toggle('mcp-open', mcpOpen);
  if (!selected) $('foot-ssh').textContent = 'SSH · Нет подключения';
  renderHosts();
  renderHome();
  renderSessions();
  renderMcp();
  renderFiles(state.sessions);
}
api.onState(next => { state = next; render(); });
api.onData((id, generation, bytes) => {
  const s = state?.sessions.find(item => item.id === id);
  if (s?.generation === generation) pane(id, generation).term.write(bytes);
});
safe(async () => { state = await api.state(); render(); })();
