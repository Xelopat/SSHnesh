import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import { setupFiles } from './files.js';
import './app.css';
import { keyWorkspace } from './key-workspace.js';
import { serverWorkspace } from './server-workspace.js';

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
let accountReturn = 0;
let activeKey, activeSequence = 0;
const panes = new Map();
const groupsClosed = new Set();
const idPart = id => id.slice(0, 8);
const endpoint = host => (host.username ? host.username + '@' : '') +
  (host.host.includes(':') ? '[' + host.host + ']' : host.host) + ':' + host.port;
const accountName = item => item.label + ' · ' + item.username +
  (item.sudo || item.username.toLowerCase() === 'root' ? ' · sudo/root' : '');
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
let workspace;
let renderedHosts;
function renderHosts() {
  if(api.prototypeMode) {
    workspace ??= serverWorkspace({api,el,button,edit,connectHost,groupsClosed});
    workspace(state);
    return;
  }
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
      actions.append(button('Подключить', () => chooseAccount(host), 'primary', 'Подключить · ' + host.label));
      if (!host.cloud || host.localProfile) actions.append(button('Настроить', () => edit(host), 'server-edit', 'Настроить ' + host.label));
      row.append(el('strong',host.label,'server-name'),address,actions);
      list.append(row);
    }
    details.append(list);
    entries.push(details);
  }
  $('hosts').replaceChildren(...(entries.length ? entries : [el('p', filter ? 'Серверы не найдены' : 'Добавьте первый сервер.', 'muted')]));
}

let connectingHost;
async function connectHost(host, accountId, filesOnly=false) {
  if(api.prototypeMode && !host.cloud && !accountId && host.auth==='password' && !host.hasPassword && !await api.setPassword(host.id)) return;
  const protectedKey = (!accountId && (host.keyProtected || (host.auth==='key' && state.keys.some(k=>k.id===host.keyId && k.protected)))) || (accountId?.startsWith('cloud-key:') &&
    state.keys.some(key => key.id === accountId.slice(10) && key.protected));
  const loginKey=host.logins?.find(l=>'login:'+l.loginId===accountId)?.keyId;
  const phrase = (protectedKey || state.keys.some(k=>k.id===loginKey && k.protected)) ? await api.requestKeyPassphrase() : undefined;
  if ((protectedKey || state.keys.some(k=>k.id===loginKey && k.protected)) && phrase === undefined) return;
  if(filesOnly)return api.openSftp(host.id,accountId,phrase);
  const id = await api.connect(host.id, accountId, phrase);
  if (id) { selected = id; view = 'terminal'; render(); }
}
async function chooseAccount(host) {

  if (api.prototypeMode) {
    const profile = await api.serverAccounts(host.id);
    const downloaded = api.mobileAccount && !host.cloud ? state.keys.filter(key => key.cloud) : [];
    if (host.cloud && !profile.debug && !profile.admin) return connectHost(host);
    if (profile.debug || profile.admin || downloaded.length) {
      connectingHost = host;
      $('connect-account').replaceChildren(
        ...(profile.debug ? [new Option(profile.debug.user + ' · диагностика', 'debug')] : []),
        ...(profile.admin ? [new Option(profile.admin.user + ' · администрирование', 'admin')] : []),
        ...(host.cloud || host.hasPassword ? [new Option(host.username + ' · сохранённый вход', '')] : []),
        ...downloaded.map(key => new Option(key.name, 'cloud-key:' + key.id)));
      $('connect-title').textContent = 'Подключение · ' + host.label;
      $('connect-dialog').showModal();
      return;
    }
  }
  if (!state.accounts.length && host.username) return connectHost(host);
  if (!state.accounts.length) {
    homeSection = 'accounts';
    renderHome();
    return edit(undefined, true);
  }
  connectingHost = host;
  const choices = state.accounts.map(item => new Option(accountName(item), item.id));
  if (host.username) choices.unshift(new Option(host.username + ' · сохранённый вход', ''));
  const select = $('connect-account');
  select.replaceChildren(...choices);
  select.selectedIndex = Math.max(0, choices.findIndex(option => option.value === (host.accountId ?? '')));
  $('connect-title').textContent = 'Подключение · ' + host.label;
  $('connect-dialog').showModal();
}
$('cancel-connect').onclick = () => $('connect-dialog').close();
$('connect-form').onsubmit = safe(async event => {
  event.preventDefault();
  const accountId = $('connect-account').value || undefined;
  $('connect-dialog').close();
  await connectHost(connectingHost, accountId);
});

const drawKeyWorkspace = keyWorkspace({ api, el, button, notify });
function renderKeys() {
  if (api.prototypeMode) return drawKeyWorkspace(state);
  const nodes = state.keys.map(key => {
    const row = el('div', undefined, 'key-row');
    const details = el('div', undefined, 'key-details');
    details.append(el('strong', key.name), el('p', key.type + (key.protected ? key.unlocked ? ' · разблокирован' : ' · защищён фразой' : ''), 'muted'));
    row.append(details, button('Копировать публичный', async () => {
      await api.copyPublicKey(key.id);
      notify('Публичный ключ скопирован.');
    }));
    if (!key.cloud) row.append(button('Удалить', async () => {
      if (confirm('Удалить ключ из хранилища SSHnesh?')) await api.removeKey(key.id);
    }, 'danger'));
    return row;
  });
  $('keys-cloud-open').hidden = !api.mobileAccount;
  $('key-list').replaceChildren(...(nodes.length ? nodes : [el('p', api.mobileAccount
    ? 'Скачайте ключи из аккаунта или откройте сохранённую копию.' : 'Создайте SSH-ключ или импортируйте существующий.', 'muted')]));
}
$('keys-cloud-open').onclick = () => { homeSection = 'sync'; renderHome(); };

$('generate-key').onclick = () => {
  $('key-form').reset();
  $('key-comment-label').hidden = !api.prototypeMode;
  if (api.prototypeMode) $('key-create-hint').textContent = 'Приватный ключ Ed25519 будет сохранён в зашифрованном хранилище SSHnesh.';
  $('key-error').hidden = true;
  $('key-dialog').showModal();
};
$('cancel-key').onclick = () => $('key-dialog').close();
$('key-dialog').oncancel = event => {
  if ($('save-key').disabled) event.preventDefault();
};
$('key-form').onsubmit = async event => {
  event.preventDefault();
  const controls = ['key-name', 'cancel-key', 'save-key'].map($);
  if ($('save-key').disabled) return;
  const name = $('key-name').value;
  const error = $('key-error');
  error.hidden = true;
  for (const control of controls) control.disabled = true;
  try {
    await api.generateKey(name, $('key-comment').value);
    $('key-dialog').close();
    notify('SSH-ключ создан. Скопируйте публичный ключ, чтобы добавить его на сервер.');
  } catch (failure) {
    error.textContent = failure.message.replace(/^Error invoking remote method '[^']+': Error: /, '');
    error.hidden = false;
  } finally {
    for (const control of controls) control.disabled = false;
  }
};

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
  if (homeSection === 'accounts' && state) {
    $('account-list').replaceChildren(...(state.accounts.length ? state.accounts.map(item => {
      const row = el('div', undefined, 'key-row');
      row.append(el('strong', accountName(item), 'key-details'), button('Настроить', () => edit(item, true)));
      return row;
    }) : [el('p', 'Сохраните учётку, чтобы выбирать её при подключении к серверам.', 'muted')]));
  }
  if (homeSection === 'sync' && state) renderSync();
  if (homeSection === 'settings' && state?.terminalSettings) renderTerminalSettings();
}

function renderSync() {
  const { username, busy, canCancel, error, cached, unlocked } = state.sync;
  $('sync-account').textContent = error || (username ? (api.prototypeMode ? username : 'Аккаунт · ' + username) : busy
    ? api.mobileAccount && !canCancel ? 'Обрабатываем запрос…' : 'Завершите вход в браузере.'
    : 'Войдите в аккаунт xelopat.ru.');
  $('sync-login').hidden = Boolean(username);
  $('sync-logout').hidden = !username;
  $('sync-form').hidden = !username && !(api.mobileAccount && cached && !unlocked);
  if (api.mobileAccount) {
    $('sync-form').querySelector('[value=pull]').hidden = !username;
    $('sync-form').querySelector('[value=push]').hidden = !username;
    $('cloud-unlock').hidden = !cached || unlocked;
    $('cloud-lock').hidden = !unlocked;
  }
  for (const control of $('home-sync').querySelectorAll('button, input')) control.disabled = busy;
  $('sync-cancel').hidden = !canCancel;
  $('sync-cancel').disabled = !canCancel;
  api.renderAccount?.(state);
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
$('sync-cancel').onclick = () => syncAction(api.syncCancel, 'Вход отменён.');
$('sync-logout').onclick = () => syncAction(api.syncLogout, 'Вы вышли из синхронизации.');
$('cloud-lock').onclick = () => syncAction(api.cloudLock, 'Хранилище заблокировано.');
$('sync-form').onsubmit = event => {
  event.preventDefault();
  const direction = event.submitter?.value ?? 'pull';
  const input = $('sync-password');
  const password = input.value;
  input.value = '';
  return syncAction(() => api.syncTransfer(direction, password),
    api.mobileAccount ? 'Серверы и ключи доступны в приложении.' :
      direction === 'pull' ? 'Локальные и облачные данные объединены.' : 'Хранилище сохранено на сервере.');
};

let renderedTerminalSettings;
function renderTerminalSettings() {
  const signature = JSON.stringify(state.terminalSettings);
  if (signature === renderedTerminalSettings) return;
  renderedTerminalSettings = signature;
  const fields = $('terminal-settings').elements;
  fields.fontSize.value = state.terminalSettings.fontSize;
  fields.scrollback.value = state.terminalSettings.scrollback;
  fields.cursorBlink.checked = state.terminalSettings.cursorBlink;
}
$('terminal-settings').onsubmit = safe(async event => {
  event.preventDefault();
  const fields = event.currentTarget.elements;
  await api.terminalSettings({fontSize: Number(fields.fontSize.value),
    scrollback: Number(fields.scrollback.value), cursorBlink: fields.cursorBlink.checked});
  notify('Настройки сохранены.');
});

let editingAccount = false;
function authFields() {
  const useAccount = !editingAccount && $('host-account').value !== 'legacy';
  const auth = $('host-auth').value;
  const key = $('host-key-select');
  const password = !useAccount && auth === 'password';
  const host = editing && (editingAccount ? state.accounts : state.hosts).find(host => host.id === editing.id);
  const fields = $('host-form').elements;
  const stored = host?.hasPassword && (editingAccount || (host.host === fields.host.value.trim().toLowerCase() &&
    host.port === Number(fields.port.value))) && host.username === fields.username.value.trim();
  for (const field of ['host-user-field', 'host-auth-field', 'sudo-field']) $(field).hidden = useAccount;
  fields.username.disabled = fields.auth.disabled = useAccount;
  $('host-key-field').hidden = useAccount || auth !== 'key';
  key.disabled = useAccount || auth !== 'key';
  key.required = !key.disabled;
  $('save-password').hidden = !password || !stored;
  $('save-host').textContent = password && !stored ? 'Сохранить и ввести пароль…' : 'Сохранить';
  $('forget-password').hidden = !password || !stored;
  $('host-auth-info').textContent = useAccount ? '' : password
    ? stored ? (api.prototypeMode ? 'Пароль доступен до закрытия прототипа.' : 'Пароль сохранён в защищённом хранилище.')
      : 'Введите пароль в отдельном окне после сохранения настроек.'
    : auth === 'key' ? 'Добавляйте приватные ключи в разделе «Ключи».' : 'Используются ключи из системного SSH-агента.';
}
$('host-auth').onchange = authFields;
$('host-account').onchange = authFields;
for (const name of ['host', 'port', 'username']) $('host-form').elements[name].addEventListener('input', authFields);
$('forget-password').onclick = safe(async () => {
  if (editing) await (editingAccount ? api.clearAccountPassword : api.clearPassword)(editing.id);
  authFields();
});

function edit(host, isAccount = false) {
  editing = host;
  editingAccount = isAccount;
  const form = $('host-form');
  form.reset();
  $('host-title').textContent = isAccount ? host ? 'Настроить учётку' : 'Добавить учётку' : host ? 'Настроить сервер' : 'Добавить сервер';
  $('form-error').textContent = '';
  $('delete-host').hidden = !host;
  $('delete-host').textContent = isAccount ? 'Удалить учётку' : 'Удалить сервер';
  $('migrate-account').hidden = isAccount || !host?.username;
  $('host-group-field').hidden = $('host-address-fields').hidden = isAccount;
  for (const field of ['group', 'host', 'port']) form.elements[field].disabled = isAccount;
  if (host) for (const key of ['label', 'group', 'host', 'port', 'username', 'auth'])
    if (host[key] !== undefined) form.elements[key].value = host[key];
  $('account-sudo').checked = Boolean(host?.sudo);
  const accountSelect = $('host-account');
  $('host-account-field').hidden = isAccount;
  accountSelect.disabled = isAccount;
  accountSelect.replaceChildren(new Option('Выбирать при подключении', ''), new Option('Вход только для этого сервера', 'legacy'),
    ...(!isAccount ? state.accounts.map(item => new Option(accountName(item), item.id)) : []));
  if (host?.accountId && !state.accounts.some(item => item.id === host.accountId))
    accountSelect.append(new Option('Удалённая учётка', host.accountId));
  accountSelect.value = isAccount ? '' : host?.accountId ?? (host?.username || api.prototypeMode ? 'legacy' : '');
  if (api.prototypeMode && !host) form.elements.auth.value = 'password';
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
if(api.prototypeMode) {
  const groupEditor=(group, members)=>{
    const dialog=document.createElement('dialog');
    dialog.innerHTML='<form><h2></h2><label>Название группы<input name="group" required maxlength="48"></label><fieldset><legend>Серверы</legend></fieldset><p role="alert" class="error"></p><div class="actions"><button type="button">Отмена</button><button class="primary">Сохранить</button></div></form>';
    const form=dialog.querySelector('form');
    form.querySelector('h2').textContent=group?'Состав группы':'Создать группу';
    form.elements.group.value=group || '';
    form.elements.group.readOnly=!!group;
    for(const h of state.hosts){
      const label=el('label',undefined,'check-field'),box=el('input');box.type='checkbox';box.value=h.id;
      box.checked=members?.includes(h.id) || false;label.append(box,h.label);form.querySelector('fieldset').append(label);
    }
    form.querySelector('button').onclick=()=>dialog.close();
    form.onsubmit=async e=>{
      e.preventDefault();
      const label=form.elements.group.value.trim();
      try{
        if(!group && ([...(state.groups || []).map(g=>g.label),...state.hosts.map(h=>h.group)].includes(label)))throw Error('Такая группа уже есть.');
        await api.saveGroup({label,members:[...form.querySelectorAll('input:checked')].map(b=>b.value)});
        groupsClosed.delete(label);dialog.close();
      }catch(err){form.querySelector('[role=alert]').textContent=err.message;}
    };
    dialog.onclose=()=>dialog.remove();document.body.append(dialog);dialog.showModal();
  };
  api.editGroup=groupEditor;
  const groupButton=button('Создать группу',()=>groupEditor());
  const tools=el('div',undefined,'actions');
  $('add').before(tools);
  tools.append(groupButton,$('add'));
}
$('add-account').onclick = safe(() => edit(undefined, true));
$('migrate-account').onclick = safe(async () => {
  await api.migrateAccount(editing.id);
  $('host-dialog').close();
  notify('Вход перенесён в раздел «Учётки».');
});
$('delete-host').onclick = safe(async () => {
  if (!confirm('Удалить «' + editing.label + '»?')) return;
  await (editingAccount ? api.deleteAccount : api.deleteHost)(editing.id);
  $('host-dialog').close();
});
$('host-form').onsubmit = async event => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  const submit = event.submitter;
  for (const button of form.querySelectorAll('button')) button.disabled = true;
  try {
    if (editingAccount || values.accountId === 'legacy') values.sudo = $('account-sudo').checked;
    if (!values.accountId || values.accountId === 'legacy') delete values.accountId;
    if (!editingAccount) values.port = Number(values.port);
    const id = await (editingAccount ? api.saveAccount : api.save)({ ...values, id: editing?.id });
    editing = { id };
    const needsPassword = values.auth === 'password' &&
      !(await api.state())[editingAccount ? 'accounts' : 'hosts'].find(host => host.id === id)?.hasPassword;
    if ((needsPassword || submit?.id === 'save-password') &&
        !await (editingAccount ? api.setAccountPassword : api.setPassword)(id)) {
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
    fontFamily: "'Cascadia Mono', Consolas, monospace", fontSize: state?.terminalSettings?.fontSize ?? 14, lineHeight: 1.16,
    cursorBlink: state?.terminalSettings?.cursorBlink ?? true, scrollback: state?.terminalSettings?.scrollback ?? 3000, allowProposedApi: true, windowOptions: {},
    theme: { background: '#090d13', foreground: '#dde6f0', cursor: '#46dfc0', selectionBackground: '#265353' },
  });
  const fit = new FitAddon();
  term.loadAddon(fit);
  term.loadAddon(new Unicode11Addon());
  term.unicode.activeVersion = '11';
  const node = el('div', undefined, 'term-pane');
  node.hidden = true;
  $('terminal').prepend(node);
  const terminalView = api.mobileLineInput ? el('div', undefined, 'preview-terminal-view') : node;
  if (api.mobileLineInput) node.append(terminalView);
  term.open(terminalView);
  term.onData(text => { if (!api.mobileLineInput) api.input(id, generation, text); });
  if (api.mobileLineInput) {
    const form = el('form', undefined, 'preview-line');
    const field = document.createElement('input');
    field.setAttribute('aria-label', 'Строка терминала');
    field.placeholder = 'Строка терминала';
    field.autocomplete = 'off';
    field.autocapitalize = 'off';
    field.spellcheck = false;
    const send = el('button', '↵', 'primary');
    send.setAttribute('aria-label', 'Отправить строку');
    form.append(field, send);
    form.onsubmit = event => {
      event.preventDefault();
      api.input(id, generation, field.value + '\r');
      field.value = '';
    };
    node.append(form);
  }
  term.onResize(({ cols, rows }) => api.resize(id, generation, cols, rows));
  terminalView.addEventListener('keydown', event => {
    if (!event.ctrlKey || event.altKey || event.metaKey || event.isComposing) return;
    if (event.code !== 'KeyC' && event.key.toLowerCase() !== 'c') return;
    const selection = term.getSelection();
    if (!event.shiftKey && !selection) return;
    event.preventDefault();
    event.stopPropagation();
    if (selection && !event.repeat) safe(() => api.copy(selection))();
  }, true);
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
  const tabs = state.sessions.filter(s=>!s.fileOnly).map(s => {
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
    if (!api.prototypeMode) controls.push(share);
    controls.push(button('Отключить', () => api.disconnect(id)));
  } else if (status === 'error' || status === 'closed') controls.push(button('Подключить снова', async () => {
    const phrase = current.keyProtected ? await api.requestKeyPassphrase() : undefined;
    if (current.keyProtected && phrase === undefined) return;
    return api.reconnect(id, phrase);
  }));
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
  if (api.prototypeMode) {
    const enabled = state.activeContextEnabled;
    const startup = $('native-mcp-startup');
    if (startup) startup.checked = state.mcp.enabled;
    const toggle = $('allow-active-context');
    if (toggle) {
      toggle.checked = enabled;
      toggle.disabled = !state.mcp.enabled;
    }
    $('foot-mcp').textContent = !state.mcp.enabled ? 'MCP · Выключен' :
      enabled ? 'MCP · Текущий сервер доступен' : 'MCP · Только по имени сервера';
    return;
  }
  const { enabled, approvalMode, shared, pending, history } = state.mcp;
  $('mcp-chat-approval').checked = state.mcp.chatApproval;
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
    if (state.mcp.privileged)
      card.insertBefore(el('span', 'Доступ sudo/root разрешён для этого подключения.', 'warn'), card.lastChild);
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

function syncActiveContext() {
  if (!state || !api.selectActive || api.mobileLineInput) return;
  const session = view === 'terminal' ? selectedSession() : view === 'files'
    ? state.sessions.find(s => s.generation === $('file-session').value) : undefined;
  const key = session?.generation ?? '';
  if (activeKey === key) return;
  activeKey = key;
  const sequence = ++activeSequence;
  api.selectActive(sequence, session ? [session.id, session.generation] : null).catch(error => {
    if (sequence === activeSequence) {
      activeKey = undefined;
      notify(error.message);
    }
  });
}
$('file-session').addEventListener('change', syncActiveContext);
$('mcp-chat-approval').onchange = safe(async event => {
  try { await api.setChatApproval(event.currentTarget.checked); }
  finally { $('mcp-chat-approval').checked = state.mcp.chatApproval; }
});

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
  if (api.prototypeMode) return notify('Команда скопирована. Вставьте её в PowerShell или терминал и откройте новый чат Codex.');
  notify('Конфигурация с ключом сопряжения скопирована. Вставьте её в настройки локального MCP-клиента.' +
    (state.persistent ? '' : ' После перезапуска потребуется скопировать снова.'));
});
$('search').oninput = () => { if (state) renderHosts(); };
function render() {
  if (!state) return;
  if (api.mobileAccount && state.sync.callback && state.sync.callback !== accountReturn) {
    accountReturn = state.sync.callback;
    view = 'home';
    homeSection = 'sync';
  }
  if (!selectedSession()) selected = state.sessions.filter(s=>!s.fileOnly).at(-1)?.id;
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
  if (state.terminalSettings) {
    for (const pane of panes.values()) {
      for (const [name, value] of Object.entries(state.terminalSettings)) {
        if (pane.term.options[name] !== value) pane.term.options[name] = value;
      }
    }
    fitSelected();
  }
  renderMcp();
  renderFiles(state.sessions,state.hosts,view==='files',workspace?.selection(),connectHost,state.keys,state.sync?.unlocked===false);
  syncActiveContext();
}
api.onState(next => { state = next; render(); });
api.onData((id, generation, bytes) => {
  const s = state?.sessions.find(item => item.id === id);
  if (s?.generation === generation) pane(id, generation).term.write(bytes);
});
safe(async () => { state = await api.state(); render(); })();
