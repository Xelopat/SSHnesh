export function keyWorkspace({ api, el, button, notify }) {
  const panel = document.getElementById('key-list');
  const search = el('input');
  search.type = 'search';
  search.placeholder = 'Найти ключ';
  search.setAttribute('aria-label', search.placeholder);
  const list = el('div', undefined, 'key-options');
  const sidebar = el('div', undefined, 'key-sidebar');
  const card = el('section', undefined, 'key-card');
  sidebar.append(search, list);
  let selected, current, signature;

  function render() {
    const { keys, hosts, sync } = current;
    const locked = sync.cached && !sync.unlocked;
    for (const id of ['keys-local-hint','keys-cloud-hint','keys-cloud-open']) document.getElementById(id).hidden = true;
    for (const id of ['generate-key','import-key']) document.getElementById(id).hidden = locked;
    panel.classList.add('key-workspace');
    if (locked || !keys.length) {
      selected = undefined;
      search.value = '';
      panel.classList.remove('show-card');
      const empty = el('div', undefined, 'key-empty');
      empty.append(el('h2', locked ? 'Хранилище закрыто' : 'Пока нет ключей'));
      if (locked) empty.append(button('Открыть хранилище', () => api.unlockKeys(), 'primary'));
      else empty.append(el('p', 'Создайте первый ключ или импортируйте существующий.', 'muted'));
      panel.replaceChildren(empty);
      return;
    }
    const matches = keys.filter(k => k.name.toLocaleLowerCase().includes(search.value.trim().toLocaleLowerCase()));
    const key = matches.find(k => k.id === selected) || matches[0];
    if (selected !== key?.id) panel.classList.remove('show-card');
    selected = key?.id;
    const usage = new Map();
    for (const host of hosts) {
      for (const login of [host, ...(host.logins || [])]) {
        if (login.auth !== 'key' || !login.keyId) continue;
        if (!usage.has(login.keyId)) usage.set(login.keyId, []);
        usage.get(login.keyId).push({ host, login });
      }
    }
    if (sidebar.parentNode !== panel) panel.replaceChildren(sidebar, card);
    list.replaceChildren(...matches.map(k => {
      const row = button('', () => {
        selected = k.id;
        render();
        panel.classList.add('show-card');
      }, 'key-choice');
      row.setAttribute('aria-pressed', String(k.id === selected));
      row.append(el('strong', k.name), el('small', k.type + ' · Входов: ' + (usage.get(k.id)?.length || 0)));
      return row;
    }));
    card.replaceChildren();
    if (!key) {
      list.append(el('p', 'Ключи не найдены', 'muted'));
      return;
    }
    const links = usage.get(key.id) || [];
    const back = button('← Все ключи', () => panel.classList.remove('show-card'), 'key-back');
    const heading = el('header');
    const menu = el('details', undefined, 'key-menu');
    const toggle = el('summary', '•••');
    toggle.setAttribute('aria-label','Действия с ключом');
    menu.append(toggle, button('Удалить ключ', async () => {
      menu.open = false;
      if (links.length) {
        notify('Сначала измените способ входа для связанных учёток ниже.');
        return;
      }
      await api.removeKey(key);
    }, 'danger'));
    heading.append(el('h2', key.name), menu);
    card.append(back, heading, el('p', key.type + (key.protected ? ' · защищён парольной фразой' : ''), 'muted'), el('h3','Входы с этим ключом'));
    const comment = el('input');
    comment.maxLength = 256;
    comment.value = key.comment || '';
    const label = el('label','Комментарий');
    label.append(comment);
    const saveComment = button('Сохранить комментарий', async () => {
      await api.saveKeyComment(key.id, comment.value);
      notify('Комментарий сохранён.');
    });
    saveComment.hidden = true;
    comment.oninput = () => { saveComment.hidden = comment.value === (key.comment || ''); };
    card.lastChild.before(label, saveComment);
    for (const { host, login } of links) {
      card.append(button(host.label + ' · ' + login.username, () => api.editVaultLogin(host, login === host ? undefined : login), 'key-login'));
    }
    if (!links.length) card.append(el('p','Ключ пока не выбран ни для одного входа.', 'muted'));
    card.append(el('h3','Отпечаток SHA256'), el('code', key.fingerprint, 'key-fingerprint'),
      button('Экспорт приватного ключа…', () => api.exportKey(key)),
      button('Скопировать публичный ключ', async () => {
        await api.copyPublicKey(key.id);
        notify('Публичный ключ скопирован.');
      }));
  }
  search.oninput = render;
  return state => {
    current = state;
    const next = JSON.stringify([state.keys, state.hosts, state.sync.cached, state.sync.unlocked]);
    if (next === signature) return;
    signature = next;
    render();
  };
}
