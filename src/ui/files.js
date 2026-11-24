export function setupFiles({ api, $, el, button, endpoint }) {
  let scope, binding, drag, busy = false, options = [];
  let locationKey='';
  const readDir=side=>localStorage.getItem('sftp-dir:'+locationKey+':'+side) || (side==='local'?'':'.');
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

  async function load(panel, dir, restoring=false) {
    const savedKey=locationKey;
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
      if(api.prototypeMode && savedKey && savedKey===locationKey) localStorage.setItem('sftp-dir:'+savedKey+':'+panel.side,result.dir);
      if (panel.isLocal) {
        const label=result.label.replace(/^\\\\\?\\UNC\\/,'\\\\').replace(/^\\\\\?\\/,'');
        panel.input.textContent = label;
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
      const fallback=panel.isLocal?'':'.';
      if(restoring && dir!==fallback) return load(panel,fallback);
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
    const before=locationKey;
    const chosen = await api.chooseLocal(...(api.prototypeMode?[before]:[]));
    if(before!==locationKey)return;
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
  if(api.prototypeMode) {
    select.setAttribute('aria-label','Сервер для SFTP');
    let latest, connectedHost, target, role, requested, attempt=0, fileId, previousVisible=false, failed, optionsSignature;
    const empty=$('file-empty');
    const controls=el('div',undefined,'sftp-controls');
    $('remote-pane').querySelector('header').after(controls);
    const loginSelect=el('select');loginSelect.setAttribute('aria-label','Учётная запись SFTP');
    const connectButton=button('Подключиться',()=>{if(approved && !failed){approved=false;reset();refresh();return;}if(!target || loginSelect.value==='')return;role=loginSelect.value==='base'?'':loginSelect.value;approved=true;requested=undefined;refresh();},'primary');
    const picker=el('div',undefined,'sftp-picker');
    for(const [caption,field] of [['Сервер',select],['Учётная запись',loginSelect]]){const line=el('label',caption);line.append(field);picker.append(line);}
    picker.append(connectButton);$('remote-pane').querySelector('header').append(picker);
    let approved=false, loginSignature, loginGeneration=0;
    loginSelect.onchange=()=>{approved=false;role=loginSelect.value==='base'?'':loginSelect.value;requested=undefined;refresh();};
    let localQueue=Promise.resolve();
    function localFolder(key,serial) {
      localQueue=localQueue.catch(()=>{}).then(async()=>{
        if(serial!==attempt)return;
        const chosen=await api.defaultLocal(key);
        if(serial!==attempt)return;
        scope=chosen;show(local,true);await load(local,readDir('local'),true);
      }).catch(e=>{if(serial===attempt){show(local,false);$('local-empty').textContent=e.message;}});
    }
    function reset() {
      ++attempt;
      if(fileId)api.remove(fileId).catch(()=>{});
      fileId=undefined;connectedHost=undefined;binding=undefined;scope=undefined;requested=undefined;failed=undefined;locationKey='';
      show(local,false);show(remote,false);
    }
    function refresh() {
      if(!latest)return;
      const {sessions,visible,connect}=latest;
      let hosts=latest.hosts;
      // Locking the vault hides its catalog. An established or pending SFTP
      // connection still owns its transport and can finish independently.
      if(latest.vaultLocked && approved && connectedHost?.id===target){
        hosts=[...hosts.filter(h=>h.id!==target),connectedHost];
      }
      if(!visible){previousVisible=false;return;}
      if(target && !hosts.some(h=>h.id===target)){target='';approved=false;}
      const signature=JSON.stringify(hosts.map(h=>[h.id,h.label]));
      if(signature!==optionsSignature){
        select.replaceChildren(new Option('Выберите сервер',''),...hosts.map(h=>new Option(h.label,h.id)));
        optionsSignature=signature;
      }
      select.value=target || '';
      const host=hosts.find(h=>h.id===target);
      const ls=JSON.stringify([target,host?.username,host?.auth,host?.logins,latest.keys]);
      if(ls!==loginSignature){
        loginSignature=ls;const gen=++loginGeneration;
        loginSelect.replaceChildren(new Option('Выберите вход',''));
        if(host){
          loginSelect.add(new Option(host.username+' · основной вход','base'));
          for(const a of host.logins || [])loginSelect.add(new Option(a.username+' · '+(a.auth==='password'?'пароль':a.auth==='agent'?'агент':'ключ'),'login:'+a.loginId));
          if(!host.cloud)for(const k of latest.keys || [])if(k.cloud && k.id!==host.keyId)loginSelect.add(new Option(host.username+' · '+k.name,'cloud-key:'+k.id));
          api.serverAccounts(host.id).then(p=>{
            if(gen!==loginGeneration)return;
            for(const r of ['debug','admin'])if(p[r])loginSelect.add(new Option(p[r].user+' · '+r,r));
            if(approved)loginSelect.value=role || 'base';
          }).catch(()=>{});
          if(approved)loginSelect.value=role || 'base';
        }
      }
      loginSelect.disabled=!host;
      connectButton.disabled=!host || !loginSelect.value;
      connectButton.textContent=approved && !failed?'Отключить':'Подключиться';
      const key=host?JSON.stringify([host.id,host.host,host.port]):'';
      const request=key+JSON.stringify([role || '',host?.username,host?.auth,host?.keyId]);
      if(request!==requested){
        reset();requested=request;locationKey=key;
        const serial=attempt;
        localFolder(key,serial);
        if(host){
          if(approved)connectedHost=host;
          if(approved)Promise.resolve(connect(host,role || undefined,true)).then(id=>{
            if(serial!==attempt){if(id)api.remove(id).catch(()=>{});return;}
            fileId=id;if(!id)failed='Подключение отменено.';refresh();
          }).catch(e=>{if(serial===attempt){failed=e.message;refresh();}});
        }
      }
      const session=sessions.find(s=>s.id===fileId && s.fileOnly);
      if(session?.state==='closed'||session?.error){approved=false;failed=session.error || 'Соединение закрыто.';connectButton.textContent='Подключиться';}
      const retry=()=>{approved=true;reset();refresh();};
      controls.replaceChildren();
      if(!host || !approved){empty.textContent=failed || (hosts.length?'Выберите сервер и учётную запись для подключения.':'Добавьте сервер, чтобы открыть SFTP.');return;}
      if(session?.state==='ready'){
        if(!binding || binding.generation!==session.generation){
          binding=session;show(remote,true);load(remote,readDir('remote'),true);
        }
        connectButton.textContent='Отключить';
      } else {
        if(binding){binding=undefined;show(remote,false);}
        if(session?.trust){
          const t=session.trust;
          empty.replaceChildren(el('h3',t.known?'Изменился ключ сервера':'Первое подключение'),el('p',t.fingerprint));
          if(t.known)empty.append(el('p','Сохранённый ключ · '+t.known));
          const actions=el('div',undefined,'sftp-trust-actions');empty.append(actions);
          actions.append(button('Отклонить',()=>api.verify(session.id,session.generation,t.fingerprint,false)),
            button(t.known?'Заменить проверенный ключ':'Доверять ключу',()=>api.verify(session.id,session.generation,t.fingerprint,true)));
        }else{
          empty.textContent=failed || session?.error || (session?.state==='closed'?'Соединение закрыто.':'Подключение к SFTP…');
          if(failed || ['closed','error'].includes(session?.state))empty.append(button('Подключиться снова',retry));
        }
      }
    }
    select.onchange=()=>{target=select.value;role=undefined;approved=false;requested=undefined;refresh();};
    return (sessions,hosts,visible,selection,connect,keys,vaultLocked)=>{latest={sessions,hosts,visible,selection,connect,keys,vaultLocked};refresh();};
  }
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
