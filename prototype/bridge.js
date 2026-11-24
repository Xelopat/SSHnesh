import { setupAccount } from './account.js';

const { core, event } = window.__TAURI__;
if (/Android/.test(navigator.userAgent)) document.documentElement.dataset.previewMobile = '';
let choosingKeyFile = false;
const call = (action, ...args) => core.invoke('dispatch', { action, args })
  .catch(message => { throw new Error(String(message)); });

document.addEventListener('DOMContentLoaded', () => {
  for (const name of ['accounts', ...(api.mobileLineInput ? ['logs'] : [])]) {
    document.querySelector(`#home-nav [data-section="${name}"]`)?.setAttribute('hidden', '');
  }
  document.querySelector('#home-nav [data-section="settings"]').hidden = false;
  if (api.mobileLineInput) document.querySelector('#host-auth option[value=agent]')?.remove();
  const refresh = setupAccount(api, call, passwordDialog);
  api.renderAccount = refresh;
  let restoring = false;
  const restore = async () => {
    if (document.hidden || restoring) return;
    restoring = true;
    try {
      const state = await api.state();
      refresh(state);
      if (state.sync.remembered && !state.sync.unlocked && !state.sync.busy) {
        await call('syncTransfer','unlock','',{});
      }
    } catch {
      // The vault stays locked and can be opened with its master password.
    } finally { restoring = false; }
  };
  api.onState(refresh);
  window.addEventListener('focus',restore);
  const suspend = async () => {
    const state=await api.state();
    if(!choosingKeyFile && state.sync.remembered && state.sync.unlocked && !state.sync.busy) await call('cloudLock','background');
  };
  window.addEventListener('blur',suspend);
  document.addEventListener('visibilitychange',() => { void (document.hidden ? suspend() : restore()); });
  void restore();
  const approvals = new Map();
  event.listen('mcp-request', ({payload}) => {
    const d = document.createElement('dialog');
    d.innerHTML = '<form method="dialog"><h2>Запрос MCP</h2><p style="white-space:pre-wrap;overflow-wrap:anywhere"></p><div class="actions"><button value="deny" autofocus>Отмена</button><button value="allow">Разрешить</button></div></form>';
    d.querySelector('p').textContent = payload.message;
    const secret=payload.kind==='secret';
    if(secret){
      const input=document.createElement('input');input.type='password';input.autocomplete='off';input.required=true;
      input.setAttribute('aria-label',payload.message);d.querySelector('p').after(input);
      const cancel=d.querySelector('[value=deny]');
      cancel.type='button';cancel.removeAttribute('autofocus');
      cancel.onclick=()=>d.close('deny');
      input.autofocus=true;
      d.querySelector('[value=allow]').textContent='Продолжить';
    }
    approvals.set(payload.id,d);
    d.onclose = () => {
      if(approvals.delete(payload.id)){
        const ok=d.returnValue==='allow';
        if(secret){const field=d.querySelector('input');void call('mcpSecret',payload.id,ok?field.value:null).catch(()=>{});field.value='';}
        else if(ok && payload.kind==='unlock'){
          void api.unlockKeys().then(()=>api.state()).then(s=>call('mcpDecision',payload.id,s.sync.unlocked)).catch(()=>call('mcpDecision',payload.id,false)).catch(()=>{});
        }else void call('mcpDecision',payload.id,ok).catch(()=>{});
      }
      d.remove();
    };
    document.body.append(d);d.showModal();
  });
  event.listen('mcp-request-closed', ({payload:id}) => {
    const d=approvals.get(id);approvals.delete(id);if(d?.open)d.close();
  });
  const mcp = document.querySelector('#mcp-panel');
  const config = mcp.querySelector('#config');
  mcp.classList.add('native-mcp');
  mcp.querySelector('h2').textContent = 'Доступ Codex';
  config.textContent = 'Скопировать команду';
  config.title = 'Скопировать команду подключения SSHnesh к Codex';
  const context = document.createElement('label');
  const startup = document.createElement('label');
  startup.className = context.className = 'mcp-option';
  const enableAtLaunch = document.createElement('input');
  enableAtLaunch.type = 'checkbox';
  enableAtLaunch.id = 'native-mcp-startup';
  enableAtLaunch.checked = true;
  enableAtLaunch.onchange = async () => {
    const desired = enableAtLaunch.checked;
    enableAtLaunch.disabled = true;
    try { await call('mcpOnStartup', desired); }
    catch (error) { enableAtLaunch.checked = !desired; window.alert(error.message); }
    finally { enableAtLaunch.disabled = false; }
  };
  startup.append(enableAtLaunch, 'Включать MCP при запуске');
  const allow = document.createElement('input');
  allow.type = 'checkbox';
  allow.id = 'allow-active-context';
  allow.checked = true;
  allow.onchange = async () => {
    try { await call('activeContextEnabled', allow.checked); }
    catch (error) { allow.checked = !allow.checked; window.alert(error.message); }
  };
  context.append(allow, 'Показывать Codex текущий сервер');
  const setup = document.createElement('details');
  setup.className = 'mcp-setup';
  const setupTitle = document.createElement('summary');
  setupTitle.textContent = 'Как подключить Codex';
  const hint = document.createElement('p');
  hint.textContent = 'Выполните команду в терминале и откройте новый чат Codex.';
  setup.append(setupTitle, hint, config);
  mcp.querySelector('#mcp-content').replaceChildren(startup, context, setup);
  if (!api.mobileLineInput) {
    void api.state().then(state => {
      enableAtLaunch.checked = state.mcp.enabled;
      allow.checked = state.activeContextEnabled;
      allow.disabled = !state.mcp.enabled;
    }).catch(console.error);
  }
  mcp.querySelector('.mcp-controls').hidden = true;
  document.querySelector('#toggle-mcp').hidden = true;
  document.querySelector('#foot-mcp').hidden = true;
  if (!api.mobileLineInput) {
    const section = document.createElement('section');
    section.className = 'card native-mcp mcp-preferences';
    section.setAttribute('aria-labelledby','settings-mcp-title');
    const title = mcp.querySelector('h2');
    title.id = 'settings-mcp-title';
    title.textContent = 'MCP · Доступ Codex';
    section.append(title, mcp.querySelector('#mcp-content'));
    document.querySelector('#home-settings').append(section);
  }
  {
    const accountTab=document.querySelector('#home-nav [data-section="sync"]');
    accountTab.querySelector('span').textContent='@';
    accountTab.lastChild.textContent='Аккаунт';
    document.querySelector('#home-nav [data-section="logs"]').lastChild.textContent='Журнал';
    document.querySelector('#sync-title').textContent = 'Аккаунт';
    document.querySelector('#import-key').hidden = false;
    document.querySelector('#generate-key').hidden = false;
  }
});

async function editServerAccounts(host, selectedRole='debug') {
  const profile=await call('serverAccounts',host.id);
  const dialog=document.createElement('dialog');
  dialog.innerHTML='<form><h2>Вход для MCP</h2><label>Назначение<select name="role"><option value="debug">Диагностика</option><option value="admin">Администрирование</option></select></label><label>Пользователь SSH<input name="username" autocomplete="off"></label><label>Файл SSH-ключа на устройстве<input name="keyPath"></label><label>Проверенный отпечаток сервера<input name="fingerprint" required placeholder="SHA256:…"></label><p class="error" role="alert"></p><div class="actions"><button type="button">Отмена</button><button class="primary">Сохранить</button></div></form>';
  const form=dialog.querySelector('form'), f=form.elements;
  f.fingerprint.value=profile.fingerprint || '';f.role.value=selectedRole;
  const update=()=>{const a=profile[f.role.value];f.username.value=a?.user || '';f.keyPath.value=a?.keyPath || '';};
  f.role.onchange=update;update();form.querySelector('button').onclick=()=>dialog.close();
  form.onsubmit=async e=>{
    e.preventDefault();const submit=form.querySelector('[type="button"] + button');submit.disabled=true;
    try {
      const current=await call('serverAccounts',host.id);
      const user=f.username.value.trim(), keyPath=f.keyPath.value.trim();
      current[f.role.value]=user || keyPath ? {user,keyPath}:null;
      await call('saveServerAccounts',host.id,f.fingerprint.value,current.debug,current.admin);
      window.dispatchEvent(new Event('server-logins-updated'));dialog.close();
    }catch(err){form.querySelector('[role=alert]').textContent=err.message;}
    finally{submit.disabled=false;}
  };
  dialog.onclose=()=>dialog.remove();document.body.append(dialog);dialog.showModal();
}

function passwordDialog(title = 'Пароль SSH', label = 'Пароль', enrollment, options = {}) {
  const dialog = document.createElement('dialog');
  dialog.innerHTML = '<form method="dialog"><h2></h2><label><span></span> ' +
    '<input type="password" autocomplete="off" required autofocus></label>' +
    '<div><button type="button">Отмена</button><button class="primary">Сохранить</button></div></form>';
  const form = dialog.querySelector('form');
  const field = dialog.querySelector('input');
  dialog.setAttribute('aria-label', title);
  if (options.submit) form.querySelector('.primary').textContent = options.submit;
  if (options.minLength) field.minLength = options.minLength;
  if (options.hint) {
    const hint = document.createElement('p');
    hint.className = 'muted';
    hint.id = 'password-dialog-hint';
    hint.textContent = options.hint;
    field.setAttribute('aria-describedby', hint.id);
    field.closest('label').after(hint);
  }
  if (enrollment) {
    const choice = document.createElement('input');
    choice.type = 'checkbox';
    const line = document.createElement('label');
    line.className = 'check-field';
    line.append(choice, 'Открывать хранилище после разблокировки устройства');
    field.closest('label').after(line);
    choice.onchange = () => { enrollment.rememberDevice = choice.checked; };
  }
  dialog.querySelector('h2').textContent = title;
  dialog.querySelector('label span').textContent = label;
  dialog.querySelector('button').onclick = () => dialog.close();
  document.body.append(dialog);
  return new Promise(resolve => {
    form.onsubmit = event => { event.preventDefault(); dialog.close('ok'); };
    dialog.onclose = () => {
      const password = dialog.returnValue === 'ok' ? field.value : undefined;
      field.value = '';
      dialog.remove();
      resolve(password);
    };
    dialog.showModal();
  });
}

async function vaultEdit(action, values) {
  const state=await api.state();
  const enrollment={};
  const master=state.sync.unlocked || state.sync.remembered ? '' : await passwordDialog('Хранилище','Мастер-пароль хранилища',enrollment);
  if(master===undefined)throw Error('Сохранение отменено.');
  return call('syncTransfer',action,master,{...values,...enrollment});
}
const api = {
  prototypeMode: true,
  async unlockKeys() {
    const { sync } = await api.state();
    const master = sync.remembered ? '' : await passwordDialog('Открыть хранилище', 'Мастер-пароль хранилища');
    if (master !== undefined) await call('syncTransfer', 'unlock', master, {});
  },
  async removeKey(key) {
    if (confirm('Удалить ключ «' + key.name + '» из хранилища SSHnesh?')) await vaultEdit('removeKey', {id:key.id, confirmed:true});
  },
  saveKeyComment: (id, comment) => vaultEdit('keyComment', {id, comment}),
  async exportKey(key) {
    const d=document.createElement('dialog');
    d.innerHTML='<form><h2>Экспорт приватного ключа</h2><label>Формат файла<select name="mode"><option value="encrypted">С парольной фразой</option><option value="plain">Без шифрования</option></select></label><label>Текущая парольная фраза<input name="old" type="password" autocomplete="off"></label><label>Новая парольная фраза<input name="phrase" type="password" autocomplete="new-password"></label><label>Повторите парольную фразу<input name="repeat" type="password" autocomplete="new-password"></label><p class="muted" hidden>Файл сможет использовать любой, у кого есть к нему доступ.</p><p role="alert" class="error"></p><div class="actions"><button type="button">Отмена</button><button class="primary">Сохранить файл…</button></div></form>';
    const form=d.querySelector('form'), f=form.elements;
    f.old.closest('label').hidden=!key.protected;
    f.old.required=key.protected;
    f.mode.onchange=()=>{
      const encrypted=f.mode.value==='encrypted';
      for(const field of [f.phrase,f.repeat]) {field.closest('label').hidden=!encrypted;field.required=encrypted;}
      d.querySelector('.muted').hidden=encrypted;
    };
    d.querySelector('[type=button]').onclick=()=>d.close();
    form.onsubmit=async e=>{
      e.preventDefault();
      const error=d.querySelector('[role=alert]');
      if(f.mode.value==='encrypted' && f.phrase.value!==f.repeat.value){error.textContent='Парольные фразы не совпадают.';return;}
      const save=d.querySelector('.primary');
      if(save.disabled)return;
      save.disabled=true;
      choosingKeyFile=true;
      try {
        if(await call('exportKey',key.id,{mode:f.mode.value,old:key.protected?f.old.value:null,new:f.mode.value==='encrypted'?f.phrase.value:null}))d.close();
      }catch(e){error.textContent=e.message;}
      finally{save.disabled=false;choosingKeyFile=false;}
    };
    d.onclose=()=>{form.reset();d.remove();};
    document.body.append(d);d.showModal();
  },
  editServerAccounts,
  moveVaultServer: (host,group) => call('syncTransfer','editHost','',{...host,group}),
  async editVaultServer(host) {
    const dialog = document.createElement('dialog');
    dialog.innerHTML = '<form method="dialog"><h2>Настроить сервер</h2><label>Название<input name="label" maxlength="120" required></label><label>Группа<input name="group" maxlength="120"></label><label>Адрес<input name="host" maxlength="253" required></label><label>Порт<input name="port" type="number" min="1" max="65535" required></label><p role="status"></p><button type="button" name="cancel">Отмена</button> <button type="button" name="remove">Удалить</button> <button class="primary">Сохранить</button></form>';
    const form = dialog.querySelector('form');
    for (const field of ['label','group','host','port']) form.elements[field].value = host[field] ?? '';
    form.elements.cancel.onclick=()=>dialog.close();
    const apply = async (action) => {
      const values = Object.fromEntries(new FormData(form));
      const buttons = form.querySelectorAll('button');
      buttons.forEach(b=>b.disabled=true);
      try { await call('syncTransfer',action,'',{...values,port:Number(values.port),id:host.id}); dialog.close(); }
      catch(error) { form.querySelector('p').textContent=error.message; }
      finally { buttons.forEach(b=>b.disabled=false); }
    };
    form.elements.remove.onclick=()=>{ if(confirm('Удалить сервер «'+host.label+'»?')) void apply('removeHost'); };
    form.onsubmit=e=>{ e.preventDefault(); void apply('editHost'); };
    dialog.onclose=()=>dialog.remove();
    document.body.append(dialog);
    dialog.showModal();
  },
  saveGroup: values=>vaultEdit("saveGroup",values),
  async editVaultLogin(host, login) {
    const server=host;
    if(login!==undefined)host={...server,loginPort:null,sudo:false,username:"",auth:"password",keyId:null,hasPassword:false,...login};
    let state = await api.state();
    const dialog = document.createElement('dialog');
    dialog.innerHTML = '<form><h2></h2><label>Пользователь SSH<input name="username" required maxlength="128" autocomplete="off"></label><label>Порт подключения<input type="number" name="loginPort" min="1" max="65535" step="1"></label><label class="check-field login-sudo"><input type="checkbox" name="sudo"><span>У пользователя есть <code>sudo</code></span></label><label>Способ входа<select name="method" required><option value="password">Пароль</option><option value="key">Ключ SSH</option></select></label><div class="login-key-tools"><label>Ключ<select name="keyChoice"></select></label><p class="muted"></p><div class="actions"></div></div><label>Пароль<input type="password" name="password" autocomplete="new-password"></label><p role="alert" class="error"></p><div class="actions"><button type="button" name="cancel">Отмена</button><button class="primary" type="submit">Сохранить</button></div></form>';
    const form=dialog.querySelector('form'), fields=form.elements;
    const tools=form.querySelector('.login-key-tools'), actions=tools.querySelector('.actions');
    form.querySelector('h2').textContent=(login===null?'Новая учётка · ':'Учётка · ')+server.label;
    fields.username.value=host.username;
    fields.sudo.checked=Boolean(host.sudo);
    fields.loginPort.placeholder="Порт сервера · "+server.port;
    fields.loginPort.value=host.loginPort ?? "";
    const update=()=>{
      const password=fields.method.value==='password';
      fields.password.closest('label').hidden=!password;
      fields.password.disabled=!password;
      tools.hidden=password;
      fields.keyChoice.disabled=password;
      fields.keyChoice.required=!password;
      const canKeep=host.hasPassword && fields.username.value.trim()===host.username;
      fields.password.placeholder=canKeep?'Оставить текущий пароль':'';
      fields.password.required=password && !canKeep;
      form.querySelector('[type=submit]').disabled=!password && !fields.keyChoice.value;
    };
    let busy=false;
    function action(label,work){
      const btn=document.createElement('button');
      btn.type='button';btn.textContent=label;
      btn.onclick=async()=>{
        if(busy)return;
        busy=true;const before=new Set(state.keys.map(k=>k.id)),previous=fields.keyChoice.value;
        form.querySelector('[role=alert]').textContent='';
        try {
          await work();
          state=await api.state();
          const added=label==='Открыть хранилище'?null:state.keys.find(k=>!before.has(k.id));
          renderMethods(added?'key:'+added.id:previous || (host.keyId?'key:'+host.keyId:''));
        }catch(e){form.querySelector('[role=alert]').textContent=e.message;}
        finally{busy=false;}
      };
      actions.append(btn);
    }
    function renderMethods(selected){
      const locked=state.sync.cached && !state.sync.unlocked;
      const picker=fields.keyChoice;
      picker.replaceChildren();
      for(const key of state.keys)picker.add(new Option(key.name,'key:'+key.id));
      if(!api.mobileLineInput || host.auth==='agent')picker.add(new Option('Системный SSH-агент','agent'));
      const placeholder=new Option('Выберите ключ','');placeholder.disabled=true;
      picker.prepend(placeholder);
      picker.value=Array.from(picker.options).some(option=>option.value===selected)?selected:'';
      picker.closest('label').hidden=picker.options.length===1;
      actions.replaceChildren();
      const hint=tools.querySelector('p');
      hint.textContent=locked?'Откройте хранилище, чтобы выбрать сохранённый ключ.':state.keys.length?'':'В SSHnesh пока нет ключей.';
      hint.hidden=!hint.textContent;
      if(locked){
        action('Открыть хранилище',async()=>{
          const master=await passwordDialog('Открыть хранилище','Мастер-пароль хранилища');
          if(master!==undefined)await call('syncTransfer','unlock',master,{});
        });
      }else{
        action('Создать ключ',()=>new Promise(resolve=>{
          document.getElementById('key-dialog').addEventListener('close',resolve,{once:true});
          document.getElementById('generate-key').click();
        }));
        action('Импортировать ключ',()=>api.importKey());
      }
      update();
    }
    fields.method.value=host.auth==='password'?'password':'key';
    fields.username.oninput=fields.method.onchange=fields.keyChoice.onchange=update;
    renderMethods(host.auth==='key'?'key:'+host.keyId:host.auth);
    fields.cancel.onclick=()=>dialog.close();
    form.onsubmit=async event=>{
      event.preventDefault();
      if(busy || !fields.method.value)return;
      const method=fields.method.value==='password'?'password':fields.keyChoice.value;
      if(!method)return;
      const values={loginPort:fields.loginPort.value ? fields.loginPort.valueAsNumber : null,sudo:fields.sudo.checked,username:fields.username.value.trim(),auth:method.startsWith('key:')?'key':method,
        keyId:method.startsWith('key:')?method.slice(4):null,password:method==='password'?fields.password.value:''};
      try {
        if(login!==undefined)await vaultEdit('saveLogin',{...values,id:server.id,loginId:login?.loginId});
        else if(server.cloud)await vaultEdit('editLogin',{...values,id:server.id});
        else {
          await call('save',{...server,loginPort:values.loginPort,sudo:values.sudo,username:values.username,auth:values.auth,keyId:values.auth==='key'?values.keyId:null});
          if(values.auth==='password' && values.password)await call('setPassword',server.id,values.password);
        }
        dialog.close();
      }
      catch(error){form.querySelector('[role=alert]').textContent=error.message;}
    };
    dialog.onclose=()=>{form.reset();dialog.remove();};
    document.body.append(dialog);dialog.showModal();
  },
  serverAccounts: id => call('serverAccounts', id),
  mobileLineInput: /Android/.test(navigator.userAgent),
  mobileAccount: true,
  requestKeyPassphrase: () => passwordDialog('SSH-ключ защищён', 'Парольная фраза ключа'),
  selectActive: (...args) => call('activeSelection', ...args),
  onState: callback => event.listen('sshnesh-state', ({ payload }) => callback(payload)),
  onData: callback => event.listen('sshnesh-data', ({ payload: [id, generation, bytes] }) =>
    callback(id, generation, Uint8Array.from(bytes))),
  setPassword: async id => {
    const password = await passwordDialog();
    if (password === undefined) return false;
    await call('setPassword', id, password);
    return true;
  },
};
for (const action of ['state', 'save', 'deleteHost', 'connect', 'reconnect', 'disconnect', 'remove',
  'verify', 'enable', 'share', 'revoke', 'decide', 'config', 'copy', 'clearPassword',
  'defaultLocal','openSftp','chooseLocal', 'listLocal', 'listFiles', 'transferFile']) {
  api[action] = (...args) => call(action, ...args);
}
for (const action of ['input', 'resize']) {
  api[action] = (...args) => void call(action, ...args).catch(console.error);
}
for (const action of ['saveAccount', 'deleteAccount',
  'setAccountPassword', 'clearAccountPassword', 'migrateAccount',
  'setChatApproval', 'setApprovalMode']) {
  api[action] = async () => { throw new Error('Эта функция пока не перенесена в прототип Tauri.'); };
}
for (const action of ['syncLogin', 'syncLogout', 'syncCancel', 'syncTransfer', 'copyPublicKey', 'cloudLock', 'terminalSettings']) {
  api[action] = (...args) => call(action, ...args);
}
window.sshash = api;
api.syncTransfer = async (mode, password, enrollment) => {
  const choices = { ...enrollment };
  for (;;) {
    try { return await call('syncTransfer', mode, password, choices); }
    catch (error) {
      if (!error.message.startsWith('SSH_CONFLICT ')) throw error;
      const { selector, label } = JSON.parse(error.message.slice('SSH_CONFLICT '.length));
      const dialog = document.createElement('dialog');
      const form = document.createElement('form');
      form.method = 'dialog';
      const title = document.createElement('p');
      title.textContent = 'Запись «' + label + '» изменилась на двух устройствах. Какую версию сохранить?';
      form.append(title);
      for (const [value, text] of [['cancel','Отменить'],['local','С этого устройства'],['remote','Из облака']]) {
        const button = document.createElement('button');
        button.value = value;
        button.textContent = text;
        form.append(button);
      }
      dialog.append(form);
      document.body.append(dialog);
      const result = new Promise(resolve => { dialog.onclose = () => resolve(dialog.returnValue); });
      dialog.showModal();
      const answer = await result;
      dialog.remove();
      if (answer !== 'local' && answer !== 'remote') return false;
      choices[selector] = answer === 'local';
    }
  }
};
api.generateKey = async (name, comment) => {
  const enrollment = {};
  const {sync}=await api.state();
  const master = sync.unlocked || sync.remembered ? '' : await passwordDialog('Создать ключ', 'Мастер-пароль хранилища', enrollment);
  if (master === undefined) throw Error('Создание ключа отменено.');
  await call('syncTransfer', 'generateKey', master, { name, comment, ...enrollment });
};
api.importKey = async () => {
  const input = document.createElement('input');
  input.type = 'file';
  let file;
  choosingKeyFile=true;
  try { file = await new Promise(resolve => {
    input.onchange = () => resolve(input.files[0]);
    input.oncancel = () => resolve(null);
    input.click();
  }); } finally { choosingKeyFile=false; }
  if (!file) return;
  if (file.size > 128 * 1024) throw Error('Размер ключа превышает 128 КиБ.');
  const enrollment = {};
  const {sync}=await api.state();
  const master = sync.unlocked || sync.remembered ? '' : await passwordDialog('Импорт ключа', 'Мастер-пароль хранилища', enrollment);
  if (master === undefined) return;
  const raw = await file.text();
  try {
    await call('syncTransfer', 'importKey', master, { name: file.name, raw, ...enrollment });
  } catch (error) {
    if (!error.message.includes('Введите парольную фразу')) throw error;
    const phrase = await passwordDialog('SSH-ключ защищён', 'Парольная фраза ключа');
    if (phrase !== undefined) await call('syncTransfer', 'importKey', master, { name: file.name, raw, phrase, ...enrollment });
  }
};
