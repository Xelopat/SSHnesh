const distroIcons = {ubuntu:'ubuntu', debian:'debian', fedora:'fedora', arch:'archlinux',
  'opensuse-leap':'opensuse', 'opensuse-tumbleweed':'opensuse', rocky:'rockylinux'};

function pencil(node) {
  const svg=document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('viewBox','0 0 24 24');svg.setAttribute('width','16');svg.setAttribute('height','16');
  svg.setAttribute('aria-hidden','true');svg.setAttribute('fill','none');svg.setAttribute('stroke','currentColor');
  svg.setAttribute('stroke-width','1.6');svg.setAttribute('stroke-linejoin','round');
  const path=document.createElementNS(svg.namespaceURI,'path');
  path.setAttribute('d','M4 20l4.6-1 11-11a2 2 0 0 0-3.6-3.6l-11 11L4 20zm10.2-13.3 3.2 3.2');
  svg.append(path);node.replaceChildren(svg);return node;
}

export function serverWorkspace({api, el, button, edit, connectHost, groupsClosed}) {
  const byId = id => document.getElementById(id);
  const page = byId('home-servers');
  document.getElementById('home').classList.add('split-home');
  page.classList.add('server-workspace');
  const tree = el('aside',undefined,'machine-tree');
  tree.setAttribute('aria-label','Группы и серверы');
  tree.append(page.querySelector('.heading'),page.querySelector('.search'),byId('hosts'));
  const pane = el('section',undefined,'machine-pane');
  pane.setAttribute('aria-label','Выбранный сервер');
  page.append(tree,pane);
  let current, treeSignature, paneSignature, revision=0, lastState;
  let chosen='';
  function icon(system) {
    if (!system) {
      const rack=el('span',undefined,'machine-glyph');
      rack.setAttribute('aria-hidden','true');
      rack.append(el('i'),el('i'));
      return rack;
    }
    const img=el('img',undefined,'machine-os-icon');
    img.alt=''; img.src='/systems/'+(Object.hasOwn(distroIcons,system.id)?distroIcons[system.id]:'linux')+'.svg';
    return img;
  }
  function display(state) {
    lastState=state;
    const query=byId('search').value.trim().toLowerCase();
    const catalog=new Map((state.groups || []).map(g=>[g.label,new Set(g.members)]));
    const names=h=>{
      const labels=[...catalog].filter(([,ids])=>ids.has(h.id)).map(([label])=>label);
      const old=h.group || 'Мои серверы';
      if(!catalog.has(old))labels.push(old);
      return labels.length?labels:['Без группы'];
    };
    const hosts=state.hosts.filter(h=>[...names(h),h.label,h.host,h.username].some(v=>v?.toLowerCase().includes(query)));
    const groups=new Map([...catalog.keys()].filter(n=>!query||n.toLowerCase().includes(query)).map(n=>[n,[]]));
    for(const h of hosts)for(const n of names(h)){if(!groups.has(n))groups.set(n,[]);groups.get(n).push(h);}
    if (!hosts.some(h=>h.id===current)) {current=hosts[0]?.id;chosen='';}
    const host=hosts.find(h=>h.id===current);
    const nextTree=JSON.stringify([query,state.groups,hosts.map(h=>[h.id,h.label,h.group,h.system?.id])]);
    if(treeSignature!==nextTree) {
      treeSignature=nextTree;
      const items=[];
      for(const [group,members] of groups) {
        const details=el('details',undefined,'machine-group');
        details.open=!!query || !groupsClosed.has(group);
        details.ontoggle=()=>{if(query || !details.isConnected)return; if(details.open)groupsClosed.delete(group);else groupsClosed.add(group);};
        const title=el('summary',group);
        const editGroup=button('✎',e=>{e.preventDefault();e.stopPropagation();api.editGroup(group,state.hosts.filter(h=>names(h).includes(group)).map(h=>h.id));},'group-edit','Изменить состав группы '+group);
        title.append(pencil(editGroup));details.append(title);
        for(const h of members) {
          const node=button(h.label,()=>{
            if(current!==h.id)chosen='';
            current=h.id;page.classList.add('show-machine');display(lastState);
            if(matchMedia('(max-width:650px)').matches)pane.querySelector('h1')?.focus();
          },'machine-link');
          node.dataset.serverId=h.id;
          node.ondblclick=()=>{if(h.id===current)(pane.querySelector('.login-connect[data-current]') || pane.querySelector('.login-connect'))?.click();};
          node.prepend(icon(h.system));
          if(current===h.id)node.setAttribute('aria-current','true');
          details.append(node);
        }
        items.push(details);
      }
      byId('hosts').replaceChildren(...(items.length?items:[el('p',query?'Серверы не найдены':'Добавьте первый сервер.','muted')]));
    }
    for(const node of tree.querySelectorAll('.machine-link')) {
      if(node.dataset.serverId===current)node.setAttribute('aria-current','true');else node.removeAttribute('aria-current');
    }
    const keyList=state.keys.map(k=>[k.id,k.name,k.protected]);
    const nextPane=JSON.stringify([host,keyList]);
    if(nextPane===paneSignature)return;
    paneSignature=nextPane;
    const generation=++revision;
    if(!host){page.classList.remove('show-machine');pane.replaceChildren();return;}
    const back=button('‹  Все серверы',()=>{page.classList.remove('show-machine');tree.querySelector('[aria-current]')?.focus();},'machine-back');
    const head=el('header',undefined,'machine-head');
    const identity=el('div'), title=el('h1',host.label);
    title.tabIndex=-1;
    const os=[host.system?.name,host.system?.version].filter(Boolean).join(' ');
    const address=(host.host.includes(':')?'['+host.host+']':host.host)+':'+host.port;
    identity.append(title,el('p',address,'machine-endpoint'));
    if(os)identity.append(el('p',os,'machine-system'));
    head.append(icon(host.system),identity,button('Изменить',()=>host.cloud && !host.localProfile?api.editVaultServer(host):edit(host),'machine-edit','Изменить адрес и группу'));
    const bar=el('header',undefined,'login-heading');
    bar.append(el('h2','Учётки на сервере'));
    bar.append(button('+ Добавить учётку',()=>api.editVaultLogin(host,null),'login-add'));
    const list=el('div',undefined,'machine-logins');
    pane.replaceChildren(back,head,bar,list);
    const method=a=>a.auth==='key'?(state.keys.find(k=>k.id===a.keyId)?.name || 'SSH-ключ'):a.auth==='agent'?'Системный SSH-агент':'Пароль SSH';
    const rows=[{id:'',user:host.username,sudo:host.sudo,detail:method(host)+(host.loginPort?" · порт "+host.loginPort:""),edit:()=>api.editVaultLogin(host)}];
    for(const a of host.logins || [])rows.push({id:'login:'+a.loginId,user:a.username,sudo:a.sudo,detail:method(a)+(a.loginPort?" · порт "+a.loginPort:""),edit:()=>api.editVaultLogin(host,a)});
    if(!host.cloud)for(const k of state.keys.filter(k=>k.cloud && k.id!==host.keyId))rows.push({id:'cloud-key:'+k.id,user:host.username,sudo:host.sudo,detail:k.name});
    const renderRows=()=>{
      list.replaceChildren(...rows.map(row=>{
        const wrap=el('div',undefined,'machine-login'), text=el('div',undefined,'login-description');
        const name=el('strong',row.user);
        if(row.user==='root'||host.rootUsers?.includes(row.user))name.append(el('span','root','root-label'));
        else if(row.sudo)name.append(el('span','sudo','root-label'));
        text.append(name,el('small',row.detail));wrap.append(text);
        const connect=button('Подключиться',async()=>{chosen=row.id;renderRows();await connectHost(host,row.id || undefined);},'primary login-connect','Подключиться как '+row.user);
        if(chosen===row.id)connect.dataset.current='';
        wrap.append(connect);
        if(row.edit)wrap.append(pencil(button('',row.edit,'login-pencil','Изменить вход '+row.user)));
        return wrap;
      }));
    };
    renderRows();
    api.serverAccounts(host.id).then(profile=>{
      if(generation!==revision)return;
      for(const key of ['debug','admin'])if(profile[key])rows.push({id:key,user:profile[key].user,
        detail:(key==='debug'?'Диагностика':'Администрирование')+' · '+profile[key].keyPath.split(/[\/]/).pop(),edit:()=>api.editServerAccounts(host,key)});
      renderRows();
    }).catch(error=>{if(generation===revision)list.append(el('p',error.message,'error'));});
  }
  window.addEventListener('server-logins-updated',()=>{paneSignature=null;if(lastState)display(lastState);});
  display.selection=()=>({hostId:current,role:chosen});
  return display;
}
