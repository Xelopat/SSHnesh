const { contextBridge, ipcRenderer } = require('electron');
const invoke = channel => (...args) => ipcRenderer.invoke(channel, ...args);
const send = channel => (...args) => ipcRenderer.send(channel, ...args);
const on = channel => callback => ipcRenderer.on(channel, (_event, ...args) => callback(...args));
contextBridge.exposeInMainWorld('sshash', {
  state: invoke('state:get'), onState: on('state:changed'), onData: on('term:data'),
  save: invoke('host:save'), deleteHost: invoke('host:delete'), connect: invoke('ssh:connect'),
  reconnect: invoke('ssh:reconnect'), disconnect: invoke('ssh:disconnect'), remove: invoke('ssh:remove'),
  verify: invoke('ssh:verify'), input: send('ssh:input'), resize: send('ssh:resize'),
  enable: invoke('mcp:enable'), share: invoke('mcp:share'), revoke: invoke('mcp:revoke'),
  decide: invoke('mcp:decide'), config: invoke('mcp:config'),
  copy: invoke('term:copy'),
  importKey: invoke('key:import'), removeKey: invoke('key:remove'), copyPublicKey: invoke('key:copy-public'),
  setPassword: invoke('host:password'), clearPassword: invoke('host:clear-password'),
  listFiles: invoke('files:list'), chooseLocal: invoke('files:choose-local'),
  listLocal: invoke('files:local-list'), transferFile: invoke('files:transfer'),
});
