#[cfg(not(mobile))]
#[path="app_mcp.rs"]
mod app_mcp;
use crate::profiles::{self, Profile};
use crate::ssh::{self, Connection, Input, VerifyKey};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    path::{Component, Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{AppHandle, Emitter, Manager, State};
use tokio::sync::{mpsc, oneshot};
use uuid::Uuid;
use zeroize::Zeroizing;

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct Host {
    #[serde(default)]
    id: String,
    label: String,
    #[serde(default)]
    group: String,
    host: String,
    port: u16,
    username: String,
    auth: String,
    #[serde(default,skip_serializing_if="Option::is_none")]
    key_id: Option<String>,
    #[serde(default,skip_serializing_if="std::ops::Not::not")]
    sudo: bool,
    #[serde(default,skip_serializing_if="Option::is_none")]
    login_port: Option<std::num::NonZeroU16>,
}

impl Host {
    fn from_entry(entry: &crate::cloud::Entry) -> Self {
        Self { id:entry.id.clone(), label:entry.label.clone(), group:entry.group.clone(),
            host:entry.host.clone(), port:entry.port, username:entry.username.clone(), login_port:entry.login_port, sudo:entry.sudo, auth:entry.auth.clone(), key_id:entry.key_id.clone() }
    }
    fn system_endpoint(host: &str, port: u16) -> String {
        use sha2::{Digest, Sha256};
        format!("{:x}",Sha256::digest(format!("{host}:{port}").as_bytes()))
    }
    fn target(&self) -> String {
        format!("{}@{}:{}", self.username, self.host, self.port)
    }
}

pub(crate) struct Session {
    pub generation: String,
    host: Host,
    role: Option<String>,
    pub status: &'static str,
    error: Option<String>,
    trust: Option<Value>,
    decision: Option<oneshot::Sender<bool>>,
    pub input: Option<mpsc::Sender<Input>>,
    connection: Option<Connection>,
    file_only: bool,
    ftp: Option<Arc<russh_sftp::client::SftpSession>>,
    task: Option<tokio::task::AbortHandle>,
}

#[derive(Default)]
pub(crate) struct Inner {
    hosts: Vec<Host>,
    passwords: HashMap<String, Zeroizing<String>>,
    host_keys: HashMap<(String, u16), String>,
    root_users: HashMap<String,bool>,
    trusted: HashMap<String,String>,
    systems: HashMap<String, (String, ssh::SystemInfo)>,
    pub sessions: HashMap<String, Session>,
    folder: Option<(String, PathBuf)>,
    pub(crate) oauth: crate::oauth::Auth,
    pub(crate) cloud: Option<crate::cloud::Vault>,
    pub(crate) cloud_owner: Option<String>,
    pub(crate) cloud_loading: bool,
    settings: TerminalSettings,
    #[cfg(not(mobile))]
    active: Option<crate::active::Window>,
    #[cfg(not(mobile))]
    mcp_enabled: bool,
    #[cfg(not(mobile))]
    pub(crate) mcp_connections: HashMap<String,app_mcp::Grant>,
    #[cfg(not(mobile))]
    chat_grants: std::collections::HashSet<String>,
    #[cfg(not(mobile))]
    grant_epoch: u64,
    #[cfg(not(mobile))]
    chat_prompt: Arc<tokio::sync::Mutex<()>>,
    #[cfg(not(mobile))]
    mcp_secrets: HashMap<String,oneshot::Sender<Option<Zeroizing<String>>>>,
    #[cfg(not(mobile))]
    mcp_approvals: HashMap<String,oneshot::Sender<bool>>,
}

#[derive(Clone)]
pub(crate) struct App {
    pub inner: Arc<Mutex<Inner>>,
    pub handle: AppHandle,
    pub(crate) profiles_path: PathBuf,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TerminalSettings {
    font_size: u16,
    cursor_blink: bool,
    scrollback: u16,
}
impl Default for TerminalSettings {
    fn default() -> Self {
        Self {
            font_size: 14,
            cursor_blink: true,
            scrollback: 3000,
        }
    }
}
impl TerminalSettings {
    fn valid(&self) -> bool {
        (10..=30).contains(&self.font_size) && (100..=10000).contains(&self.scrollback)
    }
    fn read(profiles: &Path) -> Self {
        std::fs::read(profiles.with_file_name("terminal-settings.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Self>(&bytes).ok())
            .filter(Self::valid)
            .unwrap_or_default()
    }
}

enum SessionAuth {
    Agent,
    Password(Zeroizing<String>),
    FileKey(PathBuf, String),
    CloudKey(Box<russh::keys::PrivateKey>),
}

impl App {
    pub(crate) fn local_vault(&self) -> Value {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let data = self.inner.lock().unwrap();
        let mut passwords = serde_json::Map::new();
        for host in &data.hosts {
            if let Some(password) = data.passwords.get(&host.id).filter(|_|host.auth=="password") {
                passwords.insert(
                    host.id.clone(),
                    json!({
                        "target":json!([host.host,host.port,host.username]).to_string(),
                        "secret":STANDARD.encode(password.as_bytes())
                    }),
                );
            }
        }
        let mut hosts = data.hosts.clone();
        for host in &mut hosts {
            if host.group.trim().is_empty() {
                host.group = "Серверы".into();
            }
        }
        json!({"hosts":hosts,"accounts":[],"keys":{},"passwords":passwords})
    }
    #[cfg(not(mobile))]
    fn refresh_context(data: &Inner) -> std::io::Result<()> {
        let Some(active) = data.active.as_ref() else {
            return Ok(());
        };
        let target = active
            .selection
            .as_ref()
            .filter(|_| data.mcp_enabled)
            .and_then(|(id, generation)| {
                let session = Self::input_session(data, id, generation).ok()?;
                Some(crate::active::Target {
                    id: session.host.id.clone(),
                    host: session.host.host.clone(),
                    port: session.host.port,
                })
            });
        active.publish(target)
    }

    pub fn snapshot(&self) -> Value {
        let data = self.inner.lock().unwrap();
        #[allow(unused_mut)]
        let mut hosts: Vec<_> = data
            .hosts
            .iter()
            .filter(|host| !data.cloud.as_ref().is_some_and(|v|v.matches_device(json!(host))))
            .map(|host| {
                let mut value = json!(host);
                value["hasPassword"] = json!(data.passwords.contains_key(&host.id));
                value
            })
            .collect();
        if let Some(vault) = &data.cloud {
            for mut card in vault.hosts() {
                let id = card["id"].as_str().unwrap_or_default();
                if let Some(local) = data.hosts.iter().find(|item| item.id == id) {
                    if !vault.matches_device(json!(local)) { continue; }
                    card["localProfile"] = json!(card["host"] == local.host && card["port"] == local.port);
                } else if vault.recorded(id) { continue; }
                hosts.push(card);
            }
        }
        for card in &mut hosts {
            let endpoint=Host::system_endpoint(card["host"].as_str().unwrap_or(""),card["port"].as_u64().unwrap_or(0) as u16);
            card["rootUsers"]=json!(data.root_users.iter().filter_map(|(k,b)|if *b{k.strip_prefix(&(endpoint.clone()+"/"))}else{None}).collect::<Vec<_>>());
            if let Some(v)=&data.cloud{card["logins"]=json!(v.server_logins(card["id"].as_str().unwrap_or(""),card["host"].as_str().unwrap_or(""),card["port"].as_u64().unwrap_or(0) as u16));}

            if let Some((endpoint, system)) = card["id"].as_str().and_then(|id| data.systems.get(id)) {
                if let (Some(host),Some(port))=(card["host"].as_str(),card["port"].as_u64()) {
                    if *endpoint==Host::system_endpoint(host,port as u16) {card["system"]=json!(system);}
                }
            }
        }
        let sessions: Vec<_> = data
            .sessions
            .iter()
            .map(|(id, s)| {
                let key_protected = data
                    .cloud
                    .as_ref()
                    .and_then(|vault| {
                        let key = s
                            .role
                            .as_deref()
                            .and_then(|r| r.strip_prefix("cloud-key:"))
                            .map(str::to_owned)
                            .or_else(||s.host.key_id.clone()).or_else(|| vault.entry(&s.host.id)?.key_id)?;
                        vault.keys.get(&key)
                    })
                    .is_some_and(|key| key.is_protected());
                json!({
                    "fileOnly":s.file_only,"id": id, "generation": s.generation, "host": s.host, "state": s.status,
                    "trust": s.trust, "error": s.error, "keyProtected": key_protected
                })
            })
            .collect();
        #[cfg(not(mobile))]
        let mcp_enabled = data.mcp_enabled;
        #[cfg(mobile)]
        let mcp_enabled = false;
        let (mcp, clients) = (
            json!({"enabled":mcp_enabled,"approvalMode":"manual","pending":[],"history":[]}),
            0,
        );
        #[cfg(not(mobile))]
        let active_context = data.active.as_ref().is_some_and(|active| active.enabled);
        #[cfg(mobile)]
        let active_context = false;
        let (sync, keys) = {
            let mut sync = data.oauth.snapshot();
            sync["loginBusy"] = sync["busy"].clone();
            sync["busy"] = json!(data.cloud_loading || sync["busy"] == true);
            sync["cached"] = json!(
                self.profiles_path
                    .with_file_name("android-cloud-vault.json")
                    .is_file()
                    || self
                        .profiles_path
                        .with_file_name("vault-account.json")
                        .is_file()
            );
            sync["remembered"] = json!(self.profiles_path.with_file_name("remembered-owner.json").is_file());
            sync["unlocked"] = json!(data.cloud.is_some());
            sync["lastSynced"] = json!(data.cloud.as_ref().and_then(|vault| vault.last_synced));
            (
                sync,
                data.cloud
                    .as_ref()
                    .map(|vault| vault.key_list())
                    .unwrap_or_default(),
            )
        };
        json!({"hosts": hosts, "sessions": sessions, "mcp": mcp, "clientCount": clients,
            "activeContextEnabled": active_context,
            "groups":data.cloud.as_ref().map(|v|&v.groups),"persistent": false, "accounts": [], "keys": keys, "sync": sync, "terminalSettings":data.settings})
    }

    pub fn changed(&self) {
        #[cfg(not(mobile))]
        let _ = Self::refresh_context(&self.inner.lock().unwrap());
        let _ = self.handle.emit("sshnesh-state", self.snapshot());
    }

    pub fn input_session<'a>(
        data: &'a Inner,
        id: &str,
        generation: &str,
    ) -> Result<&'a Session, String> {
        data.sessions
            .get(id)
            .filter(|s| s.generation == generation && s.status == "ready" && !s.file_only)
            .ok_or_else(|| "SSH-сеанс завершён или изменился.".into())
    }

    fn close(
        &self,
        id: &str,
        generation: Option<&str>,
        error: Option<String>,
        abort: bool,
        remove: bool,
    ) {
        let mut data = self.inner.lock().unwrap();
        if let Some(session) = data.sessions.get_mut(id) {
            if generation.is_some_and(|g| g != session.generation) {
                return;
            }
            if abort {
                if let Some(task) = session.task.take() {
                    task.abort();
                }
            }
            session.status = if error.is_some() { "error" } else { "closed" };
            session.error = error;
            session.trust = None;
            session.decision = None;
            session.input = None;
            session.connection = None;
            session.ftp = None;
            if remove {
                data.sessions.remove(id);
            }
        }
        drop(data);
        self.changed();
    }

    fn connect(
        &self,
        mut host: Host,
        replace: Option<String>,
        auth: Option<SessionAuth>,
        role: Option<String>,
        file_only: bool,
    ) -> Result<String, String> {
        let mut data = self.inner.lock().unwrap();
        if !matches!(role.as_deref(),Some("debug" | "admin")) {
            if let Some(port)=host.login_port { host.port=port.get(); }
        }
        if data.sessions.len() >= 16 && replace.is_none() {
            return Err("Закройте лишние вкладки.".into());
        }
        let auth = match auth {
            Some(auth) => auth,
            None => SessionAuth::Password(
                data.passwords
                    .get(&host.id)
                    .cloned()
                    .ok_or("Введите пароль в настройках сервера.")?,
            ),
        };
        let id = replace.unwrap_or_else(random_id);
        if let Some(old) = data.sessions.remove(&id) {
            if let Some(task) = old.task {
                task.abort();
            }
        }
        let generation = random_id();
        let (tx, rx) = mpsc::channel(64);
        let app = self.clone();
        let task_id = id.clone();
        let task_generation = generation.clone();
        let task_host = host.clone();
        let task = tauri::async_runtime::spawn(async move {
            let result = app
                .run_session(&task_id, &task_generation, &task_host, auth, rx, file_only)
                .await;
            app.close(&task_id, Some(&task_generation), result.err(), false, false);
        });
        data.sessions.insert(
            id.clone(),
            Session {
                generation,
                host,
                role,
                status: "connecting",
                error: None,
                trust: None,
                decision: None,
                input: Some(tx),
                connection: None, file_only, ftp:None,
                task: Some(task.inner().abort_handle()),
            },
        );
        drop(data);
        self.changed();
        Ok(id)
    }

    async fn run_session(
        &self,
        id: &str,
        generation: &str,
        host: &Host,
        auth: SessionAuth,
        rx: mpsc::Receiver<Input>,
        file_only: bool,
    ) -> Result<(), String> {
        let app = self.clone();
        let (session_id, current, endpoint, target) = (
            id.to_owned(),
            generation.to_owned(),
            (host.host.clone(), host.port),
            host.target(),
        );
        let verifier = VerifyKey(Box::new(move |fingerprint, algorithm| {
            let (send, receive) = oneshot::channel();
            let mut data = app.inner.lock().unwrap();
            let known = data.trusted.get(&Host::system_endpoint(&endpoint.0,endpoint.1)).or_else(||data.host_keys.get(&endpoint)).cloned();
            if let Some(session) = data
                .sessions
                .get_mut(&session_id)
                .filter(|s| s.generation == current)
            {
                if known.as_deref() == Some(fingerprint.as_str()) {
                    let _ = send.send(true);
                } else if session.status == "connecting" {
                    session.status = "host-key";
                    session.trust =
                        Some(json!({"fingerprint": fingerprint, "algorithm": algorithm,
                        "target": target, "known": known}));
                    session.decision = Some(send);
                    drop(data);
                    app.changed();
                }
            }
            receive
        }));
        let connection = tokio::time::timeout(Duration::from_secs(110), async {
            match auth {
                SessionAuth::Agent => ssh::open_agent(&host.host,host.port,&host.username,verifier).await,
                SessionAuth::FileKey(path, fingerprint) => {
                    ssh::open_key(&host.host, host.port, &host.username, &path, fingerprint).await
                }
                SessionAuth::Password(password) => {
                    ssh::open(&host.host, host.port, &host.username, password, verifier).await
                }
                SessionAuth::CloudKey(key) => {
                    ssh::open_private_key(&host.host, host.port, &host.username, *key, verifier)
                        .await
                }
            }
        })
        .await
        .map_err(|_| "Истекло время подключения к SSH.")??;
        let account_key=format!("{}/{}",Host::system_endpoint(&host.host,host.port),host.username);
        let uid=if host.username=="root" {Some(0)} else if file_only {
            // File-only services may close the transport on an exec request.
            self.inner.lock().unwrap().root_users.get(&account_key).copied().filter(|root|*root).map(|_|0)
        } else { ssh::remote_uid(&connection).await };
        if let Some(uid)=uid {
            let key=account_key;
            let mut data=self.inner.lock().unwrap();
            if data.root_users.insert(key,uid==0)!=Some(uid==0){
                let _=profiles::write_json(&self.profiles_path.with_file_name("server-root-users.json"),&data.root_users,false);
            }
        }
        if host.sudo || uid==Some(0) {
            use tauri_plugin_dialog::{DialogExt,MessageDialogButtons};
            let rights=if uid==Some(0){"У пользователя права root."}else{"Учётка помечена как sudo."};
            let (tx,rx)=oneshot::channel();
            self.handle.dialog().message(format!("{rights} Разрешить {} для {}?",if file_only{"SFTP"}else{"терминал"},host.target()))
                .title("Подтверждение доступа").buttons(MessageDialogButtons::OkCancelCustom("Разрешить".into(),"Отмена".into()))
                .show(move |yes|{let _=tx.send(yes);});
            if !rx.await.unwrap_or(false){return Err("Пользователь отменил подключение.".into());}
        }
        if file_only {
            let ftp=tokio::time::timeout(Duration::from_secs(15),ssh::sftp(&connection)).await.map_err(|_|"Нет ответа от SFTP.")??;
            {
                let mut data=self.inner.lock().unwrap();
                let session=data.sessions.get_mut(id).filter(|s|s.generation==generation).ok_or("Сеанс закрыт.")?;
                session.ftp=Some(Arc::new(ftp));
                session.connection=Some(connection.clone());
                session.status="ready";
            }
            self.changed();
            while !connection.is_closed() { tokio::time::sleep(Duration::from_secs(1)).await; }
            return Ok(());
        }
        ssh::terminal(
            &connection,
            rx,
            || {
                let mut data = self.inner.lock().unwrap();
                if let Some(session) = data
                    .sessions
                    .get_mut(id)
                    .filter(|s| s.generation == generation)
                {
                    session.status = "ready";
                    session.connection = Some(connection.clone());
                    let app=self.clone();
                    let probe=connection.clone();
                    let (sid,gen,server)=(id.to_owned(),generation.to_owned(),host.clone());
                    tauri::async_runtime::spawn(async move {
                        let Some(info)=ssh::detect_system(&probe).await else { return };
                        let mut state=app.inner.lock().unwrap();
                        if !state.sessions.get(&sid).is_some_and(|s|s.generation==gen) {return;}
                        let value=(Host::system_endpoint(&server.host,server.port),info);
                        if state.systems.get(&server.id)==Some(&value) {return;}
                        state.systems.insert(server.id,value);
                        let _=profiles::write_json(&app.profiles_path.with_file_name("server-systems.json"),&state.systems,false);
                        drop(state);
                        app.changed();
                    });
                }
                drop(data);
                self.changed();
            },
            |bytes| {
                let _ = self.handle.emit("sshnesh-data", (id, generation, bytes));
            },
        )
        .await
    }
}

fn random_id() -> String {
    Uuid::new_v4().to_string()
}
fn string(args: &[Value], n: usize) -> Result<&str, String> {
    args.get(n)
        .and_then(Value::as_str)
        .ok_or_else(|| "Некорректный параметр.".into())
}
fn read_arg<T: serde::de::DeserializeOwned>(args: &[Value], n: usize) -> Result<T, String> {
    serde_json::from_value(args.get(n).cloned().unwrap_or(Value::Null))
        .map_err(|_| "Некорректный параметр.".into())
}

async fn selected_folder(app: &App) -> Result<Option<PathBuf>, String> {
    #[cfg(desktop)]
    {
        use tauri_plugin_dialog::DialogExt;
        let (tx, rx) = oneshot::channel();
        app.handle.dialog().file().pick_folder(move |path| {
            let _ = tx.send(path);
        });
        Ok(rx
            .await
            .map_err(|e| e.to_string())?
            .and_then(|p| p.into_path().ok()))
    }
    #[cfg(mobile)]
    {
        let folder = app
            .handle
            .path()
            .app_data_dir()
            .map_err(|e| e.to_string())?
            .join("SFTP");
        tokio::fs::create_dir_all(&folder)
            .await
            .map_err(|e| e.to_string())?;
        Ok(Some(folder))
    }
}

async fn local_path(root: &Path, relative: &str) -> Result<PathBuf, String> {
    if relative.contains(['\\', ':'])
        || Path::new(relative)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("Путь выходит за пределы выбранной папки.".into());
    }
    let mut path = root.to_owned();
    for part in Path::new(relative).components() {
        path.push(part);
        if tokio::fs::symlink_metadata(&path)
            .await
            .map_err(|e| e.to_string())?
            .is_symlink()
        {
            return Err("Символьные ссылки не поддерживаются.".into());
        }
    }
    let path = tokio::fs::canonicalize(path)
        .await
        .map_err(|e| e.to_string())?;
    if !path.starts_with(root) {
        return Err("Путь выходит за пределы выбранной папки.".into());
    }
    Ok(path)
}

fn folder(app: &App, scope: &str) -> Result<PathBuf, String> {
    app.inner
        .lock()
        .unwrap()
        .folder
        .as_ref()
        .filter(|(token, _)| token == scope)
        .map(|(_, path)| path.clone())
        .ok_or_else(|| "Заново выберите локальную папку.".into())
}

fn connection(app: &App, id: &str, generation: &str) -> Result<Connection, String> {
    let data = app.inner.lock().unwrap();
    App::input_session(&data, id, generation)?
        .connection
        .clone()
        .ok_or("SSH-соединение закрыто.".into())
}

async fn file_channel(app:&App,id:&str,generation:&str)->Result<Arc<russh_sftp::client::SftpSession>,String>{
    if let Some(ftp)=app.inner.lock().unwrap().sessions.get(id).filter(|s|s.generation==generation).and_then(|s|s.ftp.clone()){return Ok(ftp);}
    ssh::sftp(&connection(app,id,generation)?).await.map(Arc::new)
}

fn remote_name(path: &str) -> Result<&str, String> {
    let name = path.rsplit('/').next().unwrap_or("");
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['\\', ':', '\0']) {
        return Err("Имя файла не поддерживается.".into());
    }
    Ok(name)
}

async fn sftp_action(app: &App, action: &str, args: &[Value]) -> Result<Value, String> {
    use russh_sftp::protocol::OpenFlags;
    use tokio::{
        fs,
        io::{self, AsyncWriteExt},
    };
    match action {
        "defaultLocal" => {
            let root=app.handle.path().document_dir().map_err(|e|e.to_string())?;
            #[cfg(mobile)]
            let root=if fs::read_dir(&root).await.is_ok(){root}else{app.handle.path().app_data_dir().map_err(|e|e.to_string())?.join("Documents")};
            fs::create_dir_all(&root).await.map_err(|e|e.to_string())?;
            let root=fs::canonicalize(root).await.map_err(|e|e.to_string())?;
            let key=string(args,0)?;
            let file=app.profiles_path.with_file_name("sftp-roots.json");
            let saved:HashMap<String,PathBuf>=std::fs::File::open(file).ok().and_then(|f|serde_json::from_reader(f).ok()).unwrap_or_default();
            let root=match saved.get(key) {Some(path)=>fs::canonicalize(path).await.ok().filter(|p|p.is_dir()).unwrap_or(root),None=>root};
            let scope=random_id();app.inner.lock().unwrap().folder=Some((scope.clone(),root));
            Ok(json!(scope))
        }
        "chooseLocal" => {
            let Some(selected) = selected_folder(app).await? else {
                return Ok(Value::Null);
            };
            let root = fs::canonicalize(selected)
                .await
                .map_err(|e| e.to_string())?;
            let scope = random_id();
            let mut data=app.inner.lock().unwrap();
            if let Some(key)=args.first().and_then(Value::as_str) {
                let file=app.profiles_path.with_file_name("sftp-roots.json");
                let mut saved:HashMap<String,PathBuf>=std::fs::File::open(&file).ok().and_then(|f|serde_json::from_reader(f).ok()).unwrap_or_default();
                saved.insert(key.into(),root.clone());
                profiles::write_json(&file,&saved,true).map_err(|e|e.to_string())?;
            }
            data.folder = Some((scope.clone(), root));
            Ok(json!(scope))
        }
        "listLocal" => {
            let root = folder(app, string(args, 0)?)?;
            let dir = string(args, 1)?;
            let path = local_path(&root, dir).await?;
            let mut iter = fs::read_dir(&path).await.map_err(|e| e.to_string())?;
            let mut entries = Vec::new();
            while let Some(item) = iter.next_entry().await.map_err(|e| e.to_string())? {
                if entries.len() == 5001 {
                    break;
                }
                let kind = item.file_type().await.map_err(|e| e.to_string())?;
                let name = item.file_name();
                if let Some(name) = name.to_str() {
                    entries.push(json!({"name":name,"kind":if kind.is_dir() {"dir"} else if kind.is_file() {"file"}
                        else if kind.is_symlink() {"link"} else {"other"}}));
                }
            }
            let truncated = entries.len() > 5000;
            entries.truncate(5000);
            Ok(
                json!({"dir":dir,"label":path.to_string_lossy(),"entries":entries,"truncated":truncated}),
            )
        }
        "listFiles" => {
            let ftp = file_channel(app, string(args, 0)?, string(args, 1)?).await?;

            let dir = ftp
                .canonicalize(string(args, 2)?)
                .await
                .map_err(|e| e.to_string())?;
            let listing = ftp.read_dir(&dir).await.map_err(|e| e.to_string())?;
            let mut entries: Vec<_> = listing.take(5001).map(|item| {
                let kind = item.file_type();
                json!({"name":item.file_name(), "kind": if kind.is_dir() {"dir"} else if kind.is_file() {"file"}
                    else if kind.is_symlink() {"link"} else {"other"}, "bytes":item.metadata().size.unwrap_or(0)})
            }).collect();
            let truncated = entries.len() > 5000;
            entries.truncate(5000);
            Ok(json!({"dir":dir,"entries":entries,"truncated":truncated}))
        }
        "transferFile" => {
            let direction = string(args, 0)?;
            let ftp = file_channel(app, string(args, 1)?, string(args, 2)?).await?;
            let root = folder(app, string(args, 3)?)?;
            let local = local_path(&root, string(args, 4)?).await?;
            let remote = string(args, 5)?;

            match direction {
                "upload" => {
                    let mut from = fs::File::open(&local).await.map_err(|e| e.to_string())?;
                    if !from.metadata().await.map_err(|e| e.to_string())?.is_file() {
                        return Err("Выберите обычный файл.".into());
                    }
                    let name = local
                        .file_name()
                        .and_then(|s| s.to_str())
                        .ok_or("Не удалось прочитать имя файла.")?;
                    let target = format!("{}/{}", remote.trim_end_matches('/'), name);
                    let mut to = ftp
                        .open_with_flags(
                            target,
                            OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                        )
                        .await
                        .map_err(|e| format!("Не удалось создать файл без перезаписи: {e}"))?;
                    io::copy(&mut from, &mut to)
                        .await
                        .map_err(|e| e.to_string())?;
                    to.shutdown().await.map_err(|e| e.to_string())?;
                }
                "download" => {
                    let name = remote_name(remote)?;
                    let attributes = ftp
                        .symlink_metadata(remote)
                        .await
                        .map_err(|e| e.to_string())?;
                    if !attributes.file_type().is_file() {
                        return Err("Выберите обычный файл без ссылки.".into());
                    }
                    let mut from = ftp.open(remote).await.map_err(|e| e.to_string())?;
                    let mut to = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(local.join(name))
                        .await
                        .map_err(|e| format!("Не удалось создать файл без перезаписи: {e}"))?;
                    io::copy(&mut from, &mut to)
                        .await
                        .map_err(|e| e.to_string())?;
                    to.sync_all().await.map_err(|e| e.to_string())?;
                }
                _ => return Err("Неизвестное направление передачи.".into()),
            }
            Ok(Value::Null)
        }
        _ => Err("Неизвестная операция SFTP.".into()),
    }
}

#[tauri::command]
async fn dispatch(
    action: String,
    args: Vec<Value>,
    state: State<'_, App>,
) -> Result<Value, String> {
    let app = state.inner();
    app.inner.lock().unwrap().oauth.restore_login(app);
    match action.as_str() {
        #[cfg(not(mobile))]
        "mcpSecret" => {
            let id=string(&args,0)?;
            let answer=app.inner.lock().unwrap().mcp_secrets.remove(id).ok_or("Запрос закрыт.")?;
            let _=answer.send(args.get(1).and_then(Value::as_str).map(|s|Zeroizing::new(s.to_owned())));
        }
        #[cfg(not(mobile))]
        "mcpDecision" => {
            let id=string(&args,0)?;
            let yes=read_arg::<bool>(&args,1)?;
            let pending=app.inner.lock().unwrap().mcp_approvals.remove(id).ok_or("Запрос уже закрыт.")?;
            let _=pending.send(yes);
        }
        "state" => return Ok(app.snapshot()),
        "terminalSettings" => {
            let settings: TerminalSettings = read_arg(&args, 0)?;
            if !settings.valid() {
                return Err(
                    "Укажите размер шрифта от 10 до 30 и историю от 100 до 10 000 строк.".into(),
                );
            }
            let mut data = app.inner.lock().unwrap();
            profiles::write_json(
                &app.profiles_path.with_file_name("terminal-settings.json"),
                &settings,
                true,
            )
            .map_err(|e| e.to_string())?;
            data.settings = settings;
            drop(data);
            app.changed();
        }
        "syncLogin" => {
            crate::oauth::start(app)?;
            return Ok(json!(false));
        }
        "syncCancel" => crate::oauth::cancel(app)?,
        "syncLogout" => crate::oauth::logout(app).await?,
        "syncTransfer" => {
            let mode = string(&args, 0)?;
            let password = Zeroizing::new(read_arg::<String>(&args, 1)?);
            crate::cloud::load(
                app,
                mode,
                password,
                args.get(2).cloned().unwrap_or(Value::Null),
            )
            .await?;
            return Ok(json!(true));
        }
        "forgetDeviceKey" => crate::cloud::forget(app)?,
        "cloudLock" => {
            let mut data = app.inner.lock().unwrap();
            if data.cloud_loading {
                return Err("Дождитесь открытия хранилища.".into());
            }
            #[cfg(not(mobile))]
            if args.first().and_then(Value::as_str)!=Some("background"){data.mcp_connections.clear(); data.chat_grants.clear(); data.grant_epoch=data.grant_epoch.wrapping_add(1);}
            data.cloud = None;
            data.cloud_owner = None;
            drop(data);
            app.changed();
        }
        "exportKey" => {
            use tauri_plugin_dialog::DialogExt;
            use std::io::Write;
            let (raw, comment) = {
                let data=app.inner.lock().unwrap();
                let key=data.cloud.as_ref().and_then(|v|v.keys.get(args.first()?.as_str()?)).ok_or("Откройте хранилище ключей.")?;
                (key.secret()?, key.comment.clone())
            };
            let options=args.get(1).ok_or("Выберите параметры экспорта.")?;
            let phrase=match options["mode"].as_str() {
                Some("plain") => None,
                Some("encrypted") => Some(options["new"].as_str().ok_or("Введите парольную фразу.")?),
                _ => return Err("Выберите формат экспорта.".into()),
            };
            let bytes=crate::portable_key::export(&raw,options["old"].as_str(),phrase,comment.as_deref())?;
            let (tx,rx)=oneshot::channel();
            app.handle.dialog().file().set_file_name("sshnesh-key").save_file(move |path| {let _=tx.send(path);});
            let Some(path)=rx.await.map_err(|e|e.to_string())? else {return Ok(json!(false));};
            #[cfg(desktop)] {
                let target=path.into_path().map_err(|e|e.to_string())?;
                let mut file=tempfile::NamedTempFile::new_in(target.parent().ok_or("Выберите папку.")?).map_err(|e|e.to_string())?;
                file.write_all(bytes.as_bytes()).and_then(|_|file.as_file().sync_all()).map_err(|e|e.to_string())?;
                file.persist(target).map_err(|e|e.to_string())?;
            }
            #[cfg(target_os="android")] {
                use tauri_plugin_fs::{FsExt,OpenOptions};
                let mut opts=OpenOptions::new();
                opts.write(true).truncate(true).create(true);
                let mut file=app.handle.fs().open(path,opts).map_err(|e|e.to_string())?;
                file.write_all(bytes.as_bytes()).and_then(|_|file.flush()).map_err(|e|e.to_string())?;
            }
            return Ok(json!(true));
        }
        "copyPublicKey" => {
            use tauri_plugin_clipboard_manager::ClipboardExt;
            let public = {
                let data = app.inner.lock().unwrap();
                data.cloud
                    .as_ref()
                    .and_then(|vault| vault.keys.get(string(&args, 0).ok()?))
                    .ok_or("Сначала откройте хранилище ключей.")?
                    .public()
            };
            app.handle
                .clipboard()
                .write_text(public)
                .map_err(|e| e.to_string())?;
        }
        #[cfg(not(mobile))]
        "mcpOnStartup" => {
            let enabled = read_arg::<bool>(&args, 0)?;
            let mut data = app.inner.lock().unwrap();
            profiles::set_mcp_enabled(&app.profiles_path, enabled).map_err(|e| e.to_string())?;
            if !enabled {data.mcp_connections.clear(); data.chat_grants.clear(); data.grant_epoch=data.grant_epoch.wrapping_add(1);}
            data.mcp_enabled = enabled;
            drop(data);
            app.changed();
        }
        #[cfg(not(mobile))]
        "activeSelection" | "activeContextEnabled" => {
            let mut data = app.inner.lock().unwrap();
            let active = data.active.as_mut().ok_or("Окно SSHnesh закрыто.")?;
            if action == "activeSelection" {
                let sequence: u64 = read_arg(&args, 0)?;
                if sequence <= active.sequence {
                    return Ok(Value::Null);
                }
                active.sequence = sequence;
                let selection: Option<(String, String)> = read_arg(&args, 1)?;
                if active.selection != selection {
                    active.selection = selection;
                    active.touched = crate::active::now();
                }
            } else {
                active.enabled = read_arg(&args, 0)?;
                active.touched = crate::active::now();
            }
            App::refresh_context(&data).map_err(|e| e.to_string())?;
            drop(data);
            if action == "activeContextEnabled" {
                app.changed();
            }
        }
        "serverAccounts" | "saveServerAccounts" => {
            let id = string(&args, 0)?;
            let mut data = app.inner.lock().unwrap();
            let local = data.hosts.iter().find(|host| host.id == id);
            let vault = data.cloud.as_ref();
            let visible = local.filter(|h| !vault.is_some_and(|v|v.matches_device(json!(h)))).cloned();
            let host = visible.or_else(||vault?.entry(id).as_ref().map(Host::from_entry)).ok_or("Сервер не найден.")?;
            let mut items = profiles::read(&app.profiles_path)?;
            let index = items.iter().position(|p| p.id == id);
            if action == "serverAccounts" {
                if let Some(i) = index.filter(|&i| items[i].host==host.host && items[i].port==host.port) {
                    return Ok(json!(items[i]));
                }
                return Ok(
                    json!({"fingerprint":data.trusted.get(&Host::system_endpoint(&host.host,host.port)).or_else(||data.host_keys.get(&(host.host, host.port))),"debug":null,"admin":null}),
                );
            }
            let mut p: Profile = serde_json::from_value(json!({
                "id":host.id,"label":host.label,"host":host.host,"port":host.port,
                "fingerprint":args.get(1),"debug":args.get(2),"admin":args.get(3),"vaultOnly":local.is_none()
            }))
            .map_err(|e| e.to_string())?;
            p.fingerprint = p.fingerprint.trim().to_owned();
            profiles::validate(&p)?;
            if let Some(i) = index {
                items[i] = p;
            } else {
                items.push(p);
            }
            profiles::write(&app.profiles_path, &items)?;
            data.host_keys
                .insert((host.host, host.port), string(&args, 1)?.trim().to_owned());
            return Ok(Value::Null);
        }
        #[cfg(not(mobile))]
        "config" => {
            use tauri_plugin_clipboard_manager::ClipboardExt;
            let exe = std::env::current_exe().map_err(|e| e.to_string())?;
            let path = exe.to_string_lossy();
            let quoted = if cfg!(windows) {
                format!("'{}'", path.replace('\'', "''"))
            } else {
                format!("'{}'", path.replace('\'', "'\"'\"'"))
            };
            let command = format!("codex mcp add sshnesh -- {quoted} --mcp");
            app.handle
                .clipboard()
                .write_text(command)
                .map_err(|e| e.to_string())?;
        }
        "defaultLocal" | "chooseLocal" | "listLocal" | "listFiles" | "transferFile" => {
            return tokio::time::timeout(
                Duration::from_secs(120),
                sftp_action(app, &action, &args),
            )
            .await
            .map_err(|_| "Истекло время операции SFTP. Проверьте файл назначения.")?;
        }
        "copy" => {
            use tauri_plugin_clipboard_manager::ClipboardExt;
            app.handle
                .clipboard()
                .write_text(string(&args, 0)?)
                .map_err(|e| e.to_string())?;
        }
        "save" => {
            let mut host: Host = read_arg(&args, 0)?;
            if !matches!(host.auth.as_str(),"password"|"key"|"agent") || (host.auth=="key" && host.key_id.as_deref().unwrap_or("").is_empty()) || host.username.trim().is_empty() {
                return Err("Выберите способ входа и укажите пользователя.".into());
            }
            if host.port == 0 || host.host.trim().is_empty() || host.label.trim().is_empty() {
                return Err("Укажите название, адрес и порт сервера.".into());
            }
            if host.auth!="key" {host.key_id=None;}
            let mut data = app.inner.lock().unwrap();
            if host.id.is_empty() {
                host.id = random_id();
            }
            let id = host.id.clone();
            let mut saved = data.hosts.clone();
            saved.retain(|entry| entry.id != id);
            saved.push(host.clone());
            if let Some(index) = data.hosts.iter().position(|item| item.id == id) {
                let previous = &data.hosts[index];
                let mut items = profiles::read(&app.profiles_path)?;
                if let Some(i) = items.iter().position(|p| p.id == id) {
                    if previous.host != host.host || previous.port != host.port {
                        items.remove(i);
                    } else {
                        items[i].label = host.label.clone();
                        profiles::validate(&items[i])?;
                    }
                    profiles::write(&app.profiles_path, &items)?;
                }
                if previous.host != host.host
                    || previous.port != host.port
                    || previous.auth != host.auth
                    || previous.username != host.username
                {
                    data.passwords.remove(&id);
                }
                profiles::write_json(
                    &app.profiles_path.with_file_name("local-servers.json"),
                    &saved,
                    true,
                )
                .map_err(|e| e.to_string())?;
                data.hosts[index] = host;
            } else {
                profiles::write_json(
                    &app.profiles_path.with_file_name("local-servers.json"),
                    &saved,
                    true,
                )
                .map_err(|e| e.to_string())?;
                data.hosts.push(host);
            }
            drop(data);
            app.changed();
            return Ok(json!(id));
        }
        "setPassword" | "clearPassword" | "deleteHost" => {
            let id = string(&args, 0)?;
            let mut data = app.inner.lock().unwrap();
            if action == "setPassword" {
                if !data.hosts.iter().any(|host| host.id == id) {
                    return Err("Сервер не найден.".into());
                }
                data.passwords
                    .insert(id.to_owned(), Zeroizing::new(read_arg(&args, 1)?));
            } else {
                data.passwords.remove(id);
                if action == "deleteHost" {
                    let mut items = profiles::read(&app.profiles_path)?;
                    let count = items.len();
                    items.retain(|p| p.id != id);
                    if items.len() != count {
                        profiles::write(&app.profiles_path, &items)?;
                    }
                    let mut saved = data.hosts.clone();
                    saved.retain(|host| host.id != id);
                    profiles::write_json(
                        &app.profiles_path.with_file_name("local-servers.json"),
                        &saved,
                        true,
                    )
                    .map_err(|e| e.to_string())?;
                    data.hosts = saved;
                }
            }
            drop(data);
            app.changed();
        }
        "connect" | "reconnect" | "openSftp" => {
            let id = string(&args, 0)?;
            let data = app.inner.lock().unwrap();
            let file_only=action=="openSftp" || (action=="reconnect" && data.sessions.get(id).is_some_and(|s|s.file_only));
            let (host_id, role) = if action == "reconnect" {
                let prev = data.sessions.get(id).ok_or("Вкладка не найдена.")?;
                (prev.host.id.as_str(), prev.role.clone())
            } else {
                (id, args.get(1).and_then(Value::as_str).map(str::to_owned))
            };
            let local = data.hosts.iter().find(|host| host.id == host_id).cloned();
            let local = local.filter(|host| !data.cloud.as_ref().is_some_and(|v|v.matches_device(json!(host))));
            let role_host = matches!(role.as_deref(),Some("debug" | "admin"));
            let local = local.or_else(|| if role_host {
                data.cloud.as_ref()?.entry(host_id).as_ref().map(Host::from_entry)
            } else { None });
            {
                let picked = role
                    .as_deref()
                    .and_then(|role| role.strip_prefix("cloud-key:")).or_else(||local.as_ref().filter(|h|h.auth=="key" && role.is_none()).and_then(|h|h.key_id.as_deref()));
                let picked=picked.map(str::to_owned);
                let saved_login=role.as_deref().and_then(|r|r.strip_prefix("login:"));
                if local.is_none() || picked.is_some() || saved_login.is_some() {
                    let vault = data
                        .cloud
                        .as_ref()
                        .ok_or("Сначала откройте облачное хранилище.")?;
                    let (host, kind, key_id, entry) = if let Some(login)=saved_login {
                        let mut host=local.or_else(||vault.entry(host_id).as_ref().map(Host::from_entry)).ok_or("Сервер не найден.")?;
                        let entry=vault.saved_entry(host_id,&host.host,host.port,login)?;
                        host.sudo=entry.sudo;host.login_port=entry.login_port;host.username=entry.username.clone();host.auth=entry.auth.clone();host.key_id=entry.key_id.clone();
                        (host,entry.auth.clone(),entry.key_id.clone(),Some(entry))
                    }else if let Some(local) = local {
                        (local, "key".to_owned(), picked, None)
                    } else {
                        let entry = vault.entry(host_id).ok_or("Сервер не найден.")?;
                        let host = Host {
                            id: entry.id.clone(),
                            label: entry.label.clone(),
                            group: entry.group.clone(),
                            host: entry.host.clone(),
                            port: entry.port,
                            username: entry.username.clone(),
                            login_port:entry.login_port, sudo:entry.sudo, auth: entry.auth.clone(), key_id: entry.key_id.clone(),
                        };
                        (host, entry.auth.clone(), entry.key_id.clone(), Some(entry))
                    };
                    let cloud_auth = match kind.as_str() {
                        "agent" => SessionAuth::Agent,
                        "password" => SessionAuth::Password(vault.password(entry.as_ref().ok_or("Учётка не найдена.")?)?),
                        "key" => {
                            let key = vault.keys.get(key_id.as_deref().ok_or("Ключ не указан.")?).ok_or("Ключа нет в облачном хранилище.")?;
                            let phrase = args.get(if action == "reconnect" { 1 } else { 2 })
                                .and_then(Value::as_str).map(|text| Zeroizing::new(text.to_owned()));
                            let secret = key.secret()?;
                            let private = russh::keys::decode_secret_key(&secret, phrase.as_deref().map(String::as_str))
                                .map_err(|_| "Не удалось открыть SSH-ключ. Проверьте парольную фразу и формат ключа.")?;
                            let public = private.public_key().to_openssh().map_err(|_| "Некорректный ключ SSH.")?;
                            if !public.split_ascii_whitespace().take(2).eq(key.public().split_ascii_whitespace()) {
                                return Err("Приватный и публичный ключи не совпадают.".into());
                            }
                            SessionAuth::CloudKey(Box::new(private))
                        }
                        _ => return Err("Системный SSH-агент на Android недоступен. Выберите пароль или SSH-ключ.".into()),
                    };
                    drop(data);
                    return app
                        .connect(
                            host,
                            (action == "reconnect").then(|| id.to_owned()),
                            Some(cloud_auth),
                            role, file_only,
                        )
                        .map(|id| json!(id));
                }
            }
            let mut host = local.ok_or("Сервер не найден.")?;
            drop(data);
            let key = if let Some(role) = role.as_deref() {
                let p = profiles::read(&app.profiles_path)?
                    .into_iter()
                    .find(|p| p.id == host.id && p.host == host.host && p.port == host.port)
                    .ok_or("Учётка этого сервера больше не настроена.")?;
                let login = match role {
                    "debug" => p.debug,
                    "admin" => p.admin,
                    _ => None,
                }
                .ok_or("Учётка не настроена.")?;
                host.username = login.user;
                Some(SessionAuth::FileKey(login.key_path, p.fingerprint))
            } else if host.auth=="agent" {Some(SessionAuth::Agent)} else {
                None
            };
            return app
                .connect(
                    host,
                    (action == "reconnect").then(|| id.to_owned()),
                    key,
                    role, file_only,
                )
                .map(|id| json!(id));
        }
        "disconnect" | "remove" => {
            app.close(string(&args, 0)?, None, None, true, action == "remove")
        }
        "verify" => {
            let (id, generation, fingerprint, accept) = (
                string(&args, 0)?,
                string(&args, 1)?,
                string(&args, 2)?,
                read_arg::<bool>(&args, 3)?,
            );
            let mut data = app.inner.lock().unwrap();
            let session = data
                .sessions
                .get_mut(id)
                .filter(|s| {
                    s.generation == generation
                        && s.trust
                            .as_ref()
                            .and_then(|trust| trust["fingerprint"].as_str())
                            == Some(fingerprint)
                })
                .ok_or("Срок проверки ключа истёк.")?;
            let previous=session.trust.as_ref().and_then(|t|t["known"].as_str()).map(str::to_owned);
            let decision = session
                .decision
                .take()
                .ok_or("Срок проверки ключа истёк.")?;
            session.trust = None;
            session.status = "connecting";
            let endpoint = (session.host.host.clone(), session.host.port);
            if accept {
                let key=Host::system_endpoint(&endpoint.0,endpoint.1);
                let known=data.trusted.get(&key).or_else(||data.host_keys.get(&endpoint));
                if known!=previous.as_ref() && known.map(String::as_str)!=Some(fingerprint){return Err("Ключ сервера изменился, повторите подключение.".into());}
                let mut saved=data.trusted.clone();saved.insert(key,fingerprint.to_owned());
                profiles::write_json(&app.profiles_path.with_file_name("trusted-hosts.json"),&saved,true).map_err(|e|e.to_string())?;
                data.trusted=saved;
                data.host_keys.insert(endpoint, fingerprint.to_owned());
            }
            let _ = decision.send(accept);
            drop(data);
            app.changed();
        }
        "input" | "resize" => {
            let data = app.inner.lock().unwrap();
            if let Ok(session) = App::input_session(&data, string(&args, 0)?, string(&args, 1)?) {
                let input = if action == "input" {
                    let text = string(&args, 2)?;
                    if text.len() > 65_536 {
                        return Err("Слишком длинный ввод.".into());
                    }
                    Input::Text(text.to_owned())
                } else {
                    let (cols, rows): (u32, u32) = (read_arg(&args, 2)?, read_arg(&args, 3)?);
                    if !(1..=1000).contains(&cols) || !(1..=1000).contains(&rows) {
                        return Ok(Value::Null);
                    }
                    Input::Resize(cols, rows)
                };
                if let Some(tx) = &session.input {
                    tx.try_send(input)
                        .map_err(|_| "Терминал занят. Повторите ввод.".to_string())?;
                }
            }
        }
        _ => return Err("Эта функция пока не перенесена в прототип Tauri.".into()),
    }
    Ok(Value::Null)
}

pub(crate) fn run() {
    let builder = tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_clipboard_manager::init());
    let builder = builder.plugin(tauri_plugin_opener::init());
    #[cfg(target_os = "android")]
    let builder = builder.plugin(tauri_plugin_fs::init()).plugin(tauri_plugin_deep_link::init()).plugin(tauri::plugin::Builder::<tauri::Wry, ()>::new("vaultdevice")
        .setup(|app,api| { app.manage(api.register_android_plugin("ru.xelopat.sshnesh.preview","VaultPlugin")?); Ok(()) }).build());
    builder
        .setup(|handle| {
            #[cfg(not(mobile))]
            let path = profiles::desktop_file().map_err(std::io::Error::other)?;
            #[cfg(mobile)]
            let path = handle.path().app_config_dir()?.join("connectors.json");
            let mut inner = Inner::default();
            inner.root_users=std::fs::File::open(path.with_file_name("server-root-users.json")).ok().and_then(|f|serde_json::from_reader(f).ok()).unwrap_or_default();
            let pins=path.with_file_name("trusted-hosts.json");
            if pins.try_exists()? {inner.trusted=serde_json::from_reader(std::fs::File::open(pins)?)?;}
            inner.systems = std::fs::File::open(path.with_file_name("server-systems.json")).ok()
                .and_then(|file|serde_json::from_reader(file).ok()).unwrap_or_default();
            inner.settings = TerminalSettings::read(&path);
            {
                inner.oauth = crate::oauth::Auth::load(&path);
            }
            #[cfg(not(mobile))]
            {
                crate::active::prune(&path);
                inner.mcp_enabled = profiles::mcp_enabled(&path).unwrap_or(false);
                inner.active = Some(crate::active::Window::new(&path));
            }
            for p in profiles::read(&path).map_err(std::io::Error::other)? {
                inner
                    .host_keys
                    .insert((p.host.clone(), p.port), p.fingerprint);
                if p.vault_only { continue; }
                inner.hosts.push(Host {
                    id: p.id,
                    group: String::new(),
                    label: p.label,
                    host: p.host,
                    port: p.port,
                    username: p
                        .debug
                        .or(p.admin)
                        .map_or_else(|| "debug".into(), |a| a.user),
                    login_port:None, sudo:false, auth: "password".into(), key_id:None,
                });
            }
            match std::fs::File::open(path.with_file_name("local-servers.json")) {
                Ok(file) => {
                    let saved: Vec<Host> = serde_json::from_reader(file)?;
                    for host in saved {
                        inner.hosts.retain(|entry| entry.id != host.id);
                        inner.hosts.push(host);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e.into()),
            }
            let state = App {
                handle: handle.handle().clone(),
                inner: Arc::new(Mutex::new(inner)),
                profiles_path: path,
            };
            #[cfg(not(mobile))]
            {
                app_mcp::start(state.clone())?;
                let _ = App::refresh_context(&state.inner.lock().unwrap());
                let data = Arc::downgrade(&state.inner);
                tauri::async_runtime::spawn(async move {
                    let mut tick = tokio::time::interval(Duration::from_secs(2));
                    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                    loop {
                        tick.tick().await;
                        let Some(data) = data.upgrade() else {
                            break;
                        };
                        let data = data.lock().unwrap();
                        if data.active.as_ref().is_none_or(|window| window.closed) {
                            break;
                        }
                        let _ = App::refresh_context(&data);
                    }
                });
            }
            handle.manage(state.clone());
            crate::oauth::attach(state);
            Ok(())
        })
        .on_window_event(|_window, _event| {
            #[cfg(not(mobile))]
            if let Some(app) = _window.try_state::<App>() {
                let mut data = app.inner.lock().unwrap();
                if let Some(active) = data.active.as_mut() {
                    match _event {
                        tauri::WindowEvent::Focused(true) => {
                            active.touched = crate::active::now();
                            let _ = App::refresh_context(&data);
                        }
                        tauri::WindowEvent::Destroyed => active.close(),
                        _ => {}
                    }
                }
            }
        })
        .invoke_handler(tauri::generate_handler![dispatch])
        .run(tauri::generate_context!())
        .expect("Не удалось запустить прототип SSHnesh");
}
