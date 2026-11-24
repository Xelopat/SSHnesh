use super::*;
use crate::{active, mcp};

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

tokio::task_local! { static STAGES: mpsc::UnboundedSender<(&'static str,u64)>; }
fn stage(message:&'static str, seconds:u64) {
    let _=STAGES.try_with(|tx|tx.send((message,seconds)));
}
fn remote_dir(s:&str)->&str {
    if !s.is_empty() && s.bytes().all(|b|b==b'/') { "/" } else { s.trim_end_matches('/') }
}

#[derive(Clone)]
pub(crate) struct Grant {
    card: Value,
    conn: Connection,
    client: String,
    thread: Option<Uuid>,
    local: PathBuf,
    remote: String,
    requested_remote: String,
    login: String,
    port:u16,
    service: Option<String>,
}
fn display_directory(path: &Path) -> String {
    let path = path.to_string_lossy();
    #[cfg(windows)]
    if let Some(drive_path) = path.strip_prefix(r"\\?\") {
        if drive_path.as_bytes().get(1) == Some(&b':') {
            return drive_path.to_owned();
        }
    }
    path.into_owned()
}

async fn release_operation(
    conn: &Connection,
    action: &str,
    root: &str,
    unit: &str,
    extra: &[&str],
) -> Result<Value, String> {
    let quote = |s: &str| format!("'{}'", s.replace('\'', "'\"'\"'"));
    let script = include_str!("release.py").trim_start_matches('\u{feff}');
    let args = [action, root, unit]
        .into_iter()
        .chain(extra.iter().copied())
        .map(quote)
        .collect::<Vec<_>>()
        .join(" ");
    let reply = mcp::run(
        conn,
        format!("/usr/bin/python3 -I -c {} {args}", quote(script)),
        None,
    )
    .await?;
    if reply["exitCode"] != 0 {
        return Err(format!(
            "Операция релиза не выполнена: {}",
            reply["stderr"].as_str().unwrap_or("").trim()
        ));
    }
    serde_json::from_str(reply["stdout"].as_str().unwrap_or(""))
        .map_err(|_| "Сервер вернул неполный результат проверки релиза.".into())
}
async fn project_listing(grant: &Grant, directory: Option<&str>) -> Result<Value, String> {
    let ftp = ssh::sftp(&grant.conn).await?;
    let root = ftp
        .canonicalize(&grant.remote)
        .await
        .map_err(|e| e.to_string())?;
    let request = match directory {
        None => root.clone(),
        Some(s) if s.starts_with('/') => s.to_owned(),
        Some(s) => format!("{}/{s}",root.trim_end_matches('/')),
    };
    let dir = ftp.canonicalize(request).await.map_err(|e| e.to_string())?;
    if dir != root && !dir.starts_with(&(root.trim_end_matches('/').to_owned() + "/")) {
        return Err("Папка находится вне проекта.".into());
    }
    let mut entries:Vec<_>=ftp.read_dir(&dir).await.map_err(|e|e.to_string())?.take(1001).map(|item|{
        let kind=item.file_type();
        json!({"name":item.file_name(),"type":if kind.is_dir(){"directory"}else if kind.is_file(){"file"}else if kind.is_symlink(){"link"}else{"other"},"bytes":item.metadata().size})
    }).collect();
    let truncated = entries.len() > 1000;
    entries.truncate(1000);
    Ok(json!({"root":root,"directory":dir,"entries":entries,"truncated":truncated}))
}

pub(super) fn start(app: App) -> std::io::Result<()> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let token = Uuid::new_v4().to_string();
    profiles::write_json(
        &app.profiles_path.with_file_name("mcp-window.json"),
        &json!({"port":listener.local_addr()?.port(),"token":token}),
        false,
    )?;
    tauri::async_runtime::spawn(async move {
        let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
            return;
        };
        let slots = Arc::new(tokio::sync::Semaphore::new(8));
        while let Ok((socket, _)) = listener.accept().await {
            let Ok(slot) = slots.clone().try_acquire_owned() else {
                continue;
            };
            let (app, token) = (app.clone(), token.clone());
            tauri::async_runtime::spawn(async move {
                let _slot = slot;
                let (read, mut write) = socket.into_split();
                let mut reader = BufReader::new(read).take(8192);
                let mut line = String::new();
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(3), reader.read_line(&mut line)).await,
                    Ok(Ok(_))
                ) || !line.ends_with('\n')
                {
                    return;
                }
                let Ok(req) = serde_json::from_str::<Value>(&line) else {
                    return;
                };
                if req["token"].as_str() != Some(&token) {
                    return;
                }
                if req["name"] == "client_session" {
                    let Some(client) = req["client"]
                        .as_str()
                        .filter(|s| Uuid::parse_str(s).is_ok())
                    else {
                        return;
                    };
                    drop(_slot);
                    if write.write_all(b"1").await.is_ok() {
                        let _ = reader.read(&mut [0]).await;
                    }
                    app.inner
                        .lock()
                        .unwrap()
                        .mcp_connections
                        .retain(|_, g| g.client != client);
                    return;
                }
                let mut disconnected = [0; 1];
                let (tx,mut stages)=mpsc::unbounded_channel();
                let task=STAGES.scope(tx,operate(&app,&req));
                tokio::pin!(task);
                let mut last="обработка запроса";
                let end=tokio::time::Instant::now()+Duration::from_secs(170);
                let mut deadline=end;
                let reply=loop {
                    tokio::select! {
                        _=reader.read(&mut disconnected)=>return,
                        result=&mut task=>break match result {Ok(v)=>json!({"result":v}),Err(e)=>json!({"error":e})},
                        Some((msg,secs))=stages.recv()=>{
                            last=msg;
                            if req["name"]=="connect_server" {deadline=end.min(tokio::time::Instant::now()+Duration::from_secs(secs));}
                            if req["progress"]==true {
                                let line=format!("{}\n",json!({"stage":msg}));
                                if write.write_all(line.as_bytes()).await.is_err(){return;}
                            }
                        },
                        _=tokio::time::sleep_until(deadline)=>break json!({"error":format!("Истекло время ожидания. Этап: {last}.")}),
                    }
                };
                let _ = write.write_all(reply.to_string().as_bytes()).await;
            });
        }
    });
    Ok(())
}

fn enabled(app: &App) -> Result<(), String> {
    if app.inner.lock().unwrap().mcp_enabled
        && profiles::mcp_enabled(&app.profiles_path).ok() == Some(true)
    {
        Ok(())
    } else {
        Err("MCP выключен в SSHnesh.".into())
    }
}

struct Approval<'a>(&'a App, String);
impl Drop for Approval<'_> {
    fn drop(&mut self) {
        let mut data = self.0.inner.lock().unwrap();
        data.mcp_approvals.remove(&self.1);
        data.mcp_secrets.remove(&self.1);
        drop(data);
        let _ = self.0.handle.emit("mcp-request-closed", &self.1);
    }
}
async fn confirm(app: &App, message: String) -> Result<(), String> {
    request(app, message, "approve").await
}
async fn request(app: &App, message: String, kind: &str) -> Result<(), String> {
    stage("Ожидается подтверждение в SSHnesh",90);
    let id = Uuid::new_v4().to_string();
    let (tx, rx) = oneshot::channel();
    app.inner
        .lock()
        .unwrap()
        .mcp_approvals
        .insert(id.clone(), tx);
    let _guard = Approval(app, id.clone());
    if let Some(window) = app.handle.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
    app.handle
        .emit(
            "mcp-request",
            json!({"id":id,"message":message,"kind":kind}),
        )
        .map_err(|e| e.to_string())?;
    if rx.await.unwrap_or(false) {
        enabled(app)
    } else {
        Err("Пользователь отклонил запрос MCP.".into())
    }
}

async fn secret(app: &App, message: String) -> Result<Zeroizing<String>, String> {
    stage("Ожидается ввод пароля в SSHnesh",100);
    let id = random_id();
    let (tx, rx) = oneshot::channel();
    app.inner.lock().unwrap().mcp_secrets.insert(id.clone(), tx);
    let _guard = Approval(app, id.clone());
    if let Some(window) = app.handle.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
    app.handle
        .emit(
            "mcp-request",
            json!({"id":id,"message":message,"kind":"secret"}),
        )
        .map_err(|e| e.to_string())?;
    let value = tokio::time::timeout(Duration::from_secs(110),rx).await
        .map_err(|_|"Истекло время ожидания ввода в окне SSHnesh.")?
        .map_err(|_|"Окно ввода SSHnesh закрылось до получения ответа.")?
        .ok_or("Пользователь отменил ввод в SSHnesh.")?;
    enabled(app)?;
    Ok(value)
}

fn logins(host: &Value) -> Vec<Value> {
    let mut list = vec![json!({"id":"default","loginPort":host["loginPort"],"user":host["username"],"sudo":host["sudo"]==true})];
    if let Some(items) = host["logins"].as_array() {
        list.extend(
            items
                .iter()
                .map(|l| json!({"id":l["loginId"],"loginPort":l["loginPort"],"user":l["username"],"sudo":l["sudo"]==true})),
        );
    }
    list
}

async fn confirm_chat_access(app: &App, scope: &Value, thread: Option<Uuid>, message: String) -> Result<(), String> {
    let Some(thread) = thread else { return confirm(app, message).await; };
    let key = json!([thread.to_string(),scope]).to_string();
    let (prompt, epoch) = {
        let data = app.inner.lock().unwrap();
        (data.chat_prompt.clone(), data.grant_epoch)
    };
    let _guard = prompt.lock().await;
    {
        let data = app.inner.lock().unwrap();
        if data.grant_epoch != epoch || !data.mcp_enabled { return Err("Доступ MCP отозван.".into()); }
        if data.chat_grants.contains(&key) { return Ok(()); }
    }
    confirm(app,format!("{message}\nРазрешение для чата {thread} распространяется на новые подключения SSH и SFTP к этой учётке.")).await?;
    let mut data = app.inner.lock().unwrap();
    if data.grant_epoch != epoch || !data.mcp_enabled { return Err("Доступ MCP отозван.".into()); }
    data.chat_grants.insert(key);
    Ok(())
}

async fn operate(app: &App, req: &Value) -> Result<Value, String> {
    enabled(app)?;
    let name = req["name"].as_str().ok_or("Укажите действие.")?;
    let args = &req["args"];
    let thread = req["thread"].as_str().and_then(|id|Uuid::parse_str(id).ok());
    stage("Подготовка сохранённой учётки",30);
    let epoch=app.inner.lock().unwrap().grant_epoch;
    let mut state = app.snapshot();
    if name != "disconnect_server" && state["sync"]["remembered"] == true
        && state["sync"]["unlocked"] != true
        && state["sync"]["busy"] != true
    {
        if crate::cloud::load(app, "unlock", Zeroizing::new(String::new()), json!({}))
            .await
            .is_ok()
        {
            state = app.snapshot();
        }
    }
    let mut hosts = state["hosts"]
        .as_array()
        .ok_or("Серверы недоступны.")?
        .clone();
    if state["sync"]["unlocked"] != true {
        let d = app.inner.lock().unwrap();
        for grant in d
            .mcp_connections
            .values()
            .filter(|g| Some(g.client.as_str()) == req["client"].as_str() && g.thread == thread && !g.conn.is_closed())
        {
            if !hosts.iter().any(|h| h["id"] == grant.card["id"]) {
                hosts.push(grant.card.clone());
            }
        }
    }
    if name == "request_unlock" {
        if state["sync"]["unlocked"] != true {
            if state["sync"]["cached"] != true {
                return Err("На устройстве пока нет сохранённого хранилища.".into());
            }
            let master = secret(app, "Мастер-пароль хранилища SSHnesh".into()).await?;
            crate::cloud::load(app, "unlock", master, json!({})).await?;
        }
        return Ok(json!({"unlocked":true}));
    }
    if name == "list_servers" {
        if hosts.is_empty() && state["sync"]["cached"] == true && state["sync"]["unlocked"] != true
        {
            return Err(
                "Хранилище закрыто. Вызовите request_unlock и повторите list_servers.".into(),
            );
        }
        return Ok(json!(hosts
            .iter()
            .map(|h| json!({"id":h["id"],"label":h["label"],"logins":logins(h)}))
            .collect::<Vec<_>>()));
    }
    if name=="active_server" && args["server"].is_null() && active::read(&app.profiles_path).is_err() {
        let d=app.inner.lock().unwrap();
        let mut grants=d.mcp_connections.values().filter(|g|!g.conn.is_closed() && g.thread==thread &&
            (thread.is_some() || req["client"].as_str()==Some(g.client.as_str())));
        if let Some(g)=grants.next() {
            if grants.next().is_none() {
                return Ok(json!({"id":g.card["id"],"label":g.card["label"],"login":g.login,"port":g.port,"remoteDirectory":g.remote,"source":"mcp_connection","logins":logins(&g.card)}));
            }
        }
        let mut files=d.sessions.values().filter(|s|s.file_only && s.status=="ready");
        if active::read(&app.profiles_path).is_err() {
            if let Some(s)=files.next() {if files.next().is_none() {
                return Ok(json!({"id":s.host.id,"label":s.host.label,"login":s.host.username,"port":s.host.port,"source":"sftp_session"}));
            }}
        }
    }
    let current;
    let server = if let Some(id) = args["server"].as_str() {
        id
    } else {
        current = active::read(&app.profiles_path)
            .map_err(|_| "Выберите сервер из list_servers и укажите его id.")?;
        if !hosts.iter().any(|h| {
            h["id"] == current.id && h["host"] == current.host
                && (h["port"] == current.port || h["loginPort"] == current.port
                    || h["logins"].as_array().is_some_and(|logins|logins.iter().any(|l|l["loginPort"] == current.port)))
        }) {
            return Err("Адрес активного сервера изменился.".into());
        }
        &current.id
    };
    let mut found = hosts
        .iter()
        .filter(|h| h["id"] == server || h["label"] == server);
    let card = found
        .next()
        .ok_or("Сервер не найден. Проверьте list_servers или откройте хранилище SSHnesh.")?;
    if found.next().is_some() {
        return Err("Укажите уникальный id сервера.".into());
    }
    if name == "active_server" {
        return Ok(json!({"id":card["id"],"label":card["label"],"logins":logins(card)}));
    }
    let mut host: Host =
        serde_json::from_value(card.clone()).map_err(|_| "Некорректный сервер.")?;
    let choices = logins(card);
    let id = args["login"].as_str().unwrap_or("default");
    let mut matches = choices.iter().filter(|l| l["id"] == id || l["user"] == id);
    let transient = json!({"id":"temporary-root","user":"root"});
    let login = matches
        .next()
        .or_else(|| (id == "root").then_some(&transient))
        .ok_or("Выберите вход из list_servers.")?;
    if matches.next().is_some() {
        return Err("Имя неоднозначно. Укажите id входа.".into());
    }
    let saved = login["id"].as_str().filter(|s| *s != "default");
    if saved == Some("temporary-root") {
        host.username = "root".into();
        host.auth = "prompt".into();
        host.key_id = None;
    } else if let Some(id) = saved {
        let l = card["logins"]
            .as_array()
            .and_then(|a| a.iter().find(|l| l["loginId"] == id))
            .ok_or("Вход удалён.")?;
        host.username = l["username"].as_str().unwrap_or("").into();
        host.auth = l["auth"].as_str().unwrap_or("").into();
        host.key_id = l["keyId"].as_str().map(str::to_owned);
    }
    let server_port = host.port;
    if saved != Some("temporary-root") {
        let port = if saved.is_none() { &card["loginPort"] } else { &login["loginPort"] };
        if let Some(port)=port.as_u64() { host.port=u16::try_from(port).ok().filter(|p|*p>0).ok_or("Недопустимый порт учётки.")?; }
    }
    let target = host.target();
    let client = req["client"]
        .as_str()
        .filter(|s| Uuid::parse_str(s).is_ok())
        .ok_or("Обновите MCP-клиент SSHnesh.")?;
    let known_root = host.username == "root" || card["rootUsers"].as_array().is_some_and(|users| users.iter().any(|u| u.as_str()==Some(host.username.as_str())));
    let cache_id = json!([
        client, thread.map(|t|t.to_string()),
        host.id,
        host.host,
        host.port,
        host.username,
        host.auth,
        host.key_id,
        saved,
        login["sudo"]==true, known_root
    ])
    .to_string();
    if name == "disconnect_server" {
        let released = app
            .inner
            .lock()
            .unwrap()
            .mcp_connections
            .remove(&cache_id)
            .is_some();
        return Ok(json!({"released":released}));
    }
    let transfer = matches!(name, "sftp_upload" | "sftp_download" | "update_site_file" | "update_file");
    let paths = if transfer {
        Some(transfer_paths(args)?)
    } else {
        None
    };
    let mut command = if transfer
        || matches!(
            name,
            "check_site_config" | "connect_server" | "deploy_preflight" | "install_release" | "list_remote_files"
        ) {
        String::new()
    } else {
        mcp::diagnostic(name, args)?
    };
    let cached = app
        .inner
        .lock()
        .unwrap()
        .mcp_connections
        .get(&cache_id)
        .filter(|g| !g.conn.is_closed())
        .cloned();
    let reusing = cached.is_some();
    let grant = if let Some(g) = cached {
        if args["localDirectory"]
            .as_str()
            .is_some_and(|s| Path::new(s).canonicalize().ok().as_ref() != Some(&g.local))
            || args["remoteDirectory"]
                .as_str()
                .is_some_and(|s| remote_dir(s) != g.remote && remote_dir(s) != g.requested_remote)
            || args["service"]
                .as_str()
                .is_some_and(|s| Some(s) != g.service.as_deref())
        {
            return Err("Для смены папки или службы завершите сессию через disconnect_server и подключитесь снова.".into());
        }
        g
    } else {
        let local = if let Some(s) = args["localDirectory"].as_str() {
            PathBuf::from(s)
        } else if let Some((path, _)) = paths {
            path.parent().ok_or("Укажите папку.")?.to_owned()
        } else {
            app.handle
                .path()
                .document_dir()
                .map_err(|e| e.to_string())?
        };
        if !local.is_absolute() || local.to_string_lossy().starts_with(r"\") {
            return Err("Укажите папку на локальном диске.".into());
        }
        let local = local
            .canonicalize()
            .map_err(|_| "Локальная папка не найдена. Укажите localDirectory при подключении.")?;
        if !local.is_dir() || local.parent().is_none() {
            return Err("Выберите локальную папку проекта.".into());
        }
        let mut remote = remote_dir(args["remoteDirectory"]
            .as_str()
            .or_else(|| paths.and_then(|(_, p)| p.rsplit_once('/').map(|(dir,_)|if dir.is_empty(){"/"}else{dir})))
            .unwrap_or("."))
            .to_owned();
        let requested_remote=remote.clone();
        if remote != "."
            && (!remote.starts_with('/')
                || remote.split('/').any(|s| s == ".." || s == ".")
                || remote.chars().any(char::is_control))
        {
            return Err("Укажите абсолютный путь к папке проекта на сервере.".into());
        }
        let service = args["service"]
            .as_str()
            .or_else(|| {
                (name == "restart_service")
                    .then(|| args["unit"].as_str())
                    .flatten()
            })
            .map(str::to_owned);
        if let Some(unit) = &service {
            mcp::diagnostic("restart_service", &json!({"unit":unit}))?;
        }
        let local_display = display_directory(&local);
        let infer_project = service.is_some() && args["remoteDirectory"].is_null() && remote == ".";
        let remote_display = if infer_project {
            "рабочая папка службы systemd"
        } else if remote == "." {
            "домашний каталог"
        } else {
            &remote
        };
        let service_display = service
            .as_deref()
            .map(|u| format!("\nПерезапуск службы: {u}"))
            .unwrap_or_default();
        let privileged = known_root || login["sudo"] == true;
        let scope = json!([host.id,host.host,host.port,host.username,host.auth,host.key_id,saved,local,known_root,login["sudo"]==true]);
        if privileged {
        let rights = if known_root { " (root)" } else if privileged { " (sudo)" } else { "" };
        confirm_chat_access(app,&scope,thread,format!("Подключиться к {} под именем {}{}?\nАдрес: {}:{}\nФайлы на устройстве: {}\nФайлы на сервере: {}{}",
            host.label,host.username,rights,host.host,host.port,local_display,remote_display,service_display)).await?;
        }
        stage("Соединение с SSH-сервером и аутентификация",30);
        let conn = connection(app, &host, server_port, saved, card["cloud"] == true).await?;
        if !privileged && !matches!(name, "connect_server" | "deploy_preflight" | "list_remote_files" | "sftp_upload" | "sftp_download" | "update_site_file") && ssh::remote_uid(&conn).await == Some(0) {
            confirm_chat_access(app,&json!([scope,"effective-root"]),thread,format!("Учётка {target} имеет UID 0. Разрешить подключение с правами root?")).await?;
        }
        if infer_project {
            let located =
                release_operation(&conn, "locate", ".", service.as_deref().unwrap(), &[]).await?;
            remote = located["workingDirectory"]
                .as_str()
                .filter(|s| s.starts_with('/') && *s != "/")
                .ok_or("Служба не указала рабочую папку. Укажите remoteDirectory.")?
                .to_owned();
        }
        if name=="connect_server" || matches!(name,"list_remote_files"|"deploy_preflight"|"sftp_upload"|"sftp_download"|"update_site_file") {
            stage("Проверка каталога через SFTP",25);
            let ftp=ssh::sftp(&conn).await?;
            let home=ftp.canonicalize(".").await.map_err(|e|format!("SFTP: не удалось определить домашний каталог: {e}"))?;
            let selected=if remote=="." {home.as_str()} else {remote.as_str()};
            let dir=ftp.canonicalize(selected).await.map_err(|e|format!("Каталог {selected} недоступен через SFTP. Домашний каталог этой учётки: {home}. {e}"))?;
            ftp.read_dir(&dir).await.map_err(|e|format!("Не удалось открыть каталог {dir} через SFTP. Домашний каталог этой учётки: {home}. {e}"))?;
            remote=remote_dir(&dir).to_owned();
        }
        Grant {
            requested_remote, login:host.username.clone(), port:host.port,
            card: card.clone(),
            conn,
            client: client.to_owned(),
            thread,
            local,
            remote,
            service,
        }
    };
    enabled(app)?;
    let latest = app.snapshot();
    let unchanged = latest["hosts"]
        .as_array()
        .and_then(|hs| hs.iter().find(|h| h["id"] == card["id"]))
        .is_some_and(|h| {
            if h["host"] != card["host"] || h["port"] != card["port"] { return false; }
            let fields=["username","auth","keyId","sudo","loginPort"];
            if let Some(id)=saved.filter(|id|*id!="temporary-root") {
                let find=|v:&Value| v["logins"].as_array().and_then(|items|items.iter().find(|l|l["loginId"]==id)).cloned();
                match (find(h),find(card)) {
                    (Some(a),Some(b))=>fields.iter().all(|f|a[*f]==b[*f]),
                    _=>false,
                }
            } else { fields.iter().all(|f| h[*f] == card[*f]) }
        });
    let active_grant = app
        .inner
        .lock()
        .unwrap()
        .mcp_connections
        .get(&cache_id)
        .is_some_and(|g| Arc::ptr_eq(&g.conn, &grant.conn));
    let background_lock=state["sync"]["unlocked"]==true && latest["sync"]["unlocked"]!=true
        && (card["cloud"]==true || saved.is_some())
        && latest["hosts"].as_array().into_iter().flatten().filter(|h|h["id"]==card["id"]).all(|h|h["host"]==card["host"] && h["port"]==card["port"]);
    if !unchanged && !background_lock && !(latest["sync"]["unlocked"] != true && active_grant) {
        return Err("Вход изменился во время запроса. Выберите сервер заново.".into());
    }
    {
        let mut d = app.inner.lock().unwrap();
        d.mcp_connections.retain(|_, g| !g.conn.is_closed());
        if d.mcp_connections.len() >= 16 && !d.mcp_connections.contains_key(&cache_id) {
            return Err("Закройте лишнее MCP-подключение.".into());
        }
        if !d.mcp_enabled || epoch!=d.grant_epoch
            || (reusing
                && !d
                    .mcp_connections
                    .get(&cache_id)
                    .is_some_and(|g| Arc::ptr_eq(&g.conn, &grant.conn)))
        {
            return Err("Разрешение на сессию отозвано.".into());
        }
        if !reusing {
            d.mcp_connections.insert(cache_id, grant.clone());
        }
    }
    let mut result = if name == "connect_server" {
        json!({"connected":true,"localDirectory":display_directory(&grant.local),"remoteDirectory":grant.remote,"service":grant.service})
    } else if name=="check_site_config" {
        let cmd=match args["elevation"].as_str() {
            None|Some("none")=>"/usr/sbin/apache2ctl configtest",
            Some("sudo") if host.username=="root"=>"/usr/sbin/apache2ctl configtest",
            Some("sudo") if login["sudo"]==true=>"/usr/bin/sudo -n -- /usr/sbin/apache2ctl configtest",
            Some("sudo")=>return Err("Для проверки через sudo выберите учётку с отметкой sudo и подтвердите подключение.".into()),
            _=>return Err("elevation: none или sudo.".into()),
        };
        mcp::run(&grant.conn,cmd.to_owned(),None).await?
    } else if name == "list_remote_files" {
        project_listing(&grant, args["directory"].as_str()).await?
    } else if name=="deploy_preflight" && grant.service.is_none() {
        use russh_sftp::protocol::{FileAttributes,OpenFlags};
        let ftp=Arc::new(ssh::sftp(&grant.conn).await?);
        let dir=ftp.canonicalize(&grant.remote).await.map_err(|e|format!("SFTP: не удалось открыть каталог: {e}"))?;
        let probe=format!("{}/.sshnesh-write-test-{}",dir.trim_end_matches('/'),random_id());
        let access=ftp.open_with_flags_and_attributes(probe.clone(),OpenFlags::WRITE|OpenFlags::CREATE|OpenFlags::EXCLUDE,FileAttributes{permissions:Some(0o600),..Default::default()}).await;
        let reasons=match access {
            Ok(mut file)=>{
                let mut cleanup=StagedUpload(ftp.clone(),Some(probe.clone()));
                file.shutdown().await.map_err(|e|e.to_string())?;
                ftp.remove_file(probe).await.map_err(|e|format!("Не удалось удалить тестовый файл: {e}"))?;
                cleanup.1.take();
                vec![]
            }
            Err(e)=>vec![format!("SFTP: не удалось создать файл в {dir}: {e}")],
        };
        json!({"mode":"website","ready":reasons.is_empty(),"writable":reasons.is_empty(),"projectDirectory":dir,"service":null,"reasons":reasons})
    } else if matches!(name, "deploy_preflight" | "install_release") {
        let unit = grant
            .service
            .as_deref()
            .ok_or("Подключитесь с названием службы в параметре service.")?;
        if name == "deploy_preflight" {
            release_operation(&grant.conn, "preflight", &grant.remote, unit, &[]).await?
        } else {
            release_operation(
                &grant.conn,
                "install",
                &grant.remote,
                unit,
                &[
                    args["archivePath"].as_str().ok_or("Укажите archivePath.")?,
                    args["sha256"].as_str().ok_or("Укажите SHA256.")?,
                ],
            )
            .await?
        }
    } else if let Some((local, remote)) = paths {
        let upload = name != "sftp_download";
        if let Some(unit) = grant.service.as_deref().filter(|_| upload) {
            let check =
                release_operation(&grant.conn, "preflight", &grant.remote, unit, &[]).await?;
            if check["ready"] != true {
                return Err(format!(
                    "Передача остановлена до загрузки. {}",
                    check["reasons"]
                ));
            }
        }
        let parent = local
            .parent()
            .ok_or("Укажите файл.")?
            .canonicalize()
            .map_err(|e| e.to_string())?;
        let file = parent.join(local.file_name().ok_or("Укажите имя файла.")?);
        if !parent.starts_with(&grant.local)
            || (upload
                && !file
                    .canonicalize()
                    .map_err(|e| e.to_string())?
                    .starts_with(&grant.local))
        {
            return Err("Файл вне локальной папки сессии.".into());
        }
        let ftp = Arc::new(ssh::sftp(&grant.conn).await?);
        let root = ftp
            .canonicalize(&grant.remote)
            .await
            .map_err(|e| e.to_string())?;
        let parent = remote.rsplit_once('/').ok_or("Укажите путь.")?.0;
        let dir = ftp
            .canonicalize(if parent.is_empty() { "/" } else { parent })
            .await
            .map_err(|e| e.to_string())?;
        if !Path::new(&dir).starts_with(Path::new(&root))
            || dir.contains('\\')
            || root.contains('\\')
            || (root != "/" && dir != root && !dir.starts_with(&(root + "/")))
        {
            return Err("Файл вне папки сервера для этой сессии.".into());
        }
        let path = format!(
            "{}/{}",
            dir.trim_end_matches('/'),
            remote.rsplit('/').next().unwrap()
        );
        if matches!(name,"update_file"|"update_site_file") {
            if name=="update_file" && !path
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/_-. +".contains(&b))
            {
                return Err("Недопустимый путь обновления.".into());
            }
            let f = tokio::fs::File::open(&file)
                .await
                .map_err(|e| e.to_string())?;
            if !f.metadata().await.map_err(|e| e.to_string())?.is_file() {
                return Err("Выберите обычный файл.".into());
            }
            let mut content = Vec::new();
            f.take(64 * 1024 * 1024 + 1)
                .read_to_end(&mut content)
                .await
                .map_err(|e| e.to_string())?;
            if content.len() > 64 * 1024 * 1024 {
                return Err("Максимальный размер файла — 64 МиБ.".into());
            }
            use sha2::{Digest, Sha256};
            let hash = format!("{:x}", Sha256::digest(&content));
            // Keep the previous contents on the approved device, outside the site's document root.
            let backup=grant.local.join(format!("sshnesh-backup-{}.bak",random_id()));
            let original=ftp.symlink_metadata(&path).await.map_err(|e|format!("SFTP: {e}"))?;
            if !original.file_type().is_file() || original.size.is_none_or(|n|n>64*1024*1024) {
                return Err("Для резервной копии нужен обычный файл до 64 МиБ.".into());
            }
            let mut reader=ftp.open(&path).await.map_err(|e|e.to_string())?.take(64*1024*1024+1);
            let mut previous=Vec::new();
            reader.read_to_end(&mut previous).await.map_err(|e|e.to_string())?;
            if previous.len()>64*1024*1024 {return Err("Исходный файл превышает 64 МиБ.".into());}
            let previous_hash=format!("{:x}",Sha256::digest(&previous));
            let tmp=tempfile::NamedTempFile::new_in(&grant.local).map_err(|e|e.to_string())?;
            {
                use std::io::Write;
                let mut writer=tmp.reopen().map_err(|e|e.to_string())?;
                writer.write_all(&previous).and_then(|_|writer.sync_all()).map_err(|e|e.to_string())?;
            }
            tmp.persist_noclobber(&backup).map_err(|e|e.to_string())?;
            let mut result=if name=="update_site_file" {
                replace_site_file(&grant,ftp,&path,&content,&original,&previous_hash).await
                    .map_err(|e|format!("{e}. Копия исходного файла: {}",display_directory(&backup)))?;
                json!({"updated":true,"sha256":hash})
            } else {
            command=format!("set -eu; dst='{path}'; test -f \"$dst\" && test -w \"$dst\" && test ! -L \"$dst\" || exit 1; tmp=$(mktemp -- \"$dst.sshnesh.XXXXXXXX\"); trap 'rm -f -- \"$tmp\"' EXIT; cat > \"$tmp\"; actual=$(sha256sum < \"$tmp\"); test \"${{actual%% *}}\" = '{hash}'; cp --attributes-only --preserve=all -- \"$dst\" \"$tmp\"; test \"$(stat -c '%u:%g:%a' -- \"$dst\")\" = \"$(stat -c '%u:%g:%a' -- \"$tmp\")\"; before=$(sha256sum < \"$dst\"); test \"${{before%% *}}\" = '{previous_hash}' || exit 75; mv -fT -- \"$tmp\" \"$dst\"");
            mcp::run(&grant.conn, command, Some(std::io::Cursor::new(content))).await
                .map_err(|e|format!("{e}. Копия исходного файла: {}",display_directory(&backup)))?

            };
            result["backupLocalPath"]=json!(display_directory(&backup));
            result["backupSha256"]=json!(previous_hash);
            result
        } else {
            let bytes = transfer_one(ftp, upload, &file, &path).await?;
            json!({"bytes":bytes})
        }
    } else {
        if name == "restart_service" && grant.service.as_deref() != args["unit"].as_str() {
            return Err("Служба не указана в разрешении на подключение. Подключитесь снова с параметром service.".into());
        }
        if name == "restart_service" {
            release_operation(
                &grant.conn,
                "restart",
                &grant.remote,
                grant.service.as_deref().unwrap(),
                &[],
            )
            .await?
        } else {
            mcp::run(&grant.conn, command, None).await?
        }
    };
    result["server"] = card["id"].clone();
    result["user"] = json!(host.username);
    Ok(result)
}

async fn connection(
    app: &App,
    host: &Host,
    server_port:u16,
    saved: Option<&str>,
    cloud: bool,
) -> Result<Connection, String> {
    enum Credential {
        Ready(SessionAuth),
        Prompt,
        Key(Zeroizing<String>, String, bool),
    }
    let (auth, print) = {
        let d = app.inner.lock().unwrap();
        let role = saved.map(|s| format!("login:{s}"));
        if let Some(c) = d
            .sessions
            .values()
            .filter(|s| {
                s.status == "ready"
                    && s.host.id == host.id
                    && s.host.host == host.host
                    && s.host.port == host.port
                    && s.host.username == host.username
                    && s.role == role
            })
            .find_map(|s| s.connection.clone().filter(|c| !c.is_closed()))
        {
            return Ok(c);
        }
        let print = d
            .trusted
            .get(&Host::system_endpoint(&host.host, host.port))
            .or_else(|| d.host_keys.get(&(host.host.clone(), host.port)))
            .cloned();
        let auth = match host.auth.as_str() {
            "prompt" => Credential::Prompt,
            "password" if !cloud && saved.is_none() => d
                .passwords
                .get(&host.id)
                .cloned()
                .map(|p| Credential::Ready(SessionAuth::Password(p)))
                .unwrap_or(Credential::Prompt),
            "password" => {
                let v = d
                    .cloud
                    .as_ref()
                    .ok_or("Откройте хранилище через request_unlock.")?;
                let e = if let Some(id) = saved {
                    v.saved_entry(&host.id, &host.host, server_port, id)?
                } else {
                    v.entry(&host.id).ok_or("Вход недоступен.")?
                };
                if let Ok(p) = v.password(&e) {
                    Credential::Ready(SessionAuth::Password(p))
                } else {
                    Credential::Prompt
                }
            }
            "agent" => Credential::Ready(SessionAuth::Agent),
            "key" => {
                let key = d
                    .cloud
                    .as_ref()
                    .and_then(|v| v.keys.get(host.key_id.as_deref()?))
                    .ok_or("Откройте хранилище через request_unlock.")?;
                Credential::Key(key.secret()?, key.public(), key.is_protected())
            }
            _ => return Err("Неизвестный способ входа.".into()),
        };
        (auth, print)
    };
    let auth = match auth {
        Credential::Ready(a) => a,
        Credential::Prompt => SessionAuth::Password(
            secret(
                app,
                format!(
                    "Пароль SSH для {}. Пароль останется в SSHnesh.",
                    host.target()
                ),
            )
            .await?,
        ),
        Credential::Key(raw, public, protected) => {
            let phrase = if protected {
                Some(
                    secret(
                        app,
                        format!("Парольная фраза SSH-ключа для {}", host.target()),
                    )
                    .await?,
                )
            } else {
                None
            };
            let key = russh::keys::decode_secret_key(&raw, phrase.as_deref().map(String::as_str))
                .map_err(|_| "Не удалось открыть ключ.")?;
            let actual = key.public_key().to_openssh().map_err(|e| e.to_string())?;
            if !actual
                .split_whitespace()
                .take(2)
                .eq(public.split_whitespace().take(2))
            {
                return Err("Публичная часть ключа не совпала.".into());
            }
            SessionAuth::CloudKey(Box::new(key))
        }
    };
    stage("Соединение с SSH-сервером и аутентификация",30);
    let verifier_app = app.clone();
    let address = host.target();
    let endpoint = Host::system_endpoint(&host.host, host.port);
    let progress=STAGES.try_with(|tx|tx.clone()).ok();
    let verify = VerifyKey(Box::new(move |actual, algorithm| {
        let (tx, rx) = oneshot::channel();
        if let Some(expected) = &print {
            let _ = tx.send(actual == *expected);
            return rx;
        }
        let (app, endpoint, address) = (verifier_app.clone(), endpoint.clone(), address.clone());
        if let Some(tx)=&progress {let _=tx.send(("Ожидается проверка ключа SSH-сервера в SSHnesh",90));}
        let progress=progress.clone();
        tauri::async_runtime::spawn(async move {
            let mut tx = tx;
            let accepted = tokio::select! {_=tx.closed()=>return,v=confirm(&app,format!("Первое подключение к {address}. Сверьте ключ сервера {algorithm}\n{actual}\nДоверять этому ключу?"))=>v.is_ok()};
            if !accepted {
                let _ = tx.send(false);
                return;
            }
            let mut d = app.inner.lock().unwrap();
            let mut pins = d.trusted.clone();
            let ok = pins.entry(endpoint).or_insert(actual.clone()) == &actual
                && profiles::write_json(
                    &app.profiles_path.with_file_name("trusted-hosts.json"),
                    &pins,
                    true,
                )
                .is_ok();
            if ok {
                d.trusted = pins;
            }
            if ok {if let Some(progress)=progress {let _=progress.send(("Аутентификация SSH",30));}}
            let _ = tx.send(ok);
        });
        rx
    }));
    match auth {
        SessionAuth::Password(p) => {
            ssh::open(&host.host, host.port, &host.username, p, verify).await
        }
        SessionAuth::CloudKey(k) => {
            ssh::open_private_key(&host.host, host.port, &host.username, *k, verify).await
        }
        SessionAuth::Agent => ssh::open_agent(&host.host, host.port, &host.username, verify).await,
        _ => Err("Выберите сохранённый вход сервера.".into()),
    }
}

fn transfer_paths(args: &Value) -> Result<(&Path, &str), String> {
    let local = args["localPath"]
        .as_str()
        .ok_or("Укажите полный путь на устройстве.")?;
    let remote = args
        .get("remotePath")
        .or_else(|| args.get("path"))
        .unwrap_or(&Value::Null)
        .as_str()
        .ok_or("Укажите полный путь на сервере.")?;
    let safe = |s: &str| {
        !s.is_empty()
            && s.len() <= 4096
            && !s.chars().any(|c| {
                c.is_control() || matches!(c,'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
            })
    };
    if !safe(local)
        || !safe(remote)
        || !remote.starts_with('/')
        || remote.ends_with('/')
        || remote.split('/').any(|p| matches!(p, ".." | "."))
    {
        return Err("Укажите абсолютные пути к файлам.".into());
    }
    let path = Path::new(local);
    if !path.is_absolute()
        || path.file_name().is_none()
        || path.components().any(|p| p == Component::ParentDir)
    {
        return Err("Недопустимый локальный путь.".into());
    }
    #[cfg(windows)]
    {
        use std::path::Prefix;
        if !matches!(path.components().next(),Some(Component::Prefix(p)) if matches!(p.kind(),Prefix::Disk(_)))
            || local[2..].contains(':')
        {
            return Err("Выберите файл на локальном диске.".into());
        }
        for c in path.components() {
            if let Component::Normal(s) = c {
                let s = s.to_string_lossy();
                let stem = s
                    .split('.')
                    .next()
                    .unwrap_or("")
                    .trim_end()
                    .to_ascii_uppercase();
                if s.ends_with(['.', ' '])
                    || matches!(
                        stem.as_str(),
                        "CON" | "NUL" | "PRN" | "AUX" | "CONIN$" | "CONOUT$"
                    )
                    || stem
                        .strip_prefix("COM")
                        .or_else(|| stem.strip_prefix("LPT"))
                        .is_some_and(|n| n.len() == 1 && n.as_bytes()[0].is_ascii_digit())
                {
                    return Err("Выберите обычный файл.".into());
                }
            }
        }
    }
    Ok((path, remote))
}

async fn replace_site_file(grant:&Grant,ftp:Arc<russh_sftp::client::SftpSession>,path:&str,
    content:&[u8],original:&russh_sftp::protocol::FileAttributes,expected:&str)->Result<(),String> {
    use russh_sftp::protocol::{FileAttributes,OpenFlags,Packet,StatusCode};
    use sha2::{Digest,Sha256};
    let mode=original.permissions.ok_or("SFTP не сообщил права файла.")?;
    if mode & 0o7000 != 0 {return Err("Специальные права файла не поддерживаются.".into());}
    let channel=grant.conn.channel_open_session().await.map_err(|e|e.to_string())?;
    channel.request_subsystem(true,"sftp").await.map_err(|e|e.to_string())?;
    let raw=russh_sftp::client::RawSftpSession::new(channel.into_stream());
    let extensions=raw.init().await.map_err(|e|e.to_string())?.extensions;
    let (parent,filename)=path.rsplit_once('/').ok_or("Укажите файл.")?;
    let tmp=format!("{parent}/.sshnesh-{}-{filename}",random_id());
    let err=|e:russh_sftp::client::error::Error|e.to_string();
    let mut dest=ftp.open_with_flags_and_attributes(tmp.clone(),OpenFlags::WRITE|OpenFlags::CREATE|OpenFlags::EXCLUDE,
        FileAttributes{permissions:Some(0o600),..Default::default()}).await.map_err(err)?;
    let mut cleanup=StagedUpload(ftp.clone(),Some(tmp.clone()));
    dest.write_all(content).await.map_err(|e|e.to_string())?;
    dest.shutdown().await.map_err(|e|e.to_string())?;
    let staged=ftp.metadata(&tmp).await.map_err(err)?;
    if original.uid.is_none() || original.gid.is_none() || staged.uid!=original.uid || staged.gid!=original.gid {
        return Err("Не удалось подтвердить сохранение владельца и группы файла.".into());
    }
    ftp.set_metadata(&tmp,FileAttributes{permissions:Some(mode & 0o777),..Default::default()}).await.map_err(err)?;
    let current=ftp.symlink_metadata(path).await.map_err(err)?;
    if !current.file_type().is_file() || current.permissions!=original.permissions || current.uid!=original.uid || current.gid!=original.gid ||
        !matches!(current.size,Some(n) if n<=64*1024*1024) {return Err("Исходный файл изменился.".into());}
    let mut bytes=Vec::new();
    ftp.open(path).await.map_err(err)?.take(64*1024*1024+1).read_to_end(&mut bytes).await.map_err(|e|e.to_string())?;
    if format!("{:x}",Sha256::digest(&bytes))!=expected {return Err("Содержимое файла изменилось. Обновите копию.".into());}
    if extensions.get("posix-rename@openssh.com").is_some_and(|v|v=="1") {
        let mut data=Vec::new();
        for name in [tmp.as_str(),path] {data.extend_from_slice(&(name.len() as u32).to_be_bytes());data.extend_from_slice(name.as_bytes());}
        match raw.extended("posix-rename@openssh.com",data).await.map_err(err)? {
            Packet::Status(status) if status.status_code==StatusCode::Ok=>{},
            Packet::Status(status)=>return Err(format!("SFTP: {}",status.error_message)),
            _=>return Err("Неожиданный ответ на замену файла.".into())
        }
    } else {
        ftp.rename(&tmp,path).await.map_err(|e|format!("SFTP-сервер отклонил замену файла: {e}"))?;
    }
    cleanup.1.take();
    Ok(())
}

struct StagedUpload(Arc<russh_sftp::client::SftpSession>, Option<String>);
impl Drop for StagedUpload {
    fn drop(&mut self) {
        if let Some(path) = self.1.take() {
            let ftp = self.0.clone();
            tauri::async_runtime::spawn(async move {
                let _ = ftp.remove_file(path).await;
            });
        }
    }
}
async fn transfer_one(
    ftp: Arc<russh_sftp::client::SftpSession>,
    upload: bool,
    local: &Path,
    remote: &str,
) -> Result<u64, String> {
    use russh_sftp::protocol::{FileAttributes, OpenFlags};
    let err = |e: std::io::Error| e.to_string();

    if upload {
        if !tokio::fs::symlink_metadata(local)
            .await
            .map_err(err)?
            .is_file()
        {
            return Err("Выберите обычный локальный файл.".into());
        }
        let mut source = tokio::fs::File::open(local).await.map_err(err)?;
        let tmp = format!(
            "{}/.sshnesh-{}",
            remote.rsplit_once('/').unwrap().0,
            random_id()
        );
        let attrs = FileAttributes {
            permissions: Some(0o600),
            ..Default::default()
        };
        let mut dest = ftp
            .open_with_flags_and_attributes(
                tmp.clone(),
                OpenFlags::WRITE | OpenFlags::CREATE | OpenFlags::EXCLUDE,
                attrs,
            )
            .await
            .map_err(|e| e.to_string())?;
        let mut staged = StagedUpload(ftp.clone(), Some(tmp.clone()));
        let bytes = tokio::io::copy(&mut source, &mut dest).await.map_err(err)?;
        dest.shutdown().await.map_err(err)?;
        ftp.rename(tmp, remote)
            .await
            .map_err(|e| format!("Не удалось сохранить файл без перезаписи: {e}"))?;
        staged.1.take();
        Ok(bytes)
    } else {
        if !ftp
            .symlink_metadata(remote)
            .await
            .map_err(|e| e.to_string())?
            .file_type()
            .is_file()
        {
            return Err("Выберите обычный файл на сервере.".into());
        }
        let mut source = ftp.open(remote).await.map_err(|e| e.to_string())?;
        let tmp = tempfile::NamedTempFile::new_in(local.parent().ok_or("Укажите папку.")?)
            .map_err(err)?;
        let mut dest = tokio::fs::File::from_std(tmp.reopen().map_err(err)?);
        let bytes = tokio::io::copy(&mut source, &mut dest).await.map_err(err)?;
        dest.sync_all().await.map_err(err)?;
        drop(dest);
        tmp.persist_noclobber(local)
            .map_err(|e| format!("Не удалось сохранить файл без перезаписи: {e}"))?;
        Ok(bytes)
    }
}
