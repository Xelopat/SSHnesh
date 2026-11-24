//! Native Android account login. The UI uses only account state, never the verifier or token.
use crate::{app::App, profiles};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
#[cfg(target_os = "android")]
use tauri_plugin_deep_link::DeepLinkExt;
use tauri_plugin_opener::OpenerExt;
use zeroize::{Zeroize, Zeroizing};

const SCHEME: &str = "ru.xelopat.sshnesh.preview";
const START: &str = "https://xelopat.ru/sshnesh-login";
const SESSION_ENDPOINT: &str = "https://sshnesh.xelopat.ru/session.php";
const PENDING_TTL: u64 = 300;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    state: String,
    verifier: String,
    expires: u64,
}

impl Drop for Pending {
    fn drop(&mut self) {
        self.verifier.zeroize();
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Session {
    subject: String,
    username: String,
    token: String,
    expires: u64,
}

impl Drop for Session {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

#[derive(Default)]
pub(crate) struct Auth {
    file: PathBuf,
    pending: Option<Pending>,
    session: Option<Session>,
    exchanging: bool,
    checked_saved_login: bool,
    error: Option<String>,
    callback: u64,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex(s: &str, len: usize) -> bool {
    s.len() == len
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn random_hex() -> Result<String, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    getrandom::fill(bytes.as_mut()).map_err(|_| "Не удалось начать безопасный вход.")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn code_ok(code: &str) -> bool {
    code.split_once('.').is_some_and(|(payload, signature)| {
        (1..=1500).contains(&payload.len())
            && payload
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            && hex(signature, 64)
    })
}

pub(crate) fn client() -> Result<Client, String> {
    Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(18))
        .build()
        .map_err(|_| "Не удалось начать HTTPS-запрос.".into())
}

impl Auth {
    pub(crate) fn cloud_subject(&self) -> Option<&str> {
        self.session
            .as_ref()
            .filter(|s| s.expires > now())
            .map(|s| s.subject.as_str())
    }

    pub(crate) fn cloud_session(&self) -> Result<(String, Zeroizing<String>), String> {
        let s = self
            .session
            .as_ref()
            .filter(|s| s.expires > now())
            .ok_or("Сначала войдите в аккаунт.")?;
        Ok((s.subject.clone(), Zeroizing::new(s.token.clone())))
    }
    pub(crate) fn load(profiles: &Path) -> Self {
        let file = profiles.with_file_name("android-account-pending.json");
        let current = now();
        let pending = fs::read(&file)
            .ok()
            .and_then(|bytes| {
                let bytes = Zeroizing::new(bytes);
                serde_json::from_slice::<Pending>(&bytes).ok()
            })
            .filter(|p| {
                p.expires > current
                    && p.expires <= current + PENDING_TTL
                    && hex(&p.state, 64)
                    && hex(&p.verifier, 64)
            });
        if pending.is_none() {
            let _ = fs::remove_file(&file);
        }
        Self {
            file,
            pending,
            ..Self::default()
        }
    }

    fn session_slot(&self) -> String {
        // Keep separate application profiles independent in the OS credential store.
        let digest = format!("{:x}", Sha256::digest(self.file.to_string_lossy().as_bytes()));
        format!("oauth-{}", &digest[..16])
    }

    pub(crate) fn restore_login(&mut self, app: &App) {
        if self.checked_saved_login { return; }
        self.checked_saved_login = true;
        if self.session.is_some() || !self.file.with_file_name("saved-login.json").exists() { return; }
        let result = crate::device_key::access(app, &self.session_slot(), crate::device_key::Operation::Read)
            .and_then(|stored| serde_json::from_str::<Session>(&stored).map_err(|_| "Повреждена сохранённая сессия.".to_owned()));
        match result {
            Ok(session) if session.expires > now() => self.session = Some(session),
            Ok(_) => {},
            Err(error) => self.error = Some(error),
        }
    }

    pub(crate) fn snapshot(&self) -> Value {
        let current = now();
        json!({"username":self.session.as_ref().filter(|s| s.expires > current).map(|s| &s.username),
            "busy":self.exchanging || self.pending.as_ref().is_some_and(|p| p.expires > current),
            "canCancel":self.pending.as_ref().is_some_and(|p| p.expires > current),
            "error":self.error,"callback":self.callback})
    }

    fn clear_pending(&mut self) -> io::Result<()> {
        match fs::remove_file(&self.file) {
            Ok(()) => (),
            Err(e) if e.kind() == io::ErrorKind::NotFound => (),
            Err(e) => return Err(e),
        }
        self.pending = None;
        Ok(())
    }
}

pub(crate) fn start(app: &App) -> Result<(), String> {
    #[cfg(not(target_os = "android"))]
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "Не удалось открыть локальный адрес входа.")?;
    let (url, marker, expires) = {
        let mut data = app.inner.lock().unwrap();
        let auth = &mut data.oauth;
        if auth.exchanging || auth.pending.as_ref().is_some_and(|p| p.expires > now()) {
            return Err("Вход уже начат.".into());
        }
        if auth.session.as_ref().is_some_and(|s| s.expires > now()) {
            return Err("Вы уже вошли в аккаунт.".into());
        }
        let p = Pending {
            state: random_hex()?,
            verifier: random_hex()?,
            expires: now() + PENDING_TTL,
        };
        let mut url = Url::parse(START).expect("fixed authorization URL");
        let challenge = format!("{:x}", Sha256::digest(p.verifier.as_bytes()));
        #[cfg(target_os = "android")]
        url.query_pairs_mut().append_pair("mode", "android");
        #[cfg(not(target_os = "android"))]
        url.query_pairs_mut().append_pair(
            "port",
            &listener
                .local_addr()
                .map_err(|e| e.to_string())?
                .port()
                .to_string(),
        );
        url.query_pairs_mut()
            .append_pair("state", &p.state)
            .append_pair("challenge", &challenge);
        profiles::write_json(&auth.file, &p, true)
            .map_err(|_| "Не удалось сохранить состояние входа.")?;
        let marker = p.state.clone();
        let expires = p.expires;
        auth.error = None;
        auth.pending = Some(p);
        (url, marker, expires)
    };
    if app
        .handle
        .opener()
        .open_url(url.as_str(), None::<&str>)
        .is_err()
    {
        cancel(app)?;
        return Err("Не удалось открыть браузер.".into());
    }
    #[cfg(not(target_os = "android"))]
    accept_local_callback(app.clone(), listener, marker.clone(), expires);
    schedule_pending_expiry(app.clone(), marker, expires);
    app.changed();
    Ok(())
}

pub(crate) fn cancel(app: &App) -> Result<(), String> {
    let mut data = app.inner.lock().unwrap();
    if data.oauth.exchanging {
        return Err("Дождитесь завершения входа.".into());
    }
    data.oauth
        .clear_pending()
        .map_err(|_| "Не удалось отменить вход.")?;
    data.oauth.error = None;
    drop(data);
    app.changed();
    Ok(())
}

pub(crate) async fn logout(app: &App) -> Result<(), String> {
    crate::cloud::forget(app)?;
    let session = {
        let mut data = app.inner.lock().unwrap();
        if data.oauth.exchanging || data.cloud_loading {
            return Err("Дождитесь завершения текущей операции.".into());
        }
        data.oauth.error = None;
        #[cfg(not(mobile))]
        data.mcp_connections.clear();
        data.cloud = None;
        data.cloud_owner = None;
        let marker = data.oauth.file.with_file_name("saved-login.json");
        if marker.exists() {
            fs::remove_file(&marker).map_err(|_| "Не удалось удалить сохранённый вход.")?;
            crate::device_key::access(app, &data.oauth.session_slot(), crate::device_key::Operation::Forget)?;
        }
        data.oauth.session.take()
    };
    app.changed();
    let Some(session) = session.filter(|s| s.expires > now()) else {
        return Ok(());
    };
    let reply = client()?
        .delete(SESSION_ENDPOINT)
        .bearer_auth(&session.token)
        .send()
        .await
        .map_err(|_| "Вы вышли на устройстве, но сервер не подтвердил выход.")?;
    if !reply.status().is_success() && reply.status() != reqwest::StatusCode::UNAUTHORIZED {
        return Err("Вы вышли на устройстве, но сервер не подтвердил выход.".into());
    }
    Ok(())
}

fn parse_callback(url: &Url) -> Option<(String, Zeroizing<String>)> {
    if url.as_str().len() > 4096
        || url.scheme() != SCHEME
        || url.host_str() != Some("auth")
        || url.path() != "/callback"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.port().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let (mut state, mut code) = (None, None);
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "state" if state.is_none() && hex(&value, 64) => state = Some(value.into_owned()),
            "code" if code.is_none() && code_ok(&value) => {
                code = Some(Zeroizing::new(value.into_owned()))
            }
            _ => return None,
        }
    }
    Some((state?, code?))
}

async fn exchange(code: &str, verifier: &str) -> Result<Session, String> {
    let mut response = client()?
        .post(SESSION_ENDPOINT)
        .json(&json!({"code":code,"verifier":verifier}))
        .send()
        .await
        .map_err(|_| "Сервер входа недоступен. Попробуйте ещё раз.")?;
    if !response.status().is_success() {
        return Err("Сервер не принял код. Начните вход заново.".into());
    }
    let mut body = Zeroizing::new(Vec::new());
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| "Сервер не ответил на запрос входа.")?
    {
        if body.len() + chunk.len() > 4096 {
            return Err("Некорректный ответ сервера входа.".into());
        }
        body.extend_from_slice(&chunk);
    }
    let session: Session =
        serde_json::from_slice(&body).map_err(|_| "Некорректный ответ сервера входа.")?;
    if !hex(&session.subject, 16)
        || !hex(&session.token, 64)
        || session.expires <= now()
        || !(3..=32).contains(&session.username.len())
        || !session
            .username
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err("Некорректный ответ сервера входа.".into());
    }
    Ok(session)
}

async fn receive(app: App, url: Url) {
    let Some((state, code)) = parse_callback(&url) else {
        return;
    };
    let pending = {
        let mut data = app.inner.lock().unwrap();
        let auth = &mut data.oauth;
        if !auth
            .pending
            .as_ref()
            .is_some_and(|p| p.expires > now() && p.state == state)
        {
            return;
        }
        // Consume the saved verifier before contacting the server, including after a cold start.
        let pending = auth.pending.take().expect("matched pending login");
        auth.callback = auth.callback.wrapping_add(1);
        if auth.clear_pending().is_err() {
            auth.error = Some("Не удалось завершить вход на этом устройстве.".into());
            drop(data);
            app.changed();
            return;
        }
        auth.exchanging = true;
        pending
    };
    drop(url);
    app.changed();
    let result = exchange(&code, &pending.verifier).await;
    let expires = result.as_ref().ok().map(|s| s.expires);
    {
        let mut data = app.inner.lock().unwrap();
        if let Ok(ref session) = result {
            if data
                .cloud_owner
                .as_deref()
                .is_some_and(|owner| owner != session.subject)
            {
                #[cfg(not(mobile))]
        data.mcp_connections.clear();
        data.cloud = None;
                data.cloud_owner = None;
            }
        }
        let auth = &mut data.oauth;
        auth.exchanging = false;
        match result {
            Ok(session) => {
                let saved = serde_json::to_string(&session).map(Zeroizing::new).map_err(|e| e.to_string())
                    .and_then(|value| crate::device_key::access(&app, &auth.session_slot(), crate::device_key::Operation::Store(&value)))
                    .and_then(|_| profiles::write_json(&auth.file.with_file_name("saved-login.json"), &true, true).map_err(|e| e.to_string()));
                auth.checked_saved_login = true;
                auth.session = Some(session);
                auth.error = saved.err().map(|_| "Вход выполнен, но система не смогла запомнить его на устройстве.".into());
            }
            Err(error) => auth.error = Some(error),
        }
    }
    app.changed();
    if let Some(expiry) = expires {
        tauri::async_runtime::spawn(async move {
            tokio::time::sleep(Duration::from_secs(expiry.saturating_sub(now()))).await;
            let mut data = app.inner.lock().unwrap();
            if data
                .oauth
                .session
                .as_ref()
                .is_some_and(|s| s.expires <= now())
            {
                data.oauth.session = None;
                drop(data);
                app.changed();
            }
        });
    }
}

fn schedule_pending_expiry(app: App, state: String, expires: u64) {
    tauri::async_runtime::spawn(async move {
        tokio::time::sleep(Duration::from_secs(expires.saturating_sub(now()))).await;
        let mut data = app.inner.lock().unwrap();
        let auth = &mut data.oauth;
        if auth
            .pending
            .as_ref()
            .is_some_and(|p| p.state == state && p.expires <= now())
        {
            let _ = auth.clear_pending();
            auth.error = Some("Время на вход истекло. Начните заново.".into());
            drop(data);
            app.changed();
        }
    });
}

#[cfg(not(target_os = "android"))]
pub(crate) fn attach(app: App) {
    let _ = app.inner.lock().unwrap().oauth.clear_pending();
}

#[cfg(not(target_os = "android"))]
fn accept_local_callback(app: App, listener: std::net::TcpListener, state: String, expires: u64) {
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    tauri::async_runtime::spawn(async move {
        if listener.set_nonblocking(true).is_err() {
            return;
        }
        let Ok(listener) = tokio::net::TcpListener::from_std(listener) else {
            return;
        };
        let _ = tokio::time::timeout(Duration::from_secs(expires.saturating_sub(now())), async {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = String::new();
                let mut reader = BufReader::new((&mut stream).take(4097));
                if !matches!(tokio::time::timeout(Duration::from_secs(2), reader.read_line(&mut request)).await, Ok(Ok(_))) { continue; }
                let Some(path) = request.split_whitespace().nth(1).filter(|_| request.starts_with("GET ")) else { continue };
                let Some(query) = path.strip_prefix("/sshnesh-callback?") else { continue };
                let Ok(url) = Url::parse(&format!("{SCHEME}://auth/callback?{query}")) else { continue };
                if !parse_callback(&url).is_some_and(|(returned, _)| returned == state) { continue; }
                receive(app.clone(), url).await;
                let connected = app.inner.lock().unwrap().oauth.cloud_subject().is_some();
                let message = if connected { "Аккаунт подключён. Можно закрыть вкладку." } else { "Не удалось завершить вход." };
                let response = format!("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n{message}");
                let _ = stream.write_all(response.as_bytes()).await;
                break;
            }
        }).await;
    });
}

#[cfg(target_os = "android")]
pub(crate) fn attach(app: App) {
    let pending = app
        .inner
        .lock()
        .unwrap()
        .oauth
        .pending
        .as_ref()
        .map(|p| (p.state.clone(), p.expires));
    if let Some((state, expires)) = pending {
        schedule_pending_expiry(app.clone(), state, expires);
    }
    let warm = app.clone();
    app.handle.deep_link().on_open_url(move |event| {
        for url in event.urls() {
            tauri::async_runtime::spawn(receive(warm.clone(), url));
        }
    });
    tauri::async_runtime::spawn(async move {
        if let Ok(Some(urls)) = app.handle.deep_link().get_current() {
            for url in urls {
                receive(app.clone(), url).await;
            }
        }
    });
}
