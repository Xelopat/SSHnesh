use russh::{client, keys::PublicKeyOrCertificate, ChannelMsg, Disconnect};
use russh_sftp::client::SftpSession;
use std::{sync::Arc, time::Duration};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

pub(crate) struct VerifyKey(
    pub Box<dyn Fn(String, String) -> oneshot::Receiver<bool> + Send + Sync>,
);

impl client::Handler for VerifyKey {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let key = key.public_key();
        let answer = (self.0)(
            key.fingerprint(russh::keys::HashAlg::Sha256).to_string(),
            key.algorithm().to_string(),
        );
        Ok(tokio::time::timeout(Duration::from_secs(90), answer)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false))
    }
}

pub(crate) enum Input {
    Text(String),
    Resize(u32, u32),
}

pub(crate) type Connection = Arc<client::Handle<VerifyKey>>;

pub(crate) async fn open_key(
    host: &str,
    port: u16,
    user: &str,
    path: &std::path::Path,
    fingerprint: String,
) -> Result<Connection, String> {
    let key = russh::keys::load_secret_key(path, None).map_err(|_| {
        "Не удалось открыть ключ SSH. В прототипе поддерживаются ключи без парольной фразы."
            .to_owned()
    })?;
    let verifier = VerifyKey(Box::new(move |actual, _| {
        let (tx, rx) = oneshot::channel();
        let _ = tx.send(actual == fingerprint);
        rx
    }));
    open_private_key(host, port, user, key, verifier).await
}

pub(crate) async fn open_private_key(
    host: &str,
    port: u16,
    user: &str,
    key: russh::keys::PrivateKey,
    verifier: VerifyKey,
) -> Result<Connection, String> {
    let mut conn = client::connect(Arc::new(client::Config::default()), (host, port), verifier)
        .await
        .map_err(|e| format!("Ошибка SSH (в том числе при несовпадении отпечатка): {e}"))?;
    let hash = conn
        .best_supported_rsa_hash()
        .await
        .map_err(|e| e.to_string())?
        .flatten();
    let result = conn
        .authenticate_publickey(
            user,
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), hash),
        )
        .await
        .map_err(|e| e.to_string())?;
    if !result.success() {
        return Err("Сервер отклонил ключ SSH.".into());
    }
    Ok(Arc::new(conn))
}

pub(crate) async fn open_agent(host:&str,port:u16,user:&str,verifier:VerifyKey)->Result<Connection,String>{
    #[cfg(target_os="android")]
    {let _=(host,port,user,verifier);Err("Системный SSH-агент на Android недоступен.".into())}
    #[cfg(not(target_os="android"))]
    {
        use russh::keys::agent::{client::AgentClient,AgentIdentity};
        #[cfg(windows)]
        let agent=AgentClient::connect_named_pipe(r"\\.\pipe\openssh-ssh-agent").await;
        #[cfg(unix)]
        let agent=AgentClient::connect_env().await;
        let mut agent=agent.map_err(|_|"Запустите SSH-агент и добавьте в него ключ.")?;
        let mut conn=client::connect(Arc::new(client::Config::default()),(host,port),verifier).await.map_err(|e|e.to_string())?;
        let hash=conn.best_supported_rsa_hash().await.map_err(|e|e.to_string())?.flatten();
        for identity in agent.request_identities().await.map_err(|e|e.to_string())? {
            if let AgentIdentity::PublicKey{key,..}=identity {
                if conn.authenticate_publickey_with(user,key,hash,&mut agent).await.map_err(|e|e.to_string())?.success(){return Ok(Arc::new(conn));}
            }
        }
        Err("Сервер не принял ключи SSH-агента.".into())
    }
}

pub(crate) async fn open(
    host: &str,
    port: u16,
    user: &str,
    password: Zeroizing<String>,
    verifier: VerifyKey,
) -> Result<Connection, String> {
    let config = client::Config {
        keepalive_interval: Some(Duration::from_secs(10)),
        keepalive_max: 2,
        ..Default::default()
    };
    let mut connection = client::connect(Arc::new(config), (host, port), verifier)
        .await
        .map_err(|error| format!("Ошибка SSH: {error}"))?;
    let result = connection
        .authenticate_password(user, password.as_str())
        .await
        .map_err(|error| error.to_string())?;
    if !result.success() {
        return Err("Сервер отклонил пароль SSH.".into());
    }
    Ok(Arc::new(connection))
}

async fn check_reply(channel: &mut russh::Channel<client::Msg>) -> Result<Vec<u8>, String> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let mut early_output = Vec::new();
        loop {
            match channel.wait().await {
                Some(ChannelMsg::Success) => return Ok(early_output),
                Some(ChannelMsg::Failure | ChannelMsg::Close | ChannelMsg::Eof) | None => {
                    return Err("Сервер отклонил запрос терминала SSH.".into());
                }
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => {
                    if early_output.len() + data.len() > 65_536 {
                        return Err(
                            "Сервер прислал слишком много данных до подтверждения PTY.".into()
                        );
                    }
                    early_output.extend_from_slice(&data);
                }
                _ => {}
            }
        }
    })
    .await
    .map_err(|_| "Сервер не подтвердил открытие терминала SSH.".to_owned())?
}

pub(crate) async fn terminal(
    connection: &Connection,
    mut inputs: mpsc::Receiver<Input>,
    ready: impl FnOnce(),
    output: impl Fn(&[u8]),
) -> Result<(), String> {
    let mut channel = connection
        .channel_open_session()
        .await
        .map_err(|e| e.to_string())?;
    channel
        .request_pty(true, "xterm-256color", 100, 30, 0, 0, &[])
        .await
        .map_err(|e| e.to_string())?;
    let early_pty_output = check_reply(&mut channel).await?;
    channel
        .request_shell(true)
        .await
        .map_err(|e| e.to_string())?;
    let early_shell_output = check_reply(&mut channel).await?;
    ready();
    if !early_pty_output.is_empty() {
        output(&early_pty_output);
    }
    if !early_shell_output.is_empty() {
        output(&early_shell_output);
    }
    loop {
        tokio::select! {
            input = inputs.recv() => match input {
                Some(Input::Text(text)) => channel.data_bytes(text.into_bytes()).await.map_err(|e| e.to_string())?,
                Some(Input::Resize(cols, rows)) => channel.window_change(cols, rows, 0, 0).await.map_err(|e| e.to_string())?,
                None => break,
            },
            message = channel.wait() => match message {
                Some(ChannelMsg::Data { data }) | Some(ChannelMsg::ExtendedData { data, .. }) => output(&data),
                Some(ChannelMsg::Close | ChannelMsg::Eof) | None => break,
                _ => {},
            },
        }
    }
    let _ = channel.close().await;
    let _ = connection
        .disconnect(Disconnect::ByApplication, "", "en")
        .await;
    Ok(())
}

pub(crate) async fn sftp(connection: &Connection) -> Result<SftpSession, String> {
    let channel = connection
        .channel_open_session()
        .await
        .map_err(|e| e.to_string())?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| e.to_string())?;
    SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| e.to_string())
}

#[derive(Clone, Debug, PartialEq, serde::Deserialize, serde::Serialize)]
pub(crate) struct SystemInfo {
    pub id: String,
    pub name: String,
    pub version: String,
}

fn parse_release(bytes: &[u8]) -> Option<SystemInfo> {
    let mut id = None;
    let mut name = None;
    let mut version = None;
    for line in std::str::from_utf8(bytes).ok()?.lines() {
        let Some((key, raw)) = line.split_once('=') else { continue };
        let value = raw.trim();
        let value = value.strip_prefix('"').and_then(|v| v.strip_suffix('"'))
            .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\''))).unwrap_or(value);
        if value.is_empty() || value.len() > 80 ||
            !value.bytes().all(|b| b.is_ascii_alphanumeric() || b" ._()+-/".contains(&b)) { continue; }
        match key {
            "ID" if value.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-".contains(&b)) => id = Some(value),
            "NAME" => name = Some(value),
            "VERSION_ID" => version = Some(value),
            _ => (),
        }
    }
    let id = id?;
    Some(SystemInfo { id:id.into(), name:name.unwrap_or(id).into(), version:version.unwrap_or("").into() })
}

pub(crate) async fn remote_uid(connection:&Connection)->Option<u32>{
    tokio::time::timeout(Duration::from_secs(4),async {
        let mut ch=connection.channel_open_session().await.ok()?;
        ch.exec(true,"id -u").await.ok()?;
        let mut bytes=Vec::new();let mut success=false;
        while let Some(msg)=ch.wait().await {match msg{
            ChannelMsg::Data{data} if bytes.len()+data.len()<=32=>bytes.extend_from_slice(&data),
            ChannelMsg::Data{..}|ChannelMsg::Failure=>return None,
            ChannelMsg::ExitStatus{exit_status}=>success=exit_status==0,
            ChannelMsg::Close=>break,_=>()
        }}
        if !success{return None;}
        std::str::from_utf8(&bytes).ok()?.trim().parse().ok()
    }).await.ok().flatten()
}

pub(crate) async fn detect_system(connection: &Connection) -> Option<SystemInfo> {
    use tokio::io::AsyncReadExt;
    tokio::time::timeout(Duration::from_secs(5), async {
        let ftp = sftp(connection).await.ok()?;
        for path in ["/etc/os-release","/usr/lib/os-release"] {
            let Ok(file) = ftp.open(path).await else { continue };
            let mut bytes = Vec::new();
            file.take(16385).read_to_end(&mut bytes).await.ok()?;
            if bytes.len() > 16384 { return None; }
            return parse_release(&bytes);
        }
        None
    }).await.ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::OpenFlags;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn distro_identity_comes_from_os_release() {
        let info=parse_release(b"NAME=Ubuntu\nID=ubuntu\nVERSION_ID=\"24.04\"\nID_LIKE=debian").unwrap();
        assert_eq!((info.id.as_str(),info.version.as_str()),("ubuntu","24.04"));
        assert_eq!(parse_release(b"NAME='Debian GNU/Linux'\nID=debian").unwrap().name,"Debian GNU/Linux");
        assert!(parse_release(b"ID=../../bad").is_none());
    }
    #[tokio::test]
    #[ignore = "requires the isolated OpenSSH fixture"]
    async fn ssh_and_sftp() {
        let host = std::env::var("SSHNESH_FIXTURE_HOST").unwrap_or_else(|_| "127.0.0.1".into());
        let port = std::env::var("SSHNESH_FIXTURE_PORT")
            .unwrap()
            .parse()
            .unwrap();
        let expected = std::env::var("SSHNESH_FIXTURE_FINGERPRINT").unwrap();
        let verifier = VerifyKey(Box::new(move |fingerprint, _| {
            let (tx, rx) = oneshot::channel();
            tx.send(fingerprint == expected).unwrap();
            rx
        }));
        let connection = open(
            &host,
            port,
            "sshnesh",
            Zeroizing::new("local-docker-fixture-only".into()),
            verifier,
        )
        .await
        .unwrap();
        assert!(detect_system(&connection).await.is_some());
        let (tx, rx) = mpsc::channel(8);
        let (data_tx, mut data_rx) = mpsc::unbounded_channel();
        let (ready_tx, ready_rx) = oneshot::channel();
        let terminal_connection = connection.clone();
        let task = tokio::spawn(async move {
            terminal(
                &terminal_connection,
                rx,
                || {
                    ready_tx.send(()).unwrap();
                },
                |bytes| {
                    let _ = data_tx.send(bytes.to_vec());
                },
            )
            .await
        });
        tokio::time::timeout(Duration::from_secs(10), ready_rx)
            .await
            .unwrap()
            .unwrap();
        tx.send(Input::Resize(101, 31)).await.unwrap();
        tx.send(Input::Text("printf '%s\\n' sshnesh-$((3+4))\r".into()))
            .await
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut output = Vec::new();
            while let Some(bytes) = data_rx.recv().await {
                output.extend(bytes);
                if output
                    .windows(b"sshnesh-7".len())
                    .any(|part| part == b"sshnesh-7")
                {
                    return;
                }
            }
            panic!("PTY closed before the command output");
        })
        .await
        .unwrap();

        let ftp = sftp(&connection).await.unwrap();
        let path = format!("sshnesh-test-{}.bin", uuid::Uuid::new_v4());
        let expected: Vec<_> = (0..131_071).map(|n| (n % 233) as u8).collect();
        let flags = OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::EXCLUDE;
        let mut file = ftp.open_with_flags(&path, flags).await.unwrap();
        file.write_all(&expected).await.unwrap();
        file.shutdown().await.unwrap();
        assert!(ftp
            .read_dir(".")
            .await
            .unwrap()
            .any(|entry| entry.file_name() == path));
        assert!(ftp.open_with_flags(&path, flags).await.is_err());
        assert_eq!(ftp.read(&path).await.unwrap(), expected);
        ftp.remove_file(path).await.unwrap();
        drop(tx);
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        println!("PASS SSH host fingerprint, password, PTY, resize, SFTP upload/list/download and overwrite refusal");
    }
}
