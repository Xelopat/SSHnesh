use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Profile {
    pub id: String,
    pub label: String,
    pub host: String,
    pub port: u16,
    pub fingerprint: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub vault_only: bool,
    pub debug: Option<Login>,
    pub admin: Option<Login>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Login {
    pub user: String,
    pub key_path: PathBuf,
}

pub(crate) fn username(s: &str) -> bool {
    s.len() <= 32
        && s.as_bytes().first().is_some_and(u8::is_ascii_lowercase)
        && s.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || b"_-".contains(&c))
        && s != "root"
}

pub(crate) fn validate(p: &Profile) -> Result<(), String> {
    if uuid::Uuid::parse_str(&p.id).is_err()
        || p.label.trim().is_empty()
        || p.label.len() > 120
        || p.label.chars().any(|c| {
            c.is_control() || matches!(c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        || p.port == 0
        || p.host.is_empty()
        || p.host.len() > 253
        || !p
            .host
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".:-".contains(&b))
    {
        return Err("Некорректный адрес или название сервера.".into());
    }
    if !p.fingerprint.strip_prefix("SHA256:").is_some_and(|s| {
        s.len() == 43
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"+/".contains(&b))
    }) {
        return Err("Укажите проверенный отпечаток SSH в формате SHA256:…".into());
    }
    for login in [&p.debug, &p.admin].into_iter().flatten() {
        if !username(&login.user) || !login.key_path.is_absolute() || !login.key_path.is_file() {
            return Err(
                "Для учётки нужны имя пользователя и путь к существующему приватному ключу.".into(),
            );
        }
    }
    if let (Some(debug), Some(admin)) = (&p.debug, &p.admin) {
        if debug.user == admin.user {
            return Err("Для диагностики и администрирования нужны разные пользователи.".into());
        }
    }
    Ok(())
}

#[cfg(not(mobile))]
pub(crate) fn desktop_file() -> Result<PathBuf, String> {
    let home = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".config")))
    };
    Ok(home
        .filter(|p| p.is_absolute())
        .ok_or("Каталог профилей недоступен.")?
        .join("SSHnesh Preview")
        .join("connectors.json"))
}

#[cfg(not(mobile))]
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct McpPreferences {
    enabled: bool,
}

#[cfg(not(mobile))]
pub(crate) fn mcp_enabled(profiles: &Path) -> std::io::Result<bool> {
    match std::fs::read(profiles.with_file_name("mcp-preferences.json")) {
        Ok(data) => Ok(serde_json::from_slice::<McpPreferences>(&data)?.enabled),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e),
    }
}

#[cfg(not(mobile))]
pub(crate) fn set_mcp_enabled(profiles: &Path, enabled: bool) -> std::io::Result<()> {
    write_json(
        &profiles.with_file_name("mcp-preferences.json"),
        &McpPreferences { enabled },
        true,
    )
}

pub(crate) fn read(path: &Path) -> Result<Vec<Profile>, String> {
    match std::fs::read(path) {
        Ok(data) => serde_json::from_slice(&data).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(e.to_string()),
    }
}

pub(crate) fn write(path: &Path, items: &[Profile]) -> Result<(), String> {
    write_json(path, items, true).map_err(|e| e.to_string())
}

pub(crate) fn write_json(
    path: &Path,
    value: &(impl Serialize + ?Sized),
    durable: bool,
) -> std::io::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .ok_or_else(|| std::io::Error::other("Нет каталога профилей."))?;
    std::fs::create_dir_all(dir)?;
    let temp = dir.join(format!(".pending-{}", uuid::Uuid::new_v4()));
    let result = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(&temp)?;
        serde_json::to_writer(&mut file, value)?;
        file.flush()?;
        if durable {
            file.sync_all()?;
        }
        drop(file);
        std::fs::rename(&temp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temp);
    }
    result
}
