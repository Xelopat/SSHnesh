use crate::profiles;
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const LEASE_MS: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Target {
    pub id: String,
    pub host: String,
    pub port: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lease {
    touched: u64,
    until: u64,
    target: Option<Target>,
}

pub(crate) fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn directory(profiles: &Path) -> PathBuf {
    profiles.with_file_name("open-windows")
}

pub(crate) struct Window {
    path: PathBuf,
    pub enabled: bool,
    pub selection: Option<(String, String)>,
    pub sequence: u64,
    pub closed: bool,
    pub touched: u64,
}

impl Window {
    pub fn new(profiles: &Path) -> Self {
        Self {
            path: directory(profiles).join(format!("{}.json", Uuid::new_v4())),
            enabled: true,
            selection: None,
            sequence: 0,
            closed: false,
            touched: now(),
        }
    }

    pub fn publish(&self, target: Option<Target>) -> io::Result<()> {
        if self.closed {
            return Ok(());
        }
        let at = now();
        profiles::write_json(
            &self.path,
            &Lease {
                touched: self.touched.min(at),
                until: at + LEASE_MS,
                target: target.filter(|_| self.enabled),
            },
            false,
        )
    }

    pub fn close(&mut self) {
        self.closed = true;
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn read(profiles: &Path) -> Result<Target, &'static str> {
    const UNAVAILABLE: &str = "В SSHnesh нет открытого SSH-сеанса для диагностики. Откройте нужную вкладку и проверьте, включён ли доступ к текущему серверу в меню MCP.";
    let now = now();
    let entries = fs::read_dir(directory(profiles)).map_err(|_| UNAVAILABLE)?;
    let latest = entries
        .flatten()
        .filter_map(|entry| {
            let path = entry.path();
            Uuid::parse_str(path.file_stem()?.to_str()?).ok()?;
            if path.extension()? != "json" || !entry.file_type().ok()?.is_file() {
                return None;
            }
            let meta = entry.metadata().ok()?;
            if meta.len() > 4096 {
                return None;
            }
            let record: Lease = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
            (record.touched <= now && record.until > now && record.until <= now + LEASE_MS)
                .then_some(record)
        })
        .max_by_key(|r| r.touched);
    latest.and_then(|r| r.target).ok_or(UNAVAILABLE)
}

// A snoozed or crashed window may leave a stale lease. Only clean up old files
// on startup; lookup ignores expiry without deleting files a live window may replace.
pub(crate) fn prune(profiles: &Path) {
    if let Ok(entries) = fs::read_dir(directory(profiles)) {
        for entry in entries.flatten() {
            let file = entry.path();
            if file.extension().is_some_and(|suffix| suffix == "json")
                && file
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .is_some_and(|s| Uuid::parse_str(s).is_ok())
                && entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .ok()
                    .and_then(|at| at.elapsed().ok())
                    .is_some_and(|age| age.as_secs() > 86_400)
            {
                let _ = fs::remove_file(file);
            }
        }
    }
}
