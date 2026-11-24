//! Android reader for the existing SSHnesh encrypted vault. The cloud snapshot
//! is cached encrypted; SSH secrets are only used in the native process.
use crate::{app::App, oauth, profiles};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ring::aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::HashMap, fs};
use zeroize::{Zeroize, Zeroizing};

const MAX_BODY: usize = 32 * 1024 * 1024;
const VAULT_ENDPOINT: &str = "https://sshnesh.xelopat.ru/vault.php";

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Envelope {
    version: u32,
    salt: String,
    iv: String,
    tag: String,
    body: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Remote {
    revision: u32,
    vault: Option<Envelope>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Snapshot {
    subject: String,
    revision: u32,
    vault: Envelope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Vault {
    #[serde(skip)]
    device_hosts: HashMap<String, Value>,
    #[serde(skip)]
    unlock_key: Option<(String,Zeroizing<[u8;32]>)>,
    hosts: Vec<Server>,
    #[serde(default)]
    pub groups: Vec<Group>,
    #[serde(default)]
    accounts: Vec<Login>,
    pub keys: HashMap<String, Key>,
    passwords: HashMap<String, Password>,
}

#[derive(Deserialize,Serialize)]
pub(crate) struct Group { id:String, label:String, members:Vec<String> }

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Server {
    id: String,
    label: String,
    #[serde(default)]
    group: String,
    host: String,
    port: u16,
    account_id: Option<String>,
    username: Option<String>,
    auth: Option<String>,
    key_id: Option<String>,
    #[serde(default)]
    sudo: bool,
    login_port: Option<std::num::NonZeroU16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Login {
    id: String,
    server_id: Option<String>,
    endpoint: Option<String>,
    username: String,
    auth: String,
    key_id: Option<String>,
    #[serde(default)]
    sudo: bool,
    login_port: Option<std::num::NonZeroU16>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Key {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    protected: bool,
    public_blob: String,
    #[serde(default)]
    pub(crate) comment: Option<String>,
    secret: String,
}

#[derive(Deserialize)]
struct Password {
    target: String,
    secret: String,
}

impl Drop for Key {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

impl Drop for Password {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

#[derive(Clone)]
pub(crate) struct Entry {
    pub id: String,
    pub label: String,
    pub group: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth: String,
    pub key_id: Option<String>,
    pub sudo: bool,
    pub login_port: Option<std::num::NonZeroU16>,
    credential_id: String,
    target: String,
}

impl Vault {
    fn remember_device(&mut self, device: &Value) {
        self.device_hosts = device["hosts"].as_array().into_iter().flatten()
            .filter_map(|host|Some((host["id"].as_str()?.to_owned(),host.clone()))).collect();
    }
    pub(crate) fn recorded(&self, id: &str) -> bool { self.device_hosts.contains_key(id) }
    pub(crate) fn matches_device(&self, mut host: Value) -> bool {
        if host["group"] == "" { host["group"] = json!("Серверы"); }
        host["id"].as_str().and_then(|id|self.device_hosts.get(id)) == Some(&host)
    }
    pub(crate) fn entry(&self, id: &str) -> Option<Entry> {
        let server = self.hosts.iter().find(|server| server.id == id)?;
        let (username, auth, key_id, credential_id, target) =
            if let Some(selected) = &server.account_id {
                let account = self.accounts.iter().find(|a| &a.id == selected)?;
                (
                    &account.username,
                    &account.auth,
                    &account.key_id,
                    &account.id,
                    json!([account.username]),
                )
            } else {
                let username = server.username.as_ref()?;
                (
                    username,
                    server.auth.as_ref()?,
                    &server.key_id,
                    &server.id,
                    json!([server.host, server.port, username]),
                )
            };
        if !valid_text(username, 120)
            || username.starts_with('-')
            || !matches!(auth.as_str(), "password" | "key" | "agent")
            || server.port == 0
            || !valid_text(&server.host, 253)
            || !valid_text(&server.label, 120)
        {
            return None;
        }
        Some(Entry {
            id: server.id.clone(),
            label: server.label.clone(),
            group: server.group.clone(),
            host: server.host.clone(),
            port: server.port,
            username: username.clone(),
            auth: auth.clone(),
            key_id: key_id.clone(),
            login_port: server.account_id.as_ref().and_then(|id|self.accounts.iter().find(|a| &a.id==id)).map_or(server.login_port, |a|a.login_port),
            sudo: server.account_id.as_ref().and_then(|id|self.accounts.iter().find(|a| &a.id==id)).map_or(server.sudo, |a|a.sudo),
            credential_id: credential_id.clone(),
            target: target.to_string(),
        })
    }

    pub(crate) fn hosts(&self) -> impl Iterator<Item = Value> + '_ {
        self.hosts.iter().filter_map(|host| self.entry(&host.id)).map(|entry| {
            let key = entry.key_id.as_ref().and_then(|id| self.keys.get(id));
            json!({"id":entry.id,"label":entry.label,"group":entry.group,"host":entry.host,"port":entry.port,
                "username":entry.username,"loginPort":entry.login_port,"sudo":entry.sudo,"auth":entry.auth,"cloud":true,"hasPassword":self.password_entry(&entry).is_some(),
                "keyId":entry.key_id,"keyProtected":key.is_some_and(|k| k.protected)})
        })
    }

    pub(crate) fn saved_entry(&self, server:&str, host:&str, port:u16, login:&str)->Result<Entry,String>{
        let address=json!([host,port]).to_string();
        let a=self.accounts.iter().find(|a|a.id==login && a.server_id.as_deref()==Some(server) && a.endpoint.as_deref()==Some(&address)).ok_or("Вход для этого адреса не найден.")?;
        Ok(Entry{id:server.into(),host:host.into(),port,label:String::new(),group:String::new(),username:a.username.clone(),
            login_port:a.login_port,sudo:a.sudo,auth:a.auth.clone(),key_id:a.key_id.clone(),credential_id:a.id.clone(),target:json!([host,port,a.username]).to_string()})
    }
    pub(crate) fn server_logins(&self,id:&str,host:&str,port:u16)->Vec<Value>{
        self.accounts.iter().filter_map(|a|{
            let e=self.saved_entry(id,host,port,&a.id).ok()?;
            Some(json!({"loginId":a.id,"loginPort":a.login_port,"sudo":a.sudo,"username":e.username,"auth":e.auth,"keyId":e.key_id,"hasPassword":self.password_entry(&e).is_some()}))
        }).collect()
    }
    fn password_entry(&self, entry: &Entry) -> Option<&Password> {
        self.passwords
            .get(&entry.credential_id)
            .filter(|item| item.target == entry.target)
    }

    pub(crate) fn password(&self, entry: &Entry) -> Result<Zeroizing<String>, String> {
        let item = self
            .password_entry(entry)
            .ok_or("Для этой учётки в облаке нет пароля.")?;
        decoded(&item.secret, 16_384)
    }

    pub(crate) fn key_list(&self) -> Vec<Value> {
        let mut keys: Vec<_> = self.keys.iter().collect();
        keys.sort_by(|a, b| a.1.name.cmp(&b.1.name));
        keys.into_iter()
            .map(|(id, key)| {
                use sha2::{Digest, Sha256};
                let blob = STANDARD.decode(&key.public_blob).expect("validated public blob");
                let digest = base64::engine::general_purpose::STANDARD_NO_PAD.encode(Sha256::digest(blob));
                json!({"id":id,"name":key.name,"type":key.kind,"fingerprint":format!("SHA256:{digest}"),
            "comment":key.comment,"protected":key.protected,"cloud":true})
            })
            .collect()
    }
}

impl Key {
    pub(crate) fn is_protected(&self) -> bool {
        self.protected
    }
    pub(crate) fn secret(&self) -> Result<Zeroizing<String>, String> {
        decoded(&self.secret, 128 * 1024)
    }
    pub(crate) fn public(&self) -> String {
        let public = format!("{} {}", self.kind, self.public_blob);
        match self.comment.as_deref().filter(|s| !s.is_empty()) {Some(c) => format!("{public} {c}"), None => public}
    }
}

fn decoded(value: &str, max: usize) -> Result<Zeroizing<String>, String> {
    if value.len() > (max + 2) / 3 * 4 {
        return Err("Некорректная запись в хранилище.".into());
    }
    let bytes = STANDARD
        .decode(value)
        .map_err(|_| "Некорректная запись в хранилище.")?;
    String::from_utf8(bytes)
        .map(Zeroizing::new)
        .map_err(|error| {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            "Некорректная запись в хранилище.".into()
        })
}

fn login_port(edit: &Value) -> Result<Option<std::num::NonZeroU16>, String> {
    serde_json::from_value(edit["loginPort"].clone()).map_err(|_| "Порт должен быть от 1 до 65535.".to_owned())
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.trim().is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], String> {
    if value.len() != 2 * N
        || !value
            .bytes()
            .all(|v| v.is_ascii_hexdigit() && !v.is_ascii_uppercase())
    {
        return Err("Некорректное облачное хранилище.".into());
    }
    let mut result = [0; N];
    for (i, item) in result.iter_mut().enumerate() {
        *item = u8::from_str_radix(&value[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
    }
    Ok(result)
}

struct Unlock<'a> { password: &'a str, saved: Option<(String,Zeroizing<[u8;32]>)> }
impl<'a> Unlock<'a> {
    fn manual(password:&'a str)->Self {Self{password,saved:None}}
    fn derive(&self,salt:&[u8;16])->Result<Zeroizing<[u8;32]>,String>{
        if let Some((id,key))=&self.saved {
            if decode_hex::<16>(id)?!=*salt {return Err("Ключ хранилища изменился. Введите мастер-пароль.".into());}
            return Ok(key.clone());
        }
        let mut key=Zeroizing::new([0;32]);
        scrypt::scrypt(self.password.as_bytes(),salt,&scrypt::Params::new(17,8,1).unwrap(),key.as_mut()).map_err(|_|"Ошибка получения ключа.")?;
        Ok(key)
    }
}
#[cfg(test)]
fn open(data:&Snapshot,password:&str)->Result<Value,String>{ open_with(data,&Unlock::manual(password)) }
#[cfg(test)]
fn seal(raw:&Value,password:&str,subject:&str,revision:u32,salt:Option<&str>)->Result<Snapshot,String>{
    seal_with(raw,&Unlock::manual(password),subject,revision,salt)
}

fn open_with(data: &Snapshot, unlock: &Unlock) -> Result<Value, String> {
    let envelope = &data.vault;
    if envelope.version != 1
        || !(1..=2_000_000_000).contains(&data.revision)
        || envelope.body.len() > MAX_BODY - 1024
        || envelope.body.is_empty()
    {
        return Err("Некорректное облачное хранилище.".into());
    }
    decode_hex::<8>(&data.subject)?;
    let salt = decode_hex::<16>(&envelope.salt)?;
    let iv = decode_hex::<12>(&envelope.iv)?;
    let tag = decode_hex::<16>(&envelope.tag)?;
    let key = unlock.derive(&salt)?;
    let cipher = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key.as_ref()).map_err(|_| "Ошибка расшифровки.")?,
    );
    let mut bytes = Zeroizing::new(
        STANDARD
            .decode(&envelope.body)
            .map_err(|_| "Некорректное облачное хранилище.")?,
    );
    bytes.extend_from_slice(&tag);
    let aad = json!(["sshnesh-vault", 1, data.subject, data.revision]).to_string();
    let plain = cipher
        .open_in_place(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_bytes()),
            &mut bytes,
        )
        .map_err(|_| "Не удалось открыть хранилище. Проверьте мастер-пароль.")?;
    serde_json::from_slice(plain).map_err(|_| "Некорректные данные хранилища.".into())
}

fn validate(raw: &Value) -> Result<Vault, String> {
    let vault: Vault = serde_json::from_value(raw.clone())
        .map_err(|_| "Формат хранилища повреждён или не поддерживается.")?;
    if vault.hosts.len() > 256
        || vault.accounts.len() > 256
        || vault.keys.len() > 64
        || vault.passwords.len() > 512
    {
        return Err("Слишком много записей в хранилище.".into());
    }
    let mut labels=std::collections::HashSet::new();
    if vault.groups.len()>256 || !vault.groups.iter().all(|g|uuid::Uuid::parse_str(&g.id).is_ok() && valid_text(&g.label,120) && labels.insert(&g.label) && g.members.len()<=256 && g.members.iter().all(|id|uuid::Uuid::parse_str(id).is_ok())){return Err("Некорректные группы серверов.".into());}
    let mut seen = std::collections::HashSet::new();
    if !vault
        .hosts
        .iter()
        .map(|s| &s.id)
        .chain(vault.accounts.iter().map(|a| &a.id))
        .all(|id| uuid::Uuid::parse_str(id).is_ok() && seen.insert(id))
        || !vault.keys.iter().all(|(id, key)| {
            id.len() == 43
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
                && valid_text(&key.name, 480)
                && key.kind.len() <= 96
                && key
                    .kind
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-@._".contains(&b))
                && key.public_blob.len() <= 16_384
                && STANDARD.decode(&key.public_blob).is_ok()
        })
    {
        return Err("Облачное хранилище содержит некорректную запись.".into());
    }
    Ok(vault)
}

fn seal_with(
    raw: &Value,
    unlock: &Unlock,
    subject: &str,
    revision: u32,
    prior_salt: Option<&str>,
) -> Result<Snapshot, String> {
    use ring::rand::{SecureRandom, SystemRandom};
    use std::fmt::Write;
    fn hex(bytes: &[u8]) -> String {
        let mut value = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            write!(value, "{b:02x}").unwrap();
        }
        value
    }
    let rng = SystemRandom::new();
    let mut salt = [0; 16];
    let mut iv = [0; 12];
    rng.fill(&mut salt)
        .and_then(|_| rng.fill(&mut iv))
        .map_err(|_| "Ошибка генератора случайных чисел.")?;
    if let Some(prior) = prior_salt {
        salt = decode_hex::<16>(prior)?;
    }
    let key = unlock.derive(&salt)?;
    let cipher = LessSafeKey::new(
        UnboundKey::new(&AES_256_GCM, key.as_ref()).map_err(|_| "Ошибка шифрования.")?,
    );
    let mut bytes = Zeroizing::new(serde_json::to_vec(raw).map_err(|e| e.to_string())?);
    let aad = json!(["sshnesh-vault", 1, subject, revision]).to_string();
    let tag = cipher
        .seal_in_place_separate_tag(
            Nonce::assume_unique_for_key(iv),
            Aad::from(aad.as_bytes()),
            bytes.as_mut_slice(),
        )
        .map_err(|_| "Ошибка шифрования.")?;
    let body = STANDARD.encode(&*bytes);
    if body.len() > MAX_BODY - 1024 {
        return Err("Хранилище слишком большое.".into());
    }
    Ok(Snapshot {
        subject: subject.to_owned(),
        revision,
        vault: Envelope {
            version: 1,
            salt: hex(&salt),
            iv: hex(&iv),
            tag: hex(tag.as_ref()),
            body,
        },
    })
}

fn snapshot_tag(snapshot: &Snapshot) -> String {
    use sha2::{Digest,Sha256};
    let v = &snapshot.vault;
    let mut hash = Sha256::new();
    for field in [&v.salt, &v.iv, &v.tag, &v.body] { hash.update(field.as_bytes()); }
    format!("\"{}-{:x}\"", snapshot.revision, hash.finalize())
}

async fn download(client: &reqwest::Client, url: &str, subject: String, token: &str, base: Option<&Snapshot>) -> Result<Option<Snapshot>, String> {
    let mut request = client.get(url).header("Accept","application/json").bearer_auth(token);
    if let Some(checkpoint) = base {
        request = request.header("If-None-Match",snapshot_tag(checkpoint));
    }
    let mut response = request.send().await.map_err(|_| "Сервер синхронизации недоступен.")?;
    if response.status() == reqwest::StatusCode::NOT_MODIFIED {
        return base.cloned().map(Some).ok_or_else(||"Некорректный ответ сервера.".into());
    }
    if response.status() == reqwest::StatusCode::UNAUTHORIZED {
        return Err("Войдите в аккаунт заново.".into());
    }
    if !response.status().is_success() {
        return Err("Сервер не отдал хранилище.".into());
    }
    let mut body = Vec::new();
    while let Some(piece) = response
        .chunk()
        .await
        .map_err(|_| "Не удалось загрузить хранилище.")?
    {
        if body.len() + piece.len() > MAX_BODY {
            return Err("Хранилище слишком большое.".into());
        }
        body.extend_from_slice(&piece);
    }
    let remote: Remote =
        serde_json::from_slice(&body).map_err(|_| "Некорректный ответ хранилища.")?;
    if remote.revision == 0 && remote.vault.is_none() {
        return Ok(None);
    }
    let vault = remote
        .vault
        .ok_or("В аккаунте ещё нет сохранённого хранилища.")?;
    Ok(Some(Snapshot {
        subject,
        revision: remote.revision,
        vault,
    }))
}

async fn upload(client: &reqwest::Client, url: &str, token: &str, prior: u32, sealed: &Snapshot) -> Result<(), String> {
    let res = client.put(url).bearer_auth(token)
        .json(&json!({"revision":prior,"vault":&sealed.vault})).send().await.map_err(|_|"Ошибка отправки хранилища.")?;
    if !res.status().is_success() { return Err("Облако отклонило запись. Повторите синхронизацию.".into()); }
    let reply: Value = res.json().await.map_err(|_|"Некорректный ответ сервера.")?;
    if reply["revision"] != sealed.revision { return Err("Сервер вернул неверную ревизию.".into()); }
    Ok(())
}

#[derive(Serialize, Deserialize)]
struct Workspace {
    base: Option<Snapshot>,
    working: Snapshot,
}

fn read_file<T: serde::de::DeserializeOwned>(
    path: &std::path::Path,
    max: u64,
) -> Result<Option<T>, String> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.to_string()),
    };
    if file.metadata().map_err(|e| e.to_string())?.len() > max {
        return Err("Файл хранилища слишком большой.".into());
    }
    serde_json::from_reader(file)
        .map(Some)
        .map_err(|_| "Не удалось прочитать зашифрованное хранилище.".into())
}

fn empty() -> Value {
    json!({"hosts":[],"accounts":[],"keys":{},"passwords":{}})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    #[ignore = "requires an isolated local PHP sync service"]
    async fn native_php_sync() {
        let url = std::env::var("SSHNESH_TEST_VAULT_URL").unwrap();
        assert_eq!(reqwest::Url::parse(&url).unwrap().host_str(), Some("127.0.0.1"));
        let token = std::env::var("SSHNESH_TEST_SESSION").unwrap();
        let client = reqwest::Client::new();
        let owner = "0011223344556677";
        let master = "local integration test password";
        assert!(download(&client,&url,owner.into(),&token,None).await.unwrap().is_none());
        let base = empty();
        let first = seal(&base,master,owner,1,None).unwrap();
        upload(&client,&url,&token,0,&first).await.unwrap();
        let downloaded = download(&client,&url,owner.into(),&token,None).await.unwrap().unwrap();
        let cached_response = client.get(&url).bearer_auth(&token)
            .header("If-None-Match",snapshot_tag(&downloaded)).send().await.unwrap();
        assert_eq!(cached_response.status(),reqwest::StatusCode::NOT_MODIFIED);
        assert_eq!(cached_response.bytes().await.unwrap().len(),0);
        let mut here = open(&downloaded,master).unwrap();
        let mut there = here.clone();
        let key = crate::portable_key::generate("from Windows").unwrap();
        here["keys"][key["id"].as_str().unwrap()] = key.clone();
        there["hosts"] = json!([{"id":uuid::Uuid::new_v4().to_string(),"host":"example.test","label":"Linux server","group":"Servers","port":22,"username":"debug","auth":"password"}]);
        let host_id=there["hosts"][0]["id"].clone();
        here["groups"]=json!([{"id":uuid::Uuid::new_v4(),"label":"Empty","members":[]},
            {"id":uuid::Uuid::new_v4(),"label":"Ops","members":[host_id]}]);
        there["groups"]=json!([{"id":uuid::Uuid::new_v4(),"label":"Prod","members":[host_id]}]);
        let second = seal(&there,master,owner,2,Some(&first.vault.salt)).unwrap();
        upload(&client,&url,&token,1,&second).await.unwrap();
        assert!(upload(&client,&url,&token,1,&second).await.is_err());
        let latest = download(&client,&url,owner.into(),&token,None).await.unwrap().unwrap();
        let merged = crate::vault_merge::merge(&base,&here,&open(&latest,master).unwrap(),|_,_|panic!("unexpected conflict")).unwrap();
        let third = seal(&merged,master,owner,3,Some(&latest.vault.salt)).unwrap();
        upload(&client,&url,&token,2,&third).await.unwrap();
        let recovered = download(&client,&url,owner.into(),&token,None).await.unwrap().unwrap();
        let data = open(&recovered,master).unwrap();
        assert!(data["hosts"]==there["hosts"] && data["keys"]==here["keys"]);
        let checked=validate(&data).unwrap();
        assert_eq!(checked.groups.len(),3);
        assert!(checked.groups.iter().any(|g|g.label=="Empty" && g.members.is_empty()));
        assert_eq!(checked.groups.iter().filter(|g|g.members.iter().any(|id|host_id==id.as_str())).count(),2);
    }

    #[test]
    fn legacy_checkpoint_can_open_following_revision() {
        let owner = "0011223344556677";
        let master = "fixture password for upgrade";
        let mut old = empty();
        let key = crate::portable_key::generate("previous version").unwrap();
        old["keys"][key["id"].as_str().unwrap()] = key.clone();
        let checkpoint = seal(&old, master, owner, 1, None).unwrap();
        let new_key = crate::portable_key::generate("new version").unwrap();
        let mut updated = open(&checkpoint, master).unwrap();
        updated["keys"][new_key["id"].as_str().unwrap()] = new_key.clone();
        let next = seal(&updated, master, owner, 2, Some(&checkpoint.vault.salt)).unwrap();
        assert_eq!(checkpoint.vault.salt, next.vault.salt);
        assert_ne!(checkpoint.vault.iv, next.vault.iv);
        assert!(open(&next, master).unwrap() == updated);
        assert!(open(&checkpoint, master).unwrap() == old);
        assert_eq!(validate(&updated).unwrap().keys.len(), 2);
    }
}

pub(crate) async fn load(
    app: &App,
    action: &str,
    password: Zeroizing<String>,
    edit: Value,
) -> Result<(), String> {
    if password.len() > 1024 {
        return Err("Введите мастер-пароль.".into());
    }
    let replace = action == "replace";
    if replace && (edit["confirmed"] != true || password.chars().count() < 16) {
        return Err("Подтвердите замену и задайте новый мастер-пароль от 16 символов.".into());
    }
    let sync = matches!(action, "pull" | "push" | "replace");
    let (session, owner) = {
        let mut inner = app.inner.lock().unwrap();
        if inner.cloud_loading {
            return Err("Дождитесь завершения операции.".into());
        }
        let session = if sync {
            Some(inner.oauth.cloud_session()?)
        } else {
            None
        };
        let owner = inner
            .oauth
            .cloud_subject()
            .map(str::to_owned)
            .or_else(|| inner.cloud_owner.clone());
        inner.cloud_loading = true;
        (session, owner)
    };
    app.changed();
    let result = async {
        let mut legacy: Option<Snapshot> = read_file(&app.profiles_path.with_file_name("android-cloud-vault.json"), MAX_BODY as u64)?;
        #[cfg(desktop)]
        if legacy.is_none() {
            #[derive(Deserialize)]
            struct LegacyWorkspace { checkpoint: Option<Snapshot> }
            use tauri::Manager;
            let path = app.handle.path().config_dir().map_err(|e|e.to_string())?
                .join("sshash").join("workspace.json");
            legacy = read_file::<LegacyWorkspace>(&path, 4 * MAX_BODY as u64)?.and_then(|w|w.checkpoint);
        }
        let marker = app.profiles_path.with_file_name("vault-account.json");
        let prior_owner = read_file::<String>(&marker, 128)?;
        let draft_subject = "0000000000000000";
        let subject = owner.or(prior_owner.clone()).or_else(|| legacy.as_ref().map(|s|s.subject.clone()))
            .or_else(|| matches!(action,"generateKey" | "importKey" | "saveGroup" | "saveLogin").then(||draft_subject.to_owned()))
            .ok_or("На устройстве нет сохранённого хранилища.")?;
        decode_hex::<8>(&subject)?;
        let path = app.profiles_path.with_file_name(format!("vault-{subject}.json"));
        let previous: Option<Workspace> = read_file(&path, (2*MAX_BODY+2048) as u64)?;
        let previous = previous.or_else(|| legacy.filter(|v| v.subject == subject).map(|v|Workspace {base:Some(v.clone()),working:v}));
        if previous.as_ref().is_some_and(|w| w.working.subject != subject || w.base.as_ref().is_some_and(|b| b.subject != subject)) {
            return Err("Копия относится к другому аккаунту.".into());
        }
        let remember_path=app.profiles_path.with_file_name("remembered-owner.json");
        let remembered:Option<String>=read_file(&remember_path,128)?;
        let memory_key = {
            let inner = app.inner.lock().unwrap();
            inner.cloud.as_ref().filter(|_| inner.cloud_owner.as_deref()==Some(&subject))
                .and_then(|vault|vault.unlock_key.clone())
        };
        let unlock=if password.is_empty() && memory_key.is_some() {
            Unlock{password:"",saved:memory_key.clone()}
        }else if password.is_empty(){
            if remembered.as_deref()!=Some(subject.as_str()){return Err("Введите мастер-пароль.".into());}
            let stored=crate::device_key::access(app,&subject,crate::device_key::Operation::Read)?;
            let (salt,encoded)=stored.trim_end().split_once(':').ok_or("Повреждён сохранённый ключ.")?;
            let mut key=Zeroizing::new([0;32]);
            if STANDARD.decode_slice(encoded,key.as_mut()).ok()!=Some(32){return Err("Повреждён сохранённый ключ.".into());}
            Unlock{password:"",saved:Some((salt.to_owned(),key))}
        }else{Unlock::manual(&password)};
        let enroll=|salt:&str|->Result<(),String>{
            if edit.get("rememberDevice")==Some(&Value::Bool(true)) && !password.is_empty(){
                let key=unlock.derive(&decode_hex::<16>(salt)?)?;
                let mut encoded=Zeroizing::new(format!("{salt}:"));
                STANDARD.encode_string(key.as_ref(),&mut encoded);
                if let Some(old)=remembered.as_ref().filter(|old|*old!=&subject){
                    crate::device_key::access(app,old,crate::device_key::Operation::Forget)?;
                }
                crate::device_key::access(app,&subject,crate::device_key::Operation::Store(&encoded))?;
                profiles::write_json(&remember_path,&subject,true).map_err(|e|e.to_string())?;
            }
            Ok(())
        };
        let mut base = previous.as_ref().and_then(|v|v.base.clone());
        let remote = if let Some((_,token)) = &session { download(&oauth::client()?, VAULT_ENDPOINT, subject.clone(), token, base.as_ref()).await? } else { None };
        let remote_revision = remote.as_ref().map_or(0,|v|v.revision);

        if previous.is_none() && remote.is_none() && password.chars().count() < 16 { return Err("Задайте мастер-пароль от 16 символов.".into()); }
        let mut decoded = match (&previous, replace) {
            (Some(v), true) if memory_key.is_some() => open_with(&v.working,&Unlock{password:"",saved:memory_key})?,
            (_, true) => empty(),
            (Some(v), false) => open_with(&v.working,&unlock)?,
            (None, false) => empty(),
        };
        let mut device = decoded.get_mut("device").map(Value::take).unwrap_or_else(empty);
        let mut working = decoded.get_mut("vault").map(Value::take).unwrap_or(decoded);
        if action == "unlock" {
            if previous.is_none() { return Err("На устройстве нет сохранённого хранилища.".into()); }
            let mut vault = validate(&working)?;
            vault.remember_device(&device);
            let salt = &previous.as_ref().unwrap().working.vault.salt;
            vault.unlock_key = Some((salt.clone(),unlock.derive(&decode_hex::<16>(salt)?)?));
            let mut inner = app.inner.lock().unwrap();
            if inner.oauth.cloud_subject().is_some_and(|current|current != subject) { return Err("Аккаунт изменился.".into()); }
            enroll(&previous.as_ref().unwrap().working.vault.salt)?;
            inner.cloud = Some(vault);
            inner.cloud_owner = Some(subject);
            return Ok(());
        }
        if sync {
            if !replace && prior_owner.as_deref() == Some(draft_subject) && subject != draft_subject {
                let draft_file = app.profiles_path.with_file_name(format!("vault-{draft_subject}.json"));
                if let Some(draft) = read_file::<Workspace>(&draft_file,(2*MAX_BODY+2048) as u64)? {
                    let decoded = open_with(&draft.working,&unlock)?;
                    let draft_vault = decoded.get("vault").unwrap_or(&decoded);
                    working = crate::vault_merge::merge(&empty(),&working,draft_vault,|_,_|Err("В локальном хранилище и аккаунте разные записи с одним идентификатором.".into()))?;
                }
            }
            let local = app.local_vault();
            for prior in device["hosts"].as_array().into_iter().flatten() {
                let id = prior["id"].as_str().ok_or("Некорректная запись устройства.")?;
                if !local["hosts"].as_array().unwrap().iter().any(|h| h["id"] == id) {
                    working["hosts"].as_array_mut().ok_or("Некорректная адресная книга.")?.retain(|h|h["id"]!=id);
                    working["passwords"].as_object_mut().ok_or("Некорректный список паролей.")?.remove(id);
                }
            }
            for host in local["hosts"].as_array().unwrap() {
                let id = host["id"].as_str().ok_or("У сервера нет идентификатора.")?;
                let prior = device["hosts"].as_array().and_then(|items|items.iter().find(|entry|entry["id"]==id));
                let password_changed = local["passwords"].get(id).is_some() && local["passwords"][id]!=device["passwords"][id];
                if prior == Some(host) && !password_changed { continue; }
                let hosts = working["hosts"].as_array_mut().ok_or("Некорректная адресная книга.")?;
                if let Some(existing) = hosts.iter_mut().find(|v| v["id"] == id) {
                    if existing.get("accountId").is_some() || (existing["auth"] != "password" && prior.is_none_or(|v|v["auth"]!=existing["auth"])) { continue; }
                    let changed_target = ["host","port","username"].iter().any(|field| existing[*field] != host[*field]);
                    for (key,value) in host.as_object().unwrap() { existing[key] = value.clone(); }
                    if host["auth"]!="key" {existing.as_object_mut().unwrap().remove("keyId");}
                    if changed_target || host["auth"]!="password" { working["passwords"].as_object_mut().ok_or("Некорректный список паролей.")?.remove(id); }
                } else { hosts.push(host.clone()); }
                if let Some(password) = local["passwords"].get(id) { working["passwords"][id] = password.clone(); }
            }
            device = local;
            let unchanged = base.as_ref().map(snapshot_tag)==remote.as_ref().map(snapshot_tag);
            if !replace && !unchanged {
            let old = match &base {Some(v)=>open_with(v,&unlock)?,None=>empty()};
            let latest = match &remote {Some(v)=>open_with(v,&unlock)?,None=>empty()};
            if remote.is_some() { validate(&latest)?; }
            // Bind the decision to the actual compared records. A second device can
            // change either side while the user is reading the conflict dialog.
            use sha2::{Digest,Sha256};
            let comparison = format!("{:x}",Sha256::digest(serde_json::to_vec(&(&subject,remote_revision,&old,&working,&latest)).map_err(|e|e.to_string())?));
            working = crate::vault_merge::merge(&old,&working,&latest,|group,id| {
                let selector = format!("{comparison}/{group}/{id}");
                edit.get(&selector).and_then(Value::as_bool).ok_or_else(|| {
                    let label = if group == "keys" { latest[group][id]["name"].as_str() } else {
                        latest[group].as_array().and_then(|items|items.iter().find(|item|item["id"]==id)).and_then(|item|item["label"].as_str())
                    };
                    format!("SSH_CONFLICT {}",json!({"selector":selector,"label":label.unwrap_or(id)}))
                })
            })?;
            }
            base = remote;
        } else {
            match action {
                "saveGroup" => {
                    let label=edit["label"].as_str().map(str::trim).filter(|s|valid_text(s,120)).ok_or("Введите название группы.")?;
                    let members:Vec<String>=serde_json::from_value(edit["members"].clone()).map_err(|_|"Выберите серверы.")?;
                    if working.get("groups").is_none(){working["groups"]=json!([]);}
                    let groups=working["groups"].as_array_mut().ok_or("Некорректные группы.")?;
                    let existing=groups.iter().position(|g|g["id"]==edit["groupId"] || g["label"]==label);
                    if let Some(i)=existing {groups[i]["members"]=json!(members);} else {
                        use sha2::{Digest,Sha256};
                        let digest=Sha256::digest(label.as_bytes());
                        let id=uuid::Uuid::from_slice(&digest[..16]).unwrap().to_string();
                        groups.push(json!({"id":id,"label":label,"members":members}));
                    }
                }
                "saveLogin" => {
                    let server=edit["id"].as_str().ok_or("Выберите сервер.")?;
                    let host=app.snapshot()["hosts"].as_array().and_then(|hs|hs.iter().find(|h|h["id"]==server)).cloned().ok_or("Сервер не найден.")?;
                    let username=edit["username"].as_str().map(str::trim).filter(|s|valid_text(s,120)&&!s.starts_with('-')).ok_or("Введите пользователя SSH.")?;
                    let addr=json!([host["host"],host["port"]]).to_string();
                    let target=json!([host["host"],host["port"],username]).to_string();
                    let auth=edit["auth"].as_str().ok_or("Выберите способ входа.")?;
                    if auth=="key" && edit["keyId"].as_str().and_then(|k|working["keys"].get(k)).is_none(){return Err("Выберите ключ.".into());}
                    if !matches!(auth,"password"|"key") && !(auth=="agent"&&!cfg!(mobile)){return Err("Способ входа недоступен.".into());}
                    let id=edit["loginId"].as_str().map(str::to_owned).unwrap_or_else(||uuid::Uuid::new_v4().to_string());
                    if working.get("accounts").is_none(){working["accounts"]=json!([]);}
                    let accounts=working["accounts"].as_array_mut().ok_or("Некорректные учётки.")?;
                    let value=json!({"id":id,"loginPort":login_port(&edit)?,"sudo":edit["sudo"]==true,"serverId":server,"endpoint":addr,"username":username,"auth":auth,"keyId":edit["keyId"].as_str().filter(|_|auth=="key")});
                    if edit["loginId"].is_string(){
                        let old=accounts.iter_mut().find(|a|a["id"]==id && a["serverId"]==server && a["endpoint"]==addr).ok_or("Вход изменился.")?;
                        *old=value;
                    }else{accounts.push(value);}
                    if auth=="password" {
                        let pw=edit["password"].as_str().unwrap_or("");
                        if pw.len()>4096{return Err("Слишком длинный пароль.".into());}
                        if !pw.is_empty(){working["passwords"][&id]=json!({"target":target,"secret":STANDARD.encode(pw.as_bytes())});}
                        if working["passwords"][&id]["target"]!=target{return Err("Введите пароль SSH.".into());}
                    }else if let Some(map)=working["passwords"].as_object_mut(){map.remove(&id);}
                }
                "editLogin" => {
                    let id=edit["id"].as_str().ok_or("Не выбран сервер.")?;
                    let username=edit["username"].as_str().map(str::trim).filter(|s|valid_text(s,120) && !s.starts_with('-')).ok_or("Введите имя пользователя SSH.")?;
                    let auth=edit["auth"].as_str().ok_or("Выберите способ входа.")?;
                    let old=validate(&working)?.entry(id).ok_or("Сервер уже удалён.")?;
                    if auth=="key" {
                        let key=edit["keyId"].as_str().ok_or("Выберите ключ.")?;
                        if working["keys"].get(key).is_none(){return Err("Ключ недоступен.".into());}
                    } else if auth!="password" && !(auth=="agent" && !cfg!(target_os="android")) {
                        return Err("Неизвестный способ входа.".into());
                    }
                    let target=json!([old.host,old.port,username]).to_string();
                    let secret=edit["password"].as_str().unwrap_or("");
                    if secret.len()>4096 {return Err("Слишком длинный пароль.".into());}
                    let credential=if auth!="password" { None } else if !secret.is_empty() {
                        Some(json!({"target":target,"secret":STANDARD.encode(secret.as_bytes())}))
                    } else if username==old.username && old.auth=="password" {
                        working["passwords"].get(&old.credential_id).filter(|p|p["target"]==old.target)
                            .map(|p|json!({"target":target,"secret":p["secret"]}))
                    } else { None };
                    if auth=="password" && credential.is_none(){return Err("Введите пароль для этого пользователя.".into());}
                    let host=working["hosts"].as_array_mut().and_then(|hs|hs.iter_mut().find(|h|h["id"]==id))
                        .and_then(Value::as_object_mut).ok_or("Сервер не найден.")?;
                    host.remove("accountId");
                    host.insert("loginPort".into(),json!(login_port(&edit)?));
                    host.insert("sudo".into(),json!(edit["sudo"]==true));
                    host.insert("username".into(),json!(username));
                    host.insert("auth".into(),json!(auth));
                    if auth=="key" {host.insert("keyId".into(),edit["keyId"].clone());} else {host.remove("keyId");}
                    let passwords=working["passwords"].as_object_mut().ok_or("Некорректные пароли.")?;
                    if let Some(value)=credential {passwords.insert(id.to_owned(),value);} else {passwords.remove(id);}
                }
                "editHost" | "removeHost" => {
                    let id = edit["id"].as_str().ok_or("Не выбран сервер.")?;
                    let hosts = working["hosts"].as_array_mut().ok_or("Некорректная адресная книга.")?;
                    let index = hosts.iter().position(|host| host["id"]==id).ok_or("Сервер уже удалён.")?;
                    if action == "removeHost" {
                        hosts.remove(index);
                        working["passwords"].as_object_mut().ok_or("Некорректные пароли.")?.remove(id);
                    } else {
                        for (field,max) in [("label",120),("host",253),("group",120)] {
                            let text=edit[field].as_str().ok_or("Проверьте поля сервера.")?.trim();
                            if !(field=="group" && text.is_empty()) && !valid_text(text,max) {return Err("Проверьте поля сервера.".into());}
                            hosts[index][field]=json!(text);
                        }
                        let port=edit["port"].as_u64().filter(|p|(1..=65535).contains(p)).ok_or("Проверьте порт.")?;
                        hosts[index]["port"]=json!(port);
                    }
                }
                "keyComment" => {
                    let id = edit["id"].as_str().ok_or("Выберите ключ.")?;
                    let comment = edit["comment"].as_str().ok_or("Введите комментарий.")?;
                    if comment.chars().count()>256 || comment.chars().any(char::is_control) { return Err("Комментарий должен быть одной строкой до 256 символов.".into()); }
                    let key=working["keys"].get_mut(id).ok_or("Ключ не найден.")?;
                    key["comment"]=json!(comment);
                }
                "removeKey" => {
                    if edit["confirmed"]!=true {return Err("Подтвердите удаление ключа.".into());}
                    let id = edit["id"].as_str().ok_or("Выберите ключ.")?;
                    let references = |row: &Value| row["keyId"].as_str() == Some(id);
                    let snapshot = app.snapshot();
                    let used = ["accounts", "hosts"].iter().any(|field|
                        working[*field].as_array().is_some_and(|rows| rows.iter().any(references)))
                        || snapshot["hosts"].as_array().is_some_and(|hosts| hosts.iter().any(references));
                    if used { return Err("Сначала выберите другой ключ или способ входа для связанных учёток.".into()); }
                    working["keys"].as_object_mut().and_then(|keys| keys.remove(id)).ok_or("Ключ уже удалён.")?;
                }
                "generateKey" | "importKey" => {
                    let name = edit["name"].as_str().ok_or("Введите название ключа.")?;
                    let key = if action == "generateKey" { crate::portable_key::generate(name)? }
                        else { crate::portable_key::import(name,edit["raw"].as_str().ok_or("Выберите файл.")?,edit["phrase"].as_str())? };
                    let mut key = key;
                    if let Some(comment) = edit["comment"].as_str() {
                        if comment.chars().count()>256 || comment.chars().any(char::is_control) {return Err("Проверьте комментарий.".into());}
                        key["comment"]=json!(comment);
                    }
                    let id = key["id"].as_str().unwrap().to_owned();
                    if working["keys"].get(&id).is_some() { return Err("Этот ключ уже есть в хранилище.".into()); }
                    working["keys"][id] = key;
                }
                _ => return Err("Хранилище ещё не создано.".into()),
            }
        }
        let mut vault = validate(&working)?;
        vault.remember_device(&device);
        let revision = if action == "push" || replace {remote_revision.checked_add(1).filter(|r|*r<=2_000_000_000).ok_or("Достигнут предел ревизий.")?} else {base.as_ref().map_or(1,|s|s.revision)};
        let prior_salt = if replace {None} else {base.as_ref().map(|s|s.vault.salt.as_str()).or_else(||previous.as_ref().map(|w|w.working.vault.salt.as_str()))};
        let sealed = seal_with(&working,&unlock,&subject,revision,prior_salt)?;
        vault.unlock_key=Some((sealed.vault.salt.clone(),unlock.derive(&decode_hex::<16>(&sealed.vault.salt)?)?));
        let saved = seal_with(&json!({"vault":working,"device":device}),&unlock,&subject,revision,Some(&sealed.vault.salt))?;
        if let Some((_,token)) = &session {
            if app.inner.lock().unwrap().oauth.cloud_subject() != Some(subject.as_str()) { return Err("Войдите в аккаунт заново.".into()); }
            if action == "push" || replace {
                if replace {
                    if let Some(remote_copy) = &base {
                        let backup = path.with_file_name(format!("vault-{subject}-cloud-before-reset-{}.json",uuid::Uuid::new_v4()));
                        profiles::write_json(&backup,remote_copy,true).map_err(|e|e.to_string())?;
                    }
                    if let Some(old) = &previous {
                        let backup = path.with_file_name(format!("vault-{subject}-before-reset-{}.json",uuid::Uuid::new_v4()));
                        profiles::write_json(&backup,old,true).map_err(|e|e.to_string())?;
                    }
                }
                upload(&oauth::client()?, VAULT_ENDPOINT, token, remote_revision, &sealed).await?;
                base = Some(sealed.clone());
            }
        }
        let mut inner = app.inner.lock().unwrap();
        if inner.oauth.cloud_subject().is_some_and(|id|id!=subject) || (sync && inner.oauth.cloud_subject().is_none()) { return Err("Аккаунт изменился.".into()); }
        let salt=saved.vault.salt.clone();
        profiles::write_json(&path,&Workspace{base,working:saved},true).map_err(|e|e.to_string())?;
        profiles::write_json(&marker,&subject,true).map_err(|e|e.to_string())?;
        if replace && remembered.as_ref()==Some(&subject) && edit["rememberDevice"]!=true {
            fs::remove_file(&remember_path).map_err(|e|e.to_string())?;
            crate::device_key::access(app,&subject,crate::device_key::Operation::Forget)?;
        }
        enroll(&salt)?;
        inner.cloud = Some(vault);
        inner.cloud_owner = Some(subject);
        Ok(())
    }.await;
    app.inner.lock().unwrap().cloud_loading = false;
    app.changed();
    result
}

pub(crate) fn forget(app:&App)->Result<(),String>{
    let path=app.profiles_path.with_file_name("remembered-owner.json");
    let mut inner=app.inner.lock().unwrap();
    if inner.cloud_loading {return Err("Дождитесь завершения операции.".into());}
    inner.cloud=None;
    inner.cloud_owner=None;
    if let Some(owner)=read_file::<String>(&path,128)?{
        crate::device_key::access(app,&owner,crate::device_key::Operation::Forget)?;
        fs::remove_file(path).map_err(|e|e.to_string())?;
    }
    drop(inner);
    app.changed();
    Ok(())
}
