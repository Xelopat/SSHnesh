use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use russh::keys::{decode_secret_key, Algorithm, PrivateKey};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

pub(crate) fn generate(name: &str) -> Result<Value, String> {
    let key = PrivateKey::random(&mut rand::rng(), Algorithm::Ed25519)
        .map_err(|_| "Не удалось создать ключ Ed25519.")?;
    let encoded = key
        .to_openssh(Default::default())
        .map_err(|_| "Ошибка записи ключа.")?;
    record(name, &encoded, key, false)
}

pub(crate) fn import(name: &str, raw: &str, phrase: Option<&str>) -> Result<Value, String> {
    if raw.is_empty() || raw.len() > 128 * 1024 {
        return Err("Размер файла ключа должен быть от 1 байта до 128 КиБ.".into());
    }
    let (key, protected) = match decode_secret_key(raw, None) {
        Ok(key) => (key, false),
        Err(_) => {
            let phrase = phrase.ok_or("Введите парольную фразу или проверьте формат ключа.")?;
            let key =
                decode_secret_key(raw, Some(phrase)).map_err(|_| "Не удалось открыть ключ.")?;
            (key, true)
        }
    };
    record(name, raw, key, protected)
}

fn record(name: &str, raw: &str, key: PrivateKey, protected: bool) -> Result<Value, String> {
    let name = name.trim();
    if name.is_empty() || name.chars().count() > 120 || name.chars().any(char::is_control) {
        return Err("Введите название ключа длиной до 120 символов.".into());
    }
    let public = key.public_key();
    let blob = public
        .to_bytes()
        .map_err(|_| "Не удалось прочитать публичный ключ.")?;
    let comment: &str = key.comment().as_ref();
    Ok(
        json!({"id":URL_SAFE_NO_PAD.encode(Sha256::digest(&blob)), "name":name,
        "type":public.algorithm().to_string(), "publicBlob":STANDARD.encode(&blob),
        "comment":comment,"protected":protected,"secret":STANDARD.encode(raw.as_bytes())}),
    )
}

pub(crate) fn export(raw: &str, old: Option<&str>, new: Option<&str>, comment: Option<&str>) -> Result<zeroize::Zeroizing<String>, String> {
    let mut key = decode_secret_key(raw, old).map_err(|_| "Проверьте парольную фразу исходного ключа.")?;
    if let Some(text) = comment { key.set_comment(text); }
    if let Some(phrase) = new {
        if phrase.is_empty() { return Err("Введите парольную фразу для файла.".into()); }
        key = key.encrypt(&mut rand::rng(), phrase).map_err(|_| "Не удалось зашифровать SSH-ключ.")?;
    }
    key.to_openssh(Default::default()).map_err(|_| "Не удалось записать SSH-ключ.".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn import_preserves_generated_identity_and_private_bytes() {
        let first = generate("fixture").unwrap();
        let secret = STANDARD.decode(first["secret"].as_str().unwrap()).unwrap();
        let restored = import("fixture", std::str::from_utf8(&secret).unwrap(), None).unwrap();
        assert!(first == restored);
    }
}
