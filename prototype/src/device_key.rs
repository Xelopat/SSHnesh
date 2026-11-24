use crate::app::App;
use zeroize::Zeroizing;
pub(crate) enum Operation<'a> { Read, Store(&'a str), Forget }
pub(crate) fn access(app: &App, owner: &str, op: Operation<'_>) -> Result<Zeroizing<String>,String> {
    let identifier=owner.strip_prefix("oauth-").unwrap_or(owner);
    if identifier.len()!=16 || !identifier.bytes().all(|b| b.is_ascii_hexdigit()) {return Err("Некорректный аккаунт.".into());}
    #[cfg(target_os="android")]
    { platform(app,owner,op) }
    #[cfg(not(target_os="android"))]
    { let _=app; platform(owner,op) }
}
#[cfg(windows)]
fn platform(owner:&str, op:Operation<'_>) -> Result<Zeroizing<String>,String> {
    use windows_sys::Win32::Security::Credentials::*;
    use std::ptr;
    let mut target:Vec<u16>=format!("SSHnesh/Vault/{owner}").encode_utf16().chain(Some(0)).collect();
    let err=||format!("Диспетчер учётных данных Windows: {}",std::io::Error::last_os_error());
    let mut result=Zeroizing::new(String::new());
    unsafe {
        match op {
            Operation::Store(value)=>{
                let mut entry:CREDENTIALW=std::mem::zeroed();
                entry.Type=CRED_TYPE_GENERIC;
                entry.TargetName=target.as_mut_ptr();
                entry.Persist=CRED_PERSIST_LOCAL_MACHINE;
                entry.CredentialBlob=value.as_ptr() as *mut u8;
                entry.CredentialBlobSize=value.len() as u32;
                if CredWriteW(&entry,0)==0 {return Err(err());}
            }
            Operation::Forget=>{if CredDeleteW(target.as_ptr(),CRED_TYPE_GENERIC,0)==0 && std::io::Error::last_os_error().raw_os_error()!=Some(1168) {return Err(err());}}
            Operation::Read=>{
                let mut cred=ptr::null_mut();
                if CredReadW(target.as_ptr(),CRED_TYPE_GENERIC,0,&mut cred)==0 {return Err(err());}
                let value=&*cred;
                let valid=value.CredentialBlobSize>0 && value.CredentialBlobSize<=512 && !value.CredentialBlob.is_null();
                if valid {
                    if let Ok(s)=std::str::from_utf8(std::slice::from_raw_parts(value.CredentialBlob,value.CredentialBlobSize as usize)){result.push_str(s);}
                }
                CredFree(cred.cast());
                if result.is_empty(){return Err("Сохранённый ключ повреждён.".into());}
            }
        }
    }
    Ok(result)
}
#[cfg(target_os="linux")]
fn platform(owner:&str,op:Operation<'_>)->Result<Zeroizing<String>,String>{
    use std::{process::{Command,Stdio},io::Write};
    let mut cmd=Command::new("/usr/bin/secret-tool");
    match op {
        Operation::Read=>{cmd.arg("lookup");}
        Operation::Forget=>{cmd.arg("clear");}
        Operation::Store(_)=>{cmd.args(["store","--label=SSHnesh"]); }
    }
    cmd.args(["application","ru.xelopat.sshnesh","account",owner]).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    let mut child=cmd.spawn().map_err(|_|"Системная связка ключей недоступна.")?;
    if let Operation::Store(value)=op {child.stdin.take().unwrap().write_all(value.as_bytes()).map_err(|_|"Не удалось сохранить ключ.")?;}
    let output=child.wait_with_output().map_err(|_|"Ошибка системной связки ключей.")?;
    if !output.status.success(){return Err("Откройте системную связку ключей или введите мастер-пароль.".into());}
    String::from_utf8(output.stdout).map(Zeroizing::new).map_err(|_|"Повреждённый ключ.".into())
}
#[cfg(target_os="android")]
fn platform(app:&App,owner:&str,op:Operation<'_>)->Result<Zeroizing<String>,String>{
    use tauri::Manager;
    let (method,value)=match op{Operation::Read=>("read", ""),Operation::Forget=>("forget",""),Operation::Store(v)=>("store",v)};
    let data:serde_json::Value=app.handle.state::<tauri::plugin::PluginHandle<tauri::Wry>>().run_mobile_plugin(method,serde_json::json!({"owner":owner,"value":value})).map_err(|_|"Android Keystore недоступен. Разблокируйте устройство или введите мастер-пароль.")?;
    Ok(Zeroizing::new(data["value"].as_str().unwrap_or("").to_owned()))
}

#[cfg(all(test,target_os="linux"))]
mod tests {
    use super::*;
    #[test]
    #[ignore="requires a disposable unlocked Secret Service collection"]
    fn linux_system_keyring() {
        let owner=uuid::Uuid::new_v4().simple().to_string();
        let owner=&owner[..16];
        platform(owner,Operation::Store("fixture")).unwrap();
        assert_eq!(platform(owner,Operation::Read).unwrap().as_str().trim_end(),"fixture");
        platform(owner,Operation::Forget).unwrap();
        assert!(platform(owner,Operation::Read).is_err());
    }
}
