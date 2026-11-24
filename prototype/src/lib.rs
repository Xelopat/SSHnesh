#[cfg(feature = "desktop-ui")]
mod profiles;
mod ssh;
mod vault_merge;
mod portable_key;

#[cfg(all(feature = "desktop-ui", not(mobile)))]
mod active;
#[cfg(feature = "desktop-ui")]
mod app;
#[cfg(feature = "desktop-ui")]
mod cloud;
#[cfg(all(feature = "desktop-ui", not(mobile)))]
mod mcp;
#[cfg(feature = "desktop-ui")]
mod oauth;

#[cfg(all(feature = "desktop-ui", not(mobile)))]
pub fn run_mcp() -> std::io::Result<()> {
    mcp::stdio()
}

#[cfg(feature = "desktop-ui")]
#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    app::run();
}

#[cfg(feature = "desktop-ui")]
mod device_key;
