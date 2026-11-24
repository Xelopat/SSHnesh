#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(all(feature = "desktop-ui", not(mobile)))]
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("--mcp")) {
        if let Err(err) = sshnesh_preview::run_mcp() {
            eprintln!("{err}");
            std::process::exit(1);
        }
        return;
    }
    #[cfg(feature = "desktop-ui")]
    sshnesh_preview::run();
}
