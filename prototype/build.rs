fn main() {
    if std::env::var_os("CARGO_FEATURE_DESKTOP_UI").is_some() {
        println!("cargo:rerun-if-changed=icons/icon.ico");
        println!("cargo:rerun-if-changed=icons/icon.png");
        tauri_build::build();
    }
}
