#!/usr/bin/env bash
set -euo pipefail
cd /source/prototype
export CARGO_TARGET_DIR=/target
export CARGO_BUILD_JOBS=3
test -f web/index.html
cargo build --release --locked --bin sshnesh-preview --features tauri/custom-protocol

bash test-sshd.sh >/tmp/sshnesh-fixture.log 2>&1 &
sshd_pid=$!
trap 'kill "$sshd_pid" 2>/dev/null || true' EXIT
for _ in {1..40}; do
  if grep -q 'Server listening' /tmp/sshnesh-fixture.log; then break; fi
  sleep 0.25
done
export SSHNESH_FIXTURE_PORT=22
export SSHNESH_FIXTURE_FINGERPRINT
SSHNESH_FIXTURE_FINGERPRINT=$(ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub | cut -d' ' -f2)
cargo test --release --locked --lib --features tauri/custom-protocol ssh_and_sftp -- --ignored --nocapture

pkg=$(mktemp -d)
install -Dm755 /target/release/sshnesh-preview "$pkg/usr/bin/sshnesh-preview"
install -Dm644 icons/128x128.png "$pkg/usr/share/icons/hicolor/128x128/apps/sshnesh-preview.png"
mkdir -p "$pkg/DEBIAN" "$pkg/usr/share/applications"
cat > "$pkg/DEBIAN/control" <<'EOF'
Package: sshnesh-preview
Version: 0.1.2
Section: net
Priority: optional
Architecture: amd64
Depends: libgtk-3-0, libwebkit2gtk-4.1-0, libsecret-tools
Maintainer: SSHnesh
Description: SSHnesh Tauri prototype with SSH and SFTP
EOF
cat > "$pkg/usr/share/applications/sshnesh-preview.desktop" <<'EOF'
[Desktop Entry]
Name=SSHnesh Preview
Exec=sshnesh-preview
Icon=sshnesh-preview
Terminal=false
Type=Application
Categories=Network;
EOF
dpkg-deb --root-owner-group --build "$pkg" /out/SSHnesh-0.1.2-native-linux-amd64.deb
wc -c /out/SSHnesh-0.1.2-native-linux-amd64.deb
