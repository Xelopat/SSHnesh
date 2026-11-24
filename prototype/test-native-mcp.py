"""End-to-end test in a disposable Debian container as root with sudo and Xvfb."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import select
import shutil
import socket
import subprocess
import tempfile
import time


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, **kwargs)


def main():
    subprocess.run(["sh", "-n", "sshnesh-provision"], check=True)
    run("install", "-m", "0755", "sshnesh-provision", "/usr/local/sbin/sshnesh-provision")
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for name in ["host", "debug", "admin", "recipient"]:
            run("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(root / name))
        for user, key in [("preview-debug", "debug"), ("preview-admin", "admin")]:
            run("useradd", "-m", "-s", "/bin/sh", user)
            # Disable password SSH below. Give the fixture account a non-locked shadow entry.
            run("chpasswd", input=f"{user}:only-for-local-test\n")
            dest = Path("/home") / user / ".ssh"
            dest.mkdir(mode=0o700)
            auth = dest / "authorized_keys"
            auth.write_text((root / (key + ".pub")).read_text())
            auth.chmod(0o600)
            shutil.chown(dest, user, user)
            shutil.chown(auth, user, user)
        sudo_rule = Path("/etc/sudoers.d/sshnesh-preview-fixture")
        sudo_rule.write_text("preview-admin ALL=(root) NOPASSWD: /usr/local/sbin/sshnesh-provision\n")
        sudo_rule.chmod(0o440)
        run("visudo", "-cf", str(sudo_rule))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        Path("/run/sshd").mkdir(exist_ok=True)
        auth_server = subprocess.Popen(["/usr/sbin/sshd", "-D", "-e", "-f", "/dev/null",
            "-h", str(root / "host"), "-p", str(port), "-o", "ListenAddress=127.0.0.1",
            "-o", "PasswordAuthentication=no", "-o", "PermitRootLogin=no", "-o", "UsePAM=yes"])
        raw = base64.b64decode((root / "host.pub").read_text().split()[1])
        fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")
        config = root / "SSHnesh Preview" / "connectors.json"
        config.parent.mkdir()
        profile = {"id": "c043ffbe-51db-40e9-9815-357ff6004082", "label": "Fixture", "host": "127.0.0.1",
            "port": port, "fingerprint": fingerprint, "debug": {"user": "preview-debug", "keyPath": str(root / "debug")},
            "admin": {"user": "preview-admin", "keyPath": str(root / "admin")}}
        config.write_text(json.dumps([profile]))
        env = dict(os.environ, XDG_CONFIG_HOME=tmp)
        mcp = subprocess.Popen([os.environ.get("SSHNESH_BIN", "/target/release/sshnesh-preview"), "--mcp"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env)
        serial = 0

        def request(method, params):
            nonlocal serial
            serial += 1
            mcp.stdin.write(json.dumps({"jsonrpc": "2.0", "id": serial, "method": method, "params": params}) + "\n")
            mcp.stdin.flush()

        def response():
            assert select.select([mcp.stdout], [], [], 25)[0], "No MCP response"
            value = json.loads(mcp.stdout.readline())
            assert value["id"] == serial and "error" not in value, value
            return value["result"]

        def ask(name, **args):
            request("tools/call", {"name": name, "arguments": args})

        def gui(approve):
            window = run("xdotool", "search", "--sync", "--onlyvisible", "--name", "SSHnesh", capture_output=True,
                timeout=10).stdout.splitlines()[-1]
            run("xdotool", "windowfocus", window)
            if approve:
                size = run("xdotool", "getwindowgeometry", "--shell", window, capture_output=True).stdout
                w = int(re.search(r"WIDTH=(\d+)", size)[1])
                h = int(re.search(r"HEIGHT=(\d+)", size)[1])
                run("xdotool", "mousemove", "--window", window, str(w // 2), str(h - 17), "click", "1")
            else:
                run("xdotool", "key", "Escape")

        try:
            for _ in range(50):
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.2):
                        break
                except OSError:
                    time.sleep(.1)
            request("initialize", {"protocolVersion": "2025-11-25"})
            assert response()["capabilities"] == {"tools": {}}
            preferences = config.with_name("mcp-preferences.json")
            preferences.write_text('{"enabled":false}')
            ask("list_servers")
            assert response()["isError"]
            preferences.write_text('{"enabled":true}')
            request("tools/list", {})
            assert {tool["name"] for tool in response()["tools"]} == {"list_servers", "active_server", "disk_usage", "service_status",
                "read_logs", "create_user", "issue_ssh_key"}
            ask("list_servers")
            listing = response()
            assert "keyPath" not in str(listing) and "Fixture" in str(listing)
            ask("disk_usage", server="Fixture")
            assert "Filesystem" in str(response())
            ask("active_server")
            assert response()["isError"]
            context = config.with_name("open-windows")
            context.mkdir()
            lease = context / "dea6ee6d-73c3-4bf2-a4af-752c7ce8c611.json"
            now = time.time_ns() // 1_000_000
            selected = {"id": profile["id"], "host": profile["host"], "port": profile["port"]}
            lease.write_text(json.dumps({"touched": now, "until": now + 10000, "target": selected}))
            ask("active_server")
            assert json.loads(response()["content"][0]["text"])["id"] == profile["id"]
            ask("disk_usage")
            assert "Filesystem" in str(response())
            ask("create_user", user="preview-recipient")
            assert response()["isError"]
            lease.write_text(json.dumps({"touched": now - 12000, "until": now - 2000, "target": selected}))
            ask("disk_usage")
            assert response()["isError"]
            ask("read_logs", server="Fixture", unit="nginx.service; false")
            assert response()["isError"]
            ask("create_user", server="Fixture", user="preview-recipient")
            gui(False)
            assert response()["isError"]
            assert subprocess.run(["getent", "passwd", "preview-recipient"]).returncode != 0
            ask("create_user", server="Fixture", user="preview-recipient")
            gui(True)
            result = response()
            assert not result["isError"], result
            run("id", "preview-recipient")
            key = (root / "recipient.pub").read_text().strip()
            ask("issue_ssh_key", server="Fixture", user="preview-recipient", publicKey=key)
            gui(True)
            result = response()
            assert not result["isError"], result
            assert key.split()[1] in Path("/home/preview-recipient/.ssh/authorized_keys").read_text()
            known = root / "known_hosts"
            known.write_text(f"[127.0.0.1]:{port} " + (root / "host.pub").read_text())
            login = run("ssh", "-p", str(port), "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
                "-o", f"UserKnownHostsFile={known}", "-i", str(root / "recipient"), "preview-recipient@127.0.0.1",
                "id -un", capture_output=True, timeout=10)
            assert login.stdout.strip() == "preview-recipient"
            ask("issue_ssh_key", server="Fixture", user="preview-admin", publicKey=key)
            gui(True)
            assert response()["isError"]
            config.write_text(json.dumps([dict(profile, fingerprint="SHA256:" + "A" * 43)]))
            ask("disk_usage", server="Fixture")
            assert response()["isError"]
            print("PASS stdio, profile secrecy, pinned SSH diagnostics, local deny/approve, provisioning and public key issue")
        finally:
            mcp.kill()
            auth_server.terminate()
            mcp.wait()
            auth_server.wait()


if __name__ == "__main__":
    main()
