#!/bin/sh
# Isolated WSL/Linux fixture. Run as root in a disposable WSL distro or VM.
set -eu
work=$1
operator=$2
port=$3
action=$4

case "$work" in /tmp/sshash-lab.*) ;; *) exit 2 ;; esac
case "$action" in
  setup)
    test ! -e "$work"
    install -d -m 0755 "$work"
    install -d -m 0700 -o "$operator" "$work/files"
    install -d -m 0755 /run/sshd
    ssh-keygen -q -t ed25519 -N '' -f "$work/host-a"
    ssh-keygen -q -t ed25519 -N '' -f "$work/host-b"
    ssh-keygen -q -t ed25519 -N '' -f "$work/client"
    cp "$work/client.pub" "$work/authorized"
    ssh-keygen -q -t ed25519 -N 'lab-key-phrase' -f "$work/imported"
    cat "$work/imported.pub" >> "$work/authorized"
    chmod 0644 "$work/authorized"
    eval "$(ssh-agent -a "$work/agent.sock" -s)"
    printf '%s\n' "$SSH_AGENT_PID" > "$work/agent.pid"
    ssh-add "$work/client"
    rm "$work/client"
    ;;
  serve)
    key=$5
    case "$key" in a|b) ;; *) exit 2 ;; esac
    cat > "$work/sshd.conf" <<EOF
Port $port
ListenAddress 127.0.0.1
HostKey $work/host-$key
PidFile $work/sshd.pid
AuthorizedKeysFile $work/authorized
StrictModes no
AllowUsers $operator
PermitRootLogin no
AuthenticationMethods publickey
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM yes
PermitTTY yes
PermitUserEnvironment no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog no
Subsystem sftp internal-sftp
EOF
    ssh-keygen -lf "$work/host-$key.pub"
    exec /usr/sbin/sshd -D -e -f "$work/sshd.conf"
    ;;
  stop)
    if test -f "$work/sshd.pid"; then kill "$(cat "$work/sshd.pid")" 2>/dev/null || true; fi
    ;;
  clean)
    if test -f "$work/agent.pid"; then kill "$(cat "$work/agent.pid")" 2>/dev/null || true; fi
    rm -rf -- "$work"
    ;;
  *) exit 2 ;;
esac
