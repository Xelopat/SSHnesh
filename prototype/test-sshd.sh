#!/usr/bin/env bash
set -euo pipefail
mkdir -p /run/sshd
id sshnesh >/dev/null 2>&1 || useradd -m -s /bin/bash sshnesh
printf '%s\n' 'sshnesh:local-docker-fixture-only' | chpasswd
ssh-keygen -A
ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub
exec /usr/sbin/sshd -D -e -f /dev/null \
  -o HostKey=/etc/ssh/ssh_host_ed25519_key \
  -o PasswordAuthentication=yes -o KbdInteractiveAuthentication=no \
  -o PermitRootLogin=no -o AllowUsers=sshnesh -o Subsystem='sftp internal-sftp'
