"""SSHnesh release operations. Invoked with /usr/bin/python3 -I on the SSH host."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import zipfile

LIMIT = 64 * 1024 * 1024
EXPANDED = 128 * 1024 * 1024
ENTRIES = 2048
CONTROL = "/usr/bin/systemctl"


def run(argv):
    return subprocess.run(argv, capture_output=True, text=True, timeout=25,
                          env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"})


def service_info(unit):
    result = run([CONTROL, "show", "--property=LoadState,WorkingDirectory,ActiveState,SubState,Result,InvocationID", "--", unit])
    fields = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    if result.returncode or fields.get("LoadState") != "loaded":
        raise ValueError("Служба не загружена: " + unit)
    return fields


def restart_method(unit):
    direct = [CONTROL, "restart", unit]
    if os.geteuid() == 0:
        return direct, "root"
    if Path("/usr/bin/pkcheck").is_file():
        check = run(["/usr/bin/pkcheck", "--action-id", "org.freedesktop.systemd1.manage-units",
                     "--process", str(os.getpid()), "--detail", "unit", unit, "--detail", "verb", "restart"])
        if check.returncode == 0:
            return direct, "polkit"
    sudo = "/usr/bin/sudo"
    if Path(sudo).is_file():
        # Require a matching non-interactive rule for this exact command.
        check = run([sudo, "-n", "-ll", "--", *direct])
        last = check.stdout.rsplit("Sudoers entry:", 1)[-1]
        if check.returncode == 0 and any("!authenticate" in line.split(":", 1)[-1].replace(" ", "").split(",")
                                         for line in last.splitlines() if line.strip().startswith("Options:")):
            return [sudo, "-n", "--", *direct], "sudo"
    return None, "unconfirmed"


def preflight(root, unit):
    info = service_info(unit)
    restart, method = restart_method(unit)
    writable = root.is_dir() and os.access(root, os.W_OK | os.X_OK)
    working = info.get("WorkingDirectory") or "/"
    matches = Path(working).resolve() == root
    reasons = []
    if not writable:
        reasons.append("Нет записи в папку проекта.")
    if not restart:
        reasons.append("SSHnesh не смог подтвердить перезапуск без ввода пароля. Команда перезапуска не выполнялась. Вход по SSH и разрешение чата действуют отдельно от проверки sudo.")
    if root == Path("/"):
        reasons.append("Укажите отдельную папку проекта.")
    return {"ready": not reasons, "projectDirectory": str(root), "workingDirectory": working,
            "service": unit, "activeState": info.get("ActiveState"), "writable": writable,
            "matchesWorkingDirectory":matches, "restartPermission": method, "reasons": reasons}, restart


def member_name(raw):
    while raw.startswith("./"):
        raw = raw[2:]
    raw = raw.rstrip("/")
    parts = raw.split("/")
    if not raw or len(raw) > 1024 or any(p in ("", ".", "..") or p.startswith(".sshnesh-") for p in parts):
        raise ValueError("Недопустимый путь в архиве.")
    if "\\" in raw or ":" in raw or any(not c.isprintable() for c in raw):
        raise ValueError("Недопустимое имя в архиве.")
    return Path(*parts)


def archive_entries(data):
    stream = io.BytesIO(data)
    if zipfile.is_zipfile(stream):
        with zipfile.ZipFile(stream) as archive:
            for item in archive.infolist():
                mode = item.external_attr >> 16
                if stat.S_IFMT(mode) not in (0, stat.S_IFDIR, stat.S_IFREG) or item.flag_bits & 1:
                    raise ValueError("В ZIP допустимы только обычные файлы и каталоги.")
                yield item.filename, item.is_dir(), item.file_size, mode, lambda: archive.open(item)
    else:
        stream.seek(0)
        if data.startswith(b"\x1f\x8b"):
            import gzip
            with gzip.GzipFile(fileobj=stream) as compressed:
                expanded = compressed.read(EXPANDED + 1)
            if len(expanded) > EXPANDED:
                raise ValueError("Распакованный архив превышает 128 МиБ.")
            stream = io.BytesIO(expanded)
        with tarfile.open(fileobj=stream, mode="r:") as archive:
            for item in archive:
                if not (item.isfile() or item.isdir()) or item.issparse():
                    raise ValueError("В TAR допустимы только обычные файлы и каталоги.")
                yield item.name, item.isdir(), item.size, item.mode, lambda: archive.extractfile(item)


def prepare(data, stage):
    files, seen = [], set()
    total = 0
    for index, (raw, directory, size, mode, open_member) in enumerate(archive_entries(data)):
        if index >= ENTRIES:
            raise ValueError("Слишком много записей в архиве.")
        if directory and raw.rstrip("/") in ("", "."):
            continue
        name = member_name(raw)
        if name in seen:
            raise ValueError("Повторяющийся путь в архиве.")
        seen.add(name)
        if directory:
            (stage / name).mkdir(parents=True, exist_ok=True)
            continue
        total += size
        if size < 0 or total > EXPANDED:
            raise ValueError("Распакованные файлы превышают 128 МиБ.")
        dest = stage / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        with open_member() as src, dest.open("xb") as out:
            shutil.copyfileobj(src, out, length=65536)
        if dest.stat().st_size != size:
            raise ValueError("Неполный файл в архиве.")
        dest.chmod(0o755 if mode & 0o111 else 0o644)
        files.append(name)
    if not files:
        raise ValueError("В архиве нет файлов.")
    return files


def health(unit, restart):
    result = run(restart)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or "Служба отклонила перезапуск.")
    invocation = None
    for sample in range(4):
        if sample:
            time.sleep(1)
        info = service_info(unit)
        if info.get("ActiveState") != "active" or info.get("Result") != "success":
            raise RuntimeError("После перезапуска служба не находится в состоянии active/success.")
        if invocation is not None and invocation != info.get("InvocationID"):
            raise RuntimeError("Служба самопроизвольно перезапустилась.")
        invocation = info.get("InvocationID")


def install(root, archive, digest, unit, restart):
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("Укажите SHA256 архива.")
    archive = Path(archive)
    if not archive.is_absolute() or archive.is_symlink() or not archive.is_file():
        raise ValueError("Укажите обычный файл архива полным путём.")
    archive = archive.resolve()
    archive.relative_to(root)
    with archive.open("rb") as src:
        data = src.read(LIMIT + 1)
    if len(data) > LIMIT or hashlib.sha256(data).hexdigest() != digest:
        raise ValueError("Размер архива превышает 64 МиБ или SHA256 не совпадает.")
    # Retain interrupted transactions for inspection instead of applying another release over them.
    if any(root.glob(".sshnesh-release-*/pending.json")):
        raise RuntimeError("В папке проекта есть незавершённое обновление. Проверьте pending.json и резервные файлы.")
    work = Path(tempfile.mkdtemp(prefix=".sshnesh-release-", dir=root))
    stage, backups = work / "stage", work / "backup"
    stage.mkdir()
    backups.mkdir()
    changed, made = [], []
    pending = work / "pending.json"
    try:
        files = prepare(data, stage)
        for name in files:
            dest = root / name
            if hasattr(os,"geteuid") and os.geteuid()==0:
                for ancestor in dest.parents:
                    if ancestor.exists() and (ancestor.stat().st_uid != 0 or ancestor.stat().st_mode & 0o022):
                        raise PermissionError("Используйте учётку владельца проекта для установки в " + str(ancestor))
            if dest.resolve() != dest or dest == archive:
                raise ValueError("Файл релиза пересекается со ссылкой или исходным архивом: " + str(name))
            if dest.exists():
                st = dest.stat()
                if not stat.S_ISREG(st.st_mode) or st.st_mode & 0o6000 or st.st_nlink != 1:
                    raise ValueError("Неподдерживаемый тип целевого файла: " + str(name))
                backup = backups / name
                backup.parent.mkdir(parents=True, exist_ok=True)
                os.link(dest, backup)
                staged = stage / name
                if (staged.stat().st_uid, staged.stat().st_gid) != (st.st_uid, st.st_gid):
                    os.chown(staged, st.st_uid, st.st_gid)
                if hasattr(os,"listxattr") and "security.capability" in os.listxattr(dest):
                    raise ValueError("Файл содержит дополнительные системные права: " + str(name))
                shutil.copystat(dest, staged)
                # A same-size Python module must invalidate a timestamp-based .pyc.
                now = time.time_ns()
                if now // 10**9 == st.st_mtime_ns // 10**9:
                    now += 10**9
                os.utime(staged, ns=(now, now))
        pending.write_text(json.dumps({"service":unit,"files":[str(n) for n in files]}))
        restarted = False
        try:
            for name in files:
                dest = root / name
                for parent in reversed(dest.parents):
                    if not parent.exists():
                        parent.mkdir()
                        made.append(parent)
                os.replace(stage / name, dest)
                changed.append(name)
            restarted = True
            health(unit, restart)
        except BaseException as error:
            for name in reversed(changed):
                backup = backups / name
                if backup.exists():
                    os.replace(backup, root / name)
                else:
                    (root / name).unlink()
            for parent in reversed(made):
                parent.rmdir()
            if restarted:
                health(unit, restart)
            pending.unlink()
            raise RuntimeError("Восстановлены предыдущие файлы. Причина: " + str(error)) from error
        pending.unlink()
        return {"installed": len(files), "sha256": digest, "service": unit, "state": "active"}
    finally:
        if not pending.exists():
            shutil.rmtree(work)


def main(args):
    action, directory, unit, *rest = args
    if action == "locate":
        working = service_info(unit).get("WorkingDirectory") or "/"
        if working == "/" or not Path(working).is_absolute():
            raise ValueError("Служба не задаёт рабочую папку. Укажите remoteDirectory.")
        return {"workingDirectory": str(Path(working).resolve(strict=True))}
    root = Path(directory).resolve(strict=True)
    check, restart = preflight(root, unit)
    if action == "preflight":
        return check
    if not restart:
        raise PermissionError("; ".join(check["reasons"]))
    if action == "restart":
        health(unit, restart)
        return {"service":unit,"state":"active"}
    if action != "install" or not check["ready"]:
        raise ValueError("; ".join(check["reasons"]) or "Неизвестное действие.")
    import fcntl
    with contextlib.ExitStack() as stack:
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
        stack.callback(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return install(root, *rest, unit, restart)


if __name__ == "__main__":
    try:
        print(json.dumps(main(sys.argv[1:]), ensure_ascii=False))
    except Exception as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
