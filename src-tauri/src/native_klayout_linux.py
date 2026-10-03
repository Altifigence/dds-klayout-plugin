"""Fixed, unprivileged optional viewer installation; never registers a Debian package."""
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile

SCHEMA = "altifigence.klayout-extension.v1"
VERSION = "0.30.12"
MAX_FILE = 128 * 1024 * 1024
MAX_EXPANDED = 240 * 1024 * 1024


def fail(code):
    raise ValueError("klayout." + code)


def regular(path, directory=False):
    value = path.lstat()
    if stat.S_ISLNK(value.st_mode) or (not stat.S_ISDIR(value.st_mode) if directory else not stat.S_ISREG(value.st_mode)):
        fail("integrity_failed")
    return value


def private_base(home):
    base = home / ".local/share/digital-design-studio/extensions/org.klayout.viewer"
    for path in list(base.parents)[::-1] + [base]:
        if path.exists() or path.is_symlink():
            regular(path, True)
        else:
            path.mkdir(mode=0o700)
    value = base.stat()
    if value.st_uid != os.getuid() or value.st_mode & 0o077:
        fail("storage_unavailable")
    return base


def supported():
    values = {}
    for line in Path("/etc/os-release").read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key] = value.strip('"')
    return os.getuid() != 0 and platform.machine() == "x86_64" and values.get("ID") == "ubuntu" and values.get("VERSION_ID") == "24.04"


def ar_members(data):
    if not data.startswith(b"!<arch>\n"):
        fail("archive_invalid")
    offset = 8
    result = {}
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            fail("archive_invalid")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58])
        end = offset + 60 + size
        if size < 0 or end > len(data) or name in result:
            fail("archive_invalid")
        result[name] = data[offset + 60:end]
        offset = end + size % 2
    names = set(result) - {"_gpgorigin"}
    if names not in ({"debian-binary", "control.tar.gz", "data.tar.xz"}, {"debian-binary", "control.tar.gz", "data.tar.gz"}):
        fail("archive_invalid")
    return result


def members(archive, pin):
    value = regular(archive)
    if value.st_size != pin["sizeBytes"]:
        fail("integrity_failed")
    data = archive.read_bytes()
    if hashlib.sha256(data).hexdigest() != pin["sha256"]:
        fail("integrity_failed")
    contents = ar_members(data)
    with tarfile.open(fileobj=io.BytesIO(contents["control.tar.gz"])) as control:
        fields = control.extractfile("control").read(8192).decode()
        for key, expected in (("Package", pin["package"]), ("Version", pin["packageVersion"]), ("Architecture", pin["architecture"])):
            if not re.search(r"^" + key + r": " + re.escape(expected) + r"$", fields, re.M):
                fail("archive_invalid")
    body = contents.get("data.tar.xz", contents.get("data.tar.gz"))
    return tarfile.open(fileobj=io.BytesIO(body))


def payload(archive, destination, pin, extract=False):
    expected = set()
    total = 0
    with members(archive, pin) as source:
        entries = source.getmembers()
        if len(entries) > 1024:
            fail("archive_invalid")
        for item in entries:
            name = item.name.removeprefix("./").rstrip("/")
            if name in ("", "."):
                continue
            parts = PurePosixPath(name)
            if parts.is_absolute() or ".." in parts.parts or any(c in name for c in "\\\0:") or name in expected:
                fail("archive_invalid")
            expected.add(name)
            path = destination / name
            if item.size < 0 or item.size > MAX_FILE:
                fail("archive_invalid")
            total += item.size
            if total > MAX_EXPANDED:
                fail("archive_invalid")
            if item.isdir():
                if extract:
                    path.mkdir(mode=0o700, parents=True, exist_ok=True)
                regular(path, True)
            elif item.isfile():
                if extract:
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    with source.extractfile(item) as reader, path.open("xb") as writer:
                        shutil.copyfileobj(reader, writer, 128 * 1024)
                    path.chmod(0o700 if item.mode & 0o111 else 0o600)
                value = regular(path)
                if value.st_uid != os.getuid() or value.st_mode & 0o022 or value.st_size != item.size:
                    fail("integrity_failed")
                with source.extractfile(item) as reader, path.open("rb") as actual:
                    while True:
                        chunk = reader.read(128 * 1024)
                        if not chunk:
                            if actual.read(1):
                                fail("integrity_failed")
                            break
                        if chunk != actual.read(len(chunk)):
                            fail("integrity_failed")
            elif item.issym():
                target = path.parent / item.linkname
                if PurePosixPath(item.linkname).is_absolute() or not target.resolve().is_relative_to(destination.resolve()):
                    fail("archive_invalid")
                if extract:
                    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                    path.symlink_to(item.linkname)
                if not path.is_symlink() or os.readlink(path) != item.linkname:
                    fail("integrity_failed")
            else:
                fail("archive_invalid")
    actual = set()
    for directory, folders, files in os.walk(destination, followlinks=False):
        for name in folders + files:
            actual.add((Path(directory) / name).relative_to(destination).as_posix())
    if actual != expected:
        fail("integrity_failed")


def child_environment(directory):
    home = pwd.getpwuid(os.getuid()).pw_dir
    environment = {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": home,
                   "LD_LIBRARY_PATH": str(directory / "payload/usr/lib/klayout"),
                   "KLAYOUT_HOME": str(directory.parent / "configuration"), "KLAYOUT_PATH": "",
                   "KLAYOUT_PYTHONPATH": "", "KLAYOUT_PYTHONHOME": "/usr"}
    # WSLg is inherited only from the selected distribution's trusted launch environment.
    for key in ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "PULSE_SERVER"):
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment


def inspect(directory, pin, platform_supported):
    value = {"schema": SCHEMA, "version": VERSION, "target": "ubuntu24-x86_64", "installationScope": "linux-user",
             "distribution": None, "supported": platform_supported, "installed": False, "ready": False,
             "code": "missing" if platform_supported else "unsupported", "dependencies": []}
    if not platform_supported or not directory.exists():
        return value
    try:
        regular(directory, True)
        if {p.name for p in directory.iterdir()} != {"archive.deb", "payload"}:
            fail("integrity_failed")
        payload(directory / "archive.deb", directory / "payload", pin)
        value["installed"] = True
    except (ValueError, OSError, tarfile.TarError):
        value["code"] = "integrity-failed"
        return value
    for name in pin["dependencies"]:
        result = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=${Status}", name], capture_output=True, timeout=5,
                                env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"})
        if result.returncode != 0 or result.stdout != b"install ok installed":
            value["dependencies"].append(name)
    if value["dependencies"]:
        value["code"] = "dependencies-missing"
        return value
    try:
        result = subprocess.run([str(directory / "payload" / pin["executable"]), "-b", "-v"],
                                cwd=str(directory / "payload/usr/lib/klayout"), env=child_environment(directory),
                                capture_output=True, timeout=10)
        if result.returncode != 0 or result.stdout.strip() != ("KLayout " + VERSION).encode() or len(result.stderr) > 4096:
            fail("version_failed")
    except (ValueError, OSError, subprocess.TimeoutExpired):
        value["code"] = "version-failed"
        return value
    display = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    value["ready"] = display
    value["code"] = "ready" if display else "display-missing"
    return value


def run(action, ticket, file_name, document):
    pin = document["packages"]["ubuntu24-x86_64"]
    platform_supported = supported()
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    # A read does not create any user directories.
    base = home / ".local/share/digital-design-studio/extensions/org.klayout.viewer"
    target = base / VERSION
    if action == "inspect":
        return inspect(target, pin, platform_supported)
    if not platform_supported:
        fail("unsupported")
    if not re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}", ticket):
        fail("request_invalid")
    base = private_base(home)
    stage = base / ("staging-" + ticket)
    if action == "stage":
        if target.exists():
            fail("already_installed")
        stage.mkdir(mode=0o700)
        try:
            archive = stage / "archive.deb"
            remaining = pin["sizeBytes"]
            with archive.open("xb") as output:
                while remaining:
                    chunk = sys.stdin.buffer.read(min(128 * 1024, remaining))
                    if not chunk:
                        fail("archive_invalid")
                    remaining -= len(chunk)
                    output.write(chunk)
                if sys.stdin.buffer.read(1):
                    fail("archive_invalid")
            (stage / "payload").mkdir(mode=0o700)
            payload(archive, stage / "payload", pin, True)
            return inspect(stage, pin, True)
        except Exception:
            shutil.rmtree(stage)
            raise
    if action == "discard":
        if stage.exists():
            regular(stage, True)
            shutil.rmtree(stage)
        return inspect(target, pin, True)
    if action == "commit":
        value = inspect(stage, pin, True)
        if not value["installed"]:
            fail("integrity_failed")
        if target.exists():
            fail("already_installed")
        stage.rename(target)
        return inspect(target, pin, True)
    if action == "uninstall":
        if target.exists():
            regular(target, True)
            # No process is stopped; only this explicitly selected DDS-owned version is removed.
            removed = base / ("removing-" + ticket)
            target.rename(removed)
            try:
                shutil.rmtree(removed)
            except Exception:
                if not target.exists():
                    removed.rename(target)
                raise
        return inspect(target, pin, True)
    if action == "open":
        value = inspect(target, pin, True)
        if not value["ready"]:
            fail(value["code"].replace("-", "_"))
        path = Path(file_name)
        if not path.is_absolute() or path.suffix.lower() not in (".gds", ".gdsii", ".oas", ".oasis") or not path.is_file():
            fail("layout_invalid")
        subprocess.Popen([str(target / "payload" / pin["executable"]), "-nc", "-rx", "-ne", str(path)],
                         cwd=str(target / "payload/usr/lib/klayout"), env=child_environment(target),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
        return value
    fail("request_invalid")


if __name__ == "__main__":
    try:
        result = run(sys.argv[1], sys.argv[2], sys.argv[3], json.loads(sys.argv[4]))
        print(json.dumps(result, separators=(",", ":")))
    except Exception as error:
        message = str(error)
        print(json.dumps({"message": message if message.startswith("klayout.") else "klayout.operation_failed"}), file=sys.stderr)
        sys.exit(1)
