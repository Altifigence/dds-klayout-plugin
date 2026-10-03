"""Audit a pinned downloaded Ubuntu package without installation or execution."""
import hashlib
import io
import json
from pathlib import Path
import tarfile

ROOT = Path(__file__).resolve().parents[1]


def ar_members(data):
    if not data.startswith(b"!<arch>\n"):
        raise ValueError("invalid Debian ar archive")
    result = {}
    offset = 8
    while offset < len(data):
        header = data[offset:offset + 60]
        if len(header) != 60 or header[58:] != b"`\n":
            raise ValueError("invalid ar header")
        name = header[:16].decode("ascii").strip().rstrip("/")
        size = int(header[48:58])
        end = offset + 60 + size
        if size < 0 or end > len(data) or name in result:
            raise ValueError("invalid ar member")
        result[name] = data[offset + 60:end]
        offset = end + size % 2
    return result


def main():
    descriptor = json.loads((ROOT / "packaging/extensions/klayout/0.30.12.json").read_text())
    pin = descriptor["packages"]["ubuntu24-x86_64"]
    package = ROOT / "dist/upstream/klayout_0.30.12-1_amd64.deb"
    data = package.read_bytes()
    if len(data) != pin["sizeBytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
        raise ValueError("Ubuntu package size/checksum mismatch")
    contents = ar_members(data)
    with tarfile.open(fileobj=io.BytesIO(contents["control.tar.gz"])) as control:
        fields = control.extractfile("control").read().decode()
    with tarfile.open(fileobj=io.BytesIO(contents.get("data.tar.xz", contents.get("data.tar.gz")))) as payload:
        entries = payload.getmembers()
        member = next(item for item in entries if item.name.removeprefix("./") == "usr/share/doc/klayout/copyright")
        notice = payload.extractfile(member).read()
        target = ROOT / "licenses/linux/copyright"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(notice)
    result = {"schema": "dds.klayout-upstream-linux-notice-audit.v1", "url": pin["url"],
              "archiveSha256": pin["sha256"], "archiveSizeBytes": len(data),
              "completeArchiveHashVerified": True, "executedOrInstalled": False,
              "controlFields": fields, "archiveEntries": len(entries),
              "sharedLibraries": sorted(item.name for item in entries if ".so" in item.name and item.isfile()),
              "notices": [{"archivePath": member.name, "path": "licenses/linux/copyright",
                           "sizeBytes": len(notice), "sha256": hashlib.sha256(notice).hexdigest()}]}
    (ROOT / "upstream-linux-notices.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Verified full Ubuntu package hash; audited {len(entries)} payload entries; preserved copyright notice")


if __name__ == "__main__":
    main()
