"""Read bounded license entries from the official ZIP using HTTPS byte ranges.

No binary is retained or executed. This is a notice inventory, not verification
of the complete pinned ZIP hash. Generated metadata records that limitation.
"""
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = json.loads((ROOT / "packaging/extensions/klayout/0.30.12.json").read_text())
PIN = DOCUMENT["packages"]["windows-x86_64"]


class Ranges(io.RawIOBase):
    def __init__(self):
        self.position = 0
        self.cache = {}
        self.fetched = 0

    def seekable(self):
        return True

    def seek(self, offset, whence=0):
        self.position = offset if whence == 0 else self.position + offset if whence == 1 else PIN["sizeBytes"] + offset
        if not 0 <= self.position <= PIN["sizeBytes"]:
            raise ValueError("range outside ZIP")
        return self.position

    def tell(self):
        return self.position

    def read(self, size=-1):
        if size < 0 or size > 16 * 1024 * 1024:
            raise ValueError("unbounded ZIP read")
        end = min(PIN["sizeBytes"], self.position + size)
        result = bytearray()
        while self.position < end:
            block = self.position // (256 * 1024)
            start = block * 256 * 1024
            stop = min(start + 256 * 1024, PIN["sizeBytes"])
            if block not in self.cache:
                if self.fetched + stop - start > 32 * 1024 * 1024:
                    raise ValueError("notice audit network limit")
                request = urllib.request.Request(PIN["url"], headers={"Range": f"bytes={start}-{stop-1}"})
                with urllib.request.urlopen(request, timeout=30) as response:
                    if response.status != 206 or response.headers.get("Content-Range") != f"bytes {start}-{stop-1}/{PIN['sizeBytes']}":
                        raise ValueError("server did not honor exact range")
                    data = response.read(stop - start + 1)
                if len(data) != stop - start:
                    raise ValueError("short or oversized range")
                self.cache[block] = data
                self.fetched += len(data)
            count = min(end - self.position, stop - self.position)
            result.extend(self.cache[block][self.position - start:self.position - start + count])
            self.position += count
        return bytes(result)


def main():
    ranges = Ranges()
    notices = []
    with zipfile.ZipFile(ranges) as archive:
        entries = archive.infolist()
        selected = [entry for entry in entries if not entry.is_dir()
                    and not PurePosixPath(entry.filename).name.lower().endswith(".rb")
                    and re.search(r"license|licence|copyright|copying|^notice(?:\.|$)", PurePosixPath(entry.filename).name, re.I)]
        if len(selected) > 512 or sum(entry.file_size for entry in selected) > 8 * 1024 * 1024:
            raise ValueError(f"notice entry limit: {len(selected)} notices / {sum(entry.file_size for entry in selected)} bytes")
        for entry in selected:
            if entry.file_size > 1024 * 1024:
                raise ValueError("notice entry too large")
            path = PurePosixPath(entry.filename)
            if path.is_absolute() or ".." in path.parts or any(char in entry.filename for char in "\\:\0"):
                raise ValueError("unsafe notice path")
            content = archive.read(entry)
            destination = ROOT / "licenses/windows" / entry.filename
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(content)
            notices.append({"archivePath": entry.filename, "path": destination.relative_to(ROOT).as_posix(),
                            "sizeBytes": len(content), "sha256": hashlib.sha256(content).hexdigest()})
        result = {"schema": "dds.klayout-upstream-windows-notice-audit.v1", "url": PIN["url"],
                  "expectedArchiveSha256": PIN["sha256"], "expectedArchiveSizeBytes": PIN["sizeBytes"],
                  "method": "HTTPS exact byte ranges; ZIP directory and selected notice entry CRC validation",
                  "completeArchiveHashVerified": False, "executedOrInstalled": False,
                  "archiveEntries": len(entries), "bytesFetched": ranges.fetched,
                  "dllNames": sorted({PurePosixPath(entry.filename).name for entry in entries if entry.filename.lower().endswith('.dll')}),
                  "notices": notices}
    (ROOT / "upstream-windows-notices.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Audited {len(entries)} entries; preserved {len(notices)} notices; fetched {ranges.fetched} bytes; full ZIP hash not verified")


if __name__ == "__main__":
    main()
