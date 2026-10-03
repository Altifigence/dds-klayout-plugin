"""Fetch and verify the unchanged corresponding KLayout source archive."""
import hashlib
import json
from pathlib import Path
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


class NoRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def main():
    pin = json.loads((ROOT / "upstream-source.json").read_text())["sourceArchive"]
    destination = ROOT / pin["localPath"]
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        data = destination.read_bytes()
        if len(data) != pin["sizeBytes"] or hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise ValueError("existing upstream source archive fails checksum")
        print(destination)
        return
    opener = urllib.request.build_opener(NoRedirects())
    digest = hashlib.sha256()
    size = 0
    created = False
    try:
        with opener.open(pin["url"], timeout=30) as source, destination.open("xb") as output:
            created = True
            while chunk := source.read(128 * 1024):
                size += len(chunk)
                if size > pin["sizeBytes"]:
                    raise ValueError("upstream source archive exceeds pinned size")
                digest.update(chunk)
                output.write(chunk)
        if size != pin["sizeBytes"] or digest.hexdigest() != pin["sha256"]:
            raise ValueError("upstream source archive fails checksum")
    except Exception:
        if created and destination.exists():
            destination.unlink()
        raise
    print(destination)


if __name__ == "__main__":
    main()
