"""Verify the selected DDS source export; optionally compare a DDS checkout."""
import argparse
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def verify(dds_root=None):
    inventory = json.loads((ROOT / "source-inventory.json").read_text())
    for item in inventory["files"]:
        path = ROOT / item["path"]
        data = path.read_bytes()
        if len(data) != item["sizeBytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("source inventory mismatch: " + item["path"])
        if dds_root is not None and data != (dds_root / item["ddsPath"]).read_bytes():
            raise ValueError("DDS export differs: " + item["ddsPath"])
    document = json.loads((ROOT / "packaging/extensions/klayout/0.30.12.json").read_text())
    upstream = json.loads((ROOT / "upstream-source.json").read_text())
    if document["sourceUrl"] != upstream["sourceArchive"]["url"]:
        raise ValueError("upstream source URL differs from descriptor")
    for item in upstream["notices"]:
        data = (ROOT / item["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise ValueError("upstream notice mismatch: " + item["path"])
    for metadata in ("upstream-windows-notices.json", "upstream-linux-notices.json"):
        audit = json.loads((ROOT / metadata).read_text())
        if audit["executedOrInstalled"]:
            raise ValueError("unexpected execution in upstream notice audit")
        for item in audit["notices"]:
            data = (ROOT / item["path"]).read_bytes()
            if len(data) != item["sizeBytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
                raise ValueError("binary dependency notice mismatch: " + item["path"])
    print(f"Verified {len(inventory['files'])} exact DDS integration source files and upstream notices")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dds-root", type=Path)
    verify(parser.parse_args().dds_root)
