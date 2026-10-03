"""Synthetic packages only: no actual extension installation or executable launch."""
import hashlib
import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "src-tauri/src/native_klayout_linux.py"
spec = importlib.util.spec_from_file_location("klayout_extension", SOURCE)
extension = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extension)


def tar(entries):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as writer:
        for name, body, link in entries:
            entry = tarfile.TarInfo(name)
            if link:
                entry.type = tarfile.SYMTYPE
                entry.linkname = link
                writer.addfile(entry)
            else:
                entry.size = len(body)
                entry.mode = 0o600
                writer.addfile(entry, io.BytesIO(body))
    return output.getvalue()


def fixture(directory, entries):
    bodies = {"debian-binary": b"2.0\n", "control.tar.gz": tar([("control", b"Package: klayout\nVersion: 0.30.12-1\nArchitecture: amd64\n", None)]),
              "data.tar.gz": tar(entries), "_gpgorigin": b"fixture"}
    output = b"!<arch>\n"
    for name, body in bodies.items():
        header = f"{name:<16}{0:<12}{0:<6}{0:<6}{'100644':<8}{len(body):<10}`\n".encode()
        assert len(header) == 60
        output += header + body + (b"\n" if len(body) % 2 else b"")
    archive = directory / "archive.deb"
    archive.write_bytes(output)
    pin = {"sizeBytes": len(output), "sha256": hashlib.sha256(output).hexdigest(), "package": "klayout", "packageVersion": "0.30.12-1", "architecture": "amd64"}
    return archive, pin


class PackageTests(unittest.TestCase):
    def test_exact_files_and_links_reject_changed_extra_and_missing_bytes(self):
        with tempfile.TemporaryDirectory(prefix="dds-klayout-fixture-") as name:
            directory = Path(name)
            archive, pin = fixture(directory, [("viewer", b"synthetic", None), ("alias", b"", "viewer")])
            output = directory / "payload"
            output.mkdir()
            extension.payload(archive, output, pin, True)
            extension.payload(archive, output, pin)
            (output / "viewer").write_bytes(b"modified!")
            with self.assertRaises(ValueError):
                extension.payload(archive, output, pin)
            (output / "viewer").write_bytes(b"synthetic")
            (output / "extra").write_bytes(b"extra")
            with self.assertRaises(ValueError):
                extension.payload(archive, output, pin)
            (output / "extra").unlink()
            (output / "viewer").unlink()
            with self.assertRaises(OSError):
                extension.payload(archive, output, pin)

    def test_escape_paths_and_symlinks_do_not_write_outside_staging(self):
        for entry in [("../escape", b"bad", None), ("alias", b"", "../../escape"), ("alias", b"", "/etc/passwd")]:
            with tempfile.TemporaryDirectory(prefix="dds-klayout-fixture-") as name:
                directory = Path(name)
                archive, pin = fixture(directory, [entry])
                output = directory / "payload"
                output.mkdir()
                with self.assertRaises(ValueError):
                    extension.payload(archive, output, pin, True)
                self.assertFalse((directory / "escape").exists())

    def test_archive_checksum_is_required_before_extraction(self):
        with tempfile.TemporaryDirectory(prefix="dds-klayout-fixture-") as name:
            directory = Path(name)
            archive, pin = fixture(directory, [("viewer", b"synthetic", None)])
            pin["sha256"] = "0" * 64
            output = directory / "payload"
            output.mkdir()
            with self.assertRaises(ValueError):
                extension.payload(archive, output, pin, True)
            self.assertEqual(list(output.iterdir()), [])

    def test_base_rejects_user_directory_symlink(self):
        with tempfile.TemporaryDirectory(prefix="dds-klayout-fixture-") as name:
            home = Path(name) / "home"
            home.mkdir()
            other = Path(name) / "other"
            other.mkdir()
            (home / ".local").symlink_to(other, target_is_directory=True)
            with self.assertRaises(ValueError):
                extension.private_base(home)
            self.assertEqual(list(other.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
