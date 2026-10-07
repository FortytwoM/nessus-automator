from __future__ import annotations

import importlib.util
import io
import os
import sys
import tarfile
import tempfile
import time
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "update-snapshot.py"
SPEC = importlib.util.spec_from_file_location("update_snapshot", MODULE_PATH)
assert SPEC and SPEC.loader
update_snapshot = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = update_snapshot
SPEC.loader.exec_module(update_snapshot)


class UpdateSnapshotTests(unittest.TestCase):
    def _write_snapshot(self, directory: Path, name: str, payload: bytes) -> Path:
        archive = directory / name
        with tarfile.open(archive, "w:gz") as bundle:
            member = tarfile.TarInfo("lib/nessus/plugins/test.nasl")
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))
        checksum = update_snapshot.snapshot_checksum_path(archive)
        checksum.write_text("deadbeef  " + name + "\n", encoding="utf-8")
        return archive

    def test_prune_keeps_newest_and_removes_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            first = self._write_snapshot(directory, "plugins-20260101000000.tar.gz", b"one")
            second = self._write_snapshot(directory, "plugins-20260102000000.tar.gz", b"two")
            third = self._write_snapshot(directory, "plugins-20260103000000.tar.gz", b"three")
            now = time.time()
            os.utime(first, (now - 30, now - 30))
            os.utime(second, (now - 20, now - 20))
            os.utime(third, (now - 10, now - 10))

            remaining = update_snapshot.prune_snapshots(directory, keep=2)

            self.assertEqual(
                {path.name for path in remaining},
                {second.name, third.name},
            )
            self.assertFalse(first.exists())
            self.assertFalse(update_snapshot.snapshot_checksum_path(first).exists())
            self.assertTrue(second.exists())
            self.assertTrue(update_snapshot.snapshot_checksum_path(second).exists())

    def test_validate_accepts_plugin_tree(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive = self._write_snapshot(Path(raw), "plugins-valid.tar.gz", b"ok")
            update_snapshot.validate_snapshot_members(archive)

    def test_validate_rejects_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            archive = Path(raw) / "plugins-unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                member = tarfile.TarInfo("../escape.nasl")
                payload = b"bad"
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))

            with self.assertRaisesRegex(update_snapshot.SnapshotError, "unsafe snapshot path"):
                update_snapshot.validate_snapshot_members(archive)


if __name__ == "__main__":
    unittest.main()
