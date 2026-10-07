from __future__ import annotations

import importlib.util
import io
import json
import platform
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "scripts" / "backup-tools.py"
SPEC = importlib.util.spec_from_file_location("backup_tools", MODULE_PATH)
assert SPEC and SPEC.loader
backup_tools = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = backup_tools
SPEC.loader.exec_module(backup_tools)


class BackupToolsTests(unittest.TestCase):
    def create_valid_backup(
        self,
        directory: Path,
    ) -> tuple[Path, Path, Path]:
        root = directory / "nessus"
        (root / "sbin").mkdir(parents=True)
        (root / "var" / "nessus").mkdir(parents=True)
        (root / "sbin" / "nessuscli").write_text("test", encoding="utf-8")
        (root / "var" / "nessus" / ".plugin_set_last").write_text(
            "202609100156\n",
            encoding="utf-8",
        )

        archive = directory / "backup.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(root, arcname=".")
        manifest_path = directory / "backup.manifest.json"
        checksum_path = directory / "backup.sha256"
        manifest = backup_tools.collect_manifest(
            root,
            archive,
            archive.name,
            "sha256:test",
        )
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        checksum_path.write_text(
            f"{manifest['archive']['sha256']}  {archive.name}\n",
            encoding="utf-8",
        )
        return archive, manifest_path, checksum_path

    def test_validates_complete_backup(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive, manifest, checksum = self.create_valid_backup(Path(directory))

            result = backup_tools.load_and_validate(
                archive,
                manifest,
                checksum,
                platform.machine(),
            )

        self.assertEqual(result["nessus"]["plugin_set"], "202609100156")
        self.assertFalse(result["compatibility"]["immutable_flags_archived"])

    def test_rejects_checksum_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive, manifest, checksum = self.create_valid_backup(Path(directory))
            with archive.open("ab") as handle:
                handle.write(b"tampered")

            with self.assertRaisesRegex(backup_tools.BackupError, "SHA-256 mismatch"):
                backup_tools.load_and_validate(
                    archive,
                    manifest,
                    checksum,
                    platform.machine(),
                )

    def test_rejects_incompatible_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive, manifest, checksum = self.create_valid_backup(Path(directory))

            with self.assertRaisesRegex(backup_tools.BackupError, "architecture mismatch"):
                backup_tools.load_and_validate(
                    archive,
                    manifest,
                    checksum,
                    "definitely-not-current",
                )

    def test_rejects_archive_path_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "unsafe.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                member = tarfile.TarInfo("../escape")
                payload = b"escape"
                member.size = len(payload)
                bundle.addfile(member, io.BytesIO(payload))

            with self.assertRaisesRegex(backup_tools.BackupError, "unsafe archive path"):
                backup_tools.validate_archive_members(archive)

    def test_rejects_file_named_like_data_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "bad-layout.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                cli = tarfile.TarInfo("sbin/nessuscli")
                payload = b"cli"
                cli.size = len(payload)
                bundle.addfile(cli, io.BytesIO(payload))
                data = tarfile.TarInfo("var/nessus")
                data.size = 4
                bundle.addfile(data, io.BytesIO(b"file"))

            with self.assertRaisesRegex(backup_tools.BackupError, "must be a directory"):
                backup_tools.validate_archive_members(archive)

    def test_rejects_duplicate_archive_members(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "duplicate.tar.gz"
            payload = b"cli"
            with tarfile.open(archive, "w:gz") as bundle:
                first = tarfile.TarInfo("sbin/nessuscli")
                first.size = len(payload)
                bundle.addfile(first, io.BytesIO(payload))
                second = tarfile.TarInfo("sbin/nessuscli")
                second.size = len(payload)
                bundle.addfile(second, io.BytesIO(payload))
                data = tarfile.TarInfo("var/nessus")
                data.type = tarfile.DIRTYPE
                bundle.addfile(data)

            with self.assertRaisesRegex(backup_tools.BackupError, "duplicate archive path"):
                backup_tools.validate_archive_members(archive)


if __name__ == "__main__":
    unittest.main()
