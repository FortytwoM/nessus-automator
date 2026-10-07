#!/usr/bin/env python3
"""Create and validate Nessus volume backup metadata."""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import subprocess
import tarfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any


SCHEMA_VERSION = 1
VOLUME_LAYOUT = "/opt/nessus"
PLUGIN_SET_RE = re.compile(r"^[0-9]{12}$")


class BackupError(RuntimeError):
    pass


def normalized_architecture(value: str) -> str:
    aliases = {
        "amd64": "x86_64",
        "x64": "x86_64",
        "aarch64": "arm64",
    }
    return aliases.get(value.strip().lower(), value.strip().lower())


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_first_line(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    output = (result.stdout or result.stderr).strip()
    return output.splitlines()[0][:200] if output else ""


def collect_manifest(
    root: Path,
    archive: Path,
    final_archive_name: str,
    source_image_id: str,
) -> dict[str, Any]:
    nessuscli = root / "sbin" / "nessuscli"
    data_dir = root / "var" / "nessus"
    if not nessuscli.is_file() or not data_dir.is_dir():
        raise BackupError(f"{root} does not contain an installed Nessus volume")

    plugin_set = ""
    plugin_set_file = data_dir / ".plugin_set_last"
    if plugin_set_file.is_file():
        plugin_set = plugin_set_file.read_text(
            encoding="utf-8", errors="replace"
        ).strip()
        if not PLUGIN_SET_RE.fullmatch(plugin_set):
            plugin_set = ""

    archive_hash = sha256_file(archive)
    return {
        "schema_version": SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "product": "Tenable Nessus",
        "nessus": {
            "version": read_first_line([str(nessuscli), "--version"]),
            "plugin_set": plugin_set,
        },
        "archive": {
            "file": final_archive_name,
            "sha256": archive_hash,
            "size_bytes": archive.stat().st_size,
        },
        "compatibility": {
            "architecture": normalized_architecture(platform.machine()),
            "volume_layout": VOLUME_LAYOUT,
            "immutable_flags_archived": False,
        },
        "source_image_id": source_image_id,
    }


def safe_relative_path(value: str, base: PurePosixPath | None = None) -> bool:
    path = PurePosixPath(value)
    if path.is_absolute():
        return False
    parts: list[str] = []
    for part in (*((base or PurePosixPath()).parts), *path.parts):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return False
            parts.pop()
        else:
            parts.append(part)
    return True


def validate_archive_members(archive: Path) -> None:
    has_cli = False
    has_data = False
    seen: set[str] = set()
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle:
                name = member.name.removeprefix("./")
                if not safe_relative_path(name):
                    raise BackupError(f"unsafe archive path: {member.name}")
                normalized = str(PurePosixPath(name))
                if normalized in seen:
                    raise BackupError(f"duplicate archive path: {normalized}")
                seen.add(normalized)
                if normalized == "sbin/nessuscli":
                    if not member.isfile() or member.issym() or member.islnk():
                        raise BackupError("sbin/nessuscli must be a regular file")
                    has_cli = True
                if normalized == "var/nessus":
                    if not member.isdir():
                        raise BackupError("var/nessus must be a directory")
                    has_data = True
                if member.isdev() or member.isfifo():
                    raise BackupError(f"unsupported special file: {member.name}")
                if member.issym() and not safe_relative_path(
                    member.linkname,
                    PurePosixPath(name).parent,
                ):
                    raise BackupError(f"unsafe symlink target: {member.linkname}")
                if member.islnk() and not safe_relative_path(member.linkname):
                    raise BackupError(f"unsafe hardlink target: {member.linkname}")
    except BackupError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise BackupError(f"invalid backup archive: {exc}") from exc
    if not has_cli or not has_data:
        raise BackupError("archive does not contain the expected Nessus volume layout")


def load_and_validate(
    archive: Path,
    manifest_path: Path,
    checksum_path: Path,
    expected_architecture: str,
) -> dict[str, Any]:
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise BackupError(f"invalid manifest: {exc}") from exc
    if not isinstance(manifest, dict):
        raise BackupError("manifest root must be an object")
    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise BackupError(
            f"unsupported backup schema: {manifest.get('schema_version')!r}"
        )
    if manifest.get("product") != "Tenable Nessus":
        raise BackupError("manifest product is not Tenable Nessus")

    compatibility = manifest.get("compatibility")
    if not isinstance(compatibility, dict):
        raise BackupError("manifest compatibility section is missing")
    if compatibility.get("volume_layout") != VOLUME_LAYOUT:
        raise BackupError("backup volume layout is incompatible")
    backup_arch = normalized_architecture(str(compatibility.get("architecture", "")))
    current_arch = normalized_architecture(expected_architecture)
    if not backup_arch or backup_arch != current_arch:
        raise BackupError(
            f"architecture mismatch: backup={backup_arch or '<empty>'}, "
            f"current={current_arch or '<empty>'}"
        )

    archive_info = manifest.get("archive")
    if not isinstance(archive_info, dict):
        raise BackupError("manifest archive section is missing")
    if archive_info.get("file") != archive.name:
        raise BackupError("manifest archive filename does not match")
    expected_hash = str(archive_info.get("sha256", "")).lower()
    if not re.fullmatch(r"[0-9a-f]{64}", expected_hash):
        raise BackupError("manifest SHA-256 is invalid")
    actual_hash = sha256_file(archive)
    if actual_hash != expected_hash:
        raise BackupError(
            f"SHA-256 mismatch: expected {expected_hash}, got {actual_hash}"
        )
    if archive_info.get("size_bytes") != archive.stat().st_size:
        raise BackupError("archive size does not match manifest")
    try:
        checksum_parts = checksum_path.read_text(encoding="utf-8").strip().split()
    except OSError as exc:
        raise BackupError(f"invalid checksum file: {exc}") from exc
    if checksum_parts != [expected_hash, archive.name]:
        raise BackupError("checksum sidecar does not match the manifest and archive")

    validate_archive_members(archive)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    create = subparsers.add_parser("create")
    create.add_argument("--root", type=Path, required=True)
    create.add_argument("--archive", type=Path, required=True)
    create.add_argument("--archive-name", required=True)
    create.add_argument("--manifest-output", type=Path, required=True)
    create.add_argument("--checksum-output", type=Path, required=True)
    create.add_argument("--source-image-id", default="")

    validate = subparsers.add_parser("validate")
    validate.add_argument("--archive", type=Path, required=True)
    validate.add_argument("--manifest", type=Path, required=True)
    validate.add_argument("--checksum", type=Path, required=True)
    validate.add_argument(
        "--architecture",
        default=platform.machine(),
    )

    args = parser.parse_args()
    try:
        if args.command == "create":
            manifest = collect_manifest(
                args.root,
                args.archive,
                args.archive_name,
                args.source_image_id,
            )
            args.manifest_output.write_text(
                json.dumps(manifest, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            args.checksum_output.write_text(
                f"{manifest['archive']['sha256']}  {args.archive_name}\n",
                encoding="utf-8",
            )
        else:
            manifest = load_and_validate(
                args.archive,
                args.manifest,
                args.checksum,
                args.architecture,
            )
            print(
                "backup valid: "
                f"nessus={manifest['nessus'].get('version') or 'unknown'}, "
                f"plugin_set={manifest['nessus'].get('plugin_set') or 'unknown'}"
            )
    except BackupError as exc:
        parser.exit(1, f"backup-tools: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
