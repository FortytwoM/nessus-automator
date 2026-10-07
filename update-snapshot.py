#!/usr/bin/env python3
"""Validate and prune plugin rollback snapshots."""

from __future__ import annotations

import argparse
import tarfile
from pathlib import Path, PurePosixPath


class SnapshotError(RuntimeError):
    pass


SNAPSHOT_GLOB = "plugins-*.tar.gz"
REQUIRED_MEMBERS = (
    "lib/nessus/plugins",
    "lib/nessus/plugins/",
)


def snapshot_checksum_path(archive: Path) -> Path:
    return archive.with_name(archive.name + ".sha256")


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


def list_snapshots(directory: Path) -> list[Path]:
    snapshots = [
        path for path in directory.glob(SNAPSHOT_GLOB)
        if path.is_file() and not path.name.endswith(".partial")
    ]
    return sorted(snapshots, key=lambda path: path.stat().st_mtime, reverse=True)


def prune_snapshots(directory: Path, keep: int) -> list[Path]:
    if keep < 1:
        raise SnapshotError("snapshot keep count must be at least 1")
    remaining: list[Path] = []
    for index, snapshot in enumerate(list_snapshots(directory)):
        if index < keep:
            remaining.append(snapshot)
            continue
        snapshot.unlink(missing_ok=True)
        snapshot_checksum_path(snapshot).unlink(missing_ok=True)
    return remaining


def validate_snapshot_members(archive: Path) -> None:
    has_plugins = False
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            for member in bundle:
                name = member.name.removeprefix("./")
                if not safe_relative_path(name):
                    raise SnapshotError(f"unsafe snapshot path: {member.name}")
                normalized = str(PurePosixPath(name))
                if normalized == "lib/nessus/plugins" or normalized.startswith(
                    "lib/nessus/plugins/"
                ):
                    has_plugins = True
                if member.isdev() or member.isfifo():
                    raise SnapshotError(f"unsupported special file: {member.name}")
                if member.issym() and not safe_relative_path(
                    member.linkname,
                    PurePosixPath(name).parent,
                ):
                    raise SnapshotError(f"unsafe symlink target: {member.linkname}")
                if member.islnk() and not safe_relative_path(member.linkname):
                    raise SnapshotError(f"unsafe hardlink target: {member.linkname}")
    except (OSError, tarfile.TarError) as exc:
        raise SnapshotError(f"invalid plugin snapshot: {exc}") from exc
    if not has_plugins:
        raise SnapshotError("snapshot does not contain lib/nessus/plugins")


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)

    prune = subparsers.add_parser("prune")
    prune.add_argument("--directory", type=Path, required=True)
    prune.add_argument("--keep", type=int, required=True)

    validate = subparsers.add_parser("validate")
    validate.add_argument("--archive", type=Path, required=True)

    args = parser.parse_args()
    try:
        if args.command == "prune":
            remaining = prune_snapshots(args.directory, args.keep)
            print(f"snapshots kept={len(remaining)}")
        else:
            validate_snapshot_members(args.archive)
            print("snapshot valid")
    except SnapshotError as exc:
        parser.exit(1, f"update-snapshot: {exc}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
