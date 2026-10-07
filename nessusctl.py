#!/usr/bin/env python3
"""Host-side CLI over Docker Compose and the existing maintenance scripts.

This is not a new network service and does not replace the Operator API.
It runs on the machine that has the git checkout and Docker Compose files,
then either calls `docker compose`/`docker exec` or the local bash scripts.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Callable, Mapping


ROOT = Path(__file__).resolve().parent


def run(command: list[str], *, check: bool = True) -> int:
    try:
        result = subprocess.run(command, cwd=ROOT, check=False)
    except FileNotFoundError as exc:
        raise SystemExit(f"Required command is not installed: {command[0]}") from exc
    if check and result.returncode != 0:
        raise SystemExit(result.returncode)
    return result.returncode


@lru_cache(maxsize=1)
def using_desktop_compose() -> bool:
    flag = os.environ.get("NESSUS_COMPOSE_DESKTOP", "").strip().lower()
    if flag in {"1", "true", "yes"}:
        return True
    if flag in {"0", "false", "no"}:
        return False
    try:
        result = subprocess.run(
            ["docker", "info", "--format", "{{.OperatingSystem}}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        return os.name == "nt"
    return result.stdout.strip() == "Docker Desktop"


def compose_command(*args: str) -> list[str]:
    command = ["docker", "compose", "-f", "docker-compose.yml"]
    if using_desktop_compose():
        command.extend(["-f", "docker-compose.desktop.yml"])
    command.extend(args)
    return command


def compose(*args: str) -> int:
    return run(compose_command(*args))


def windows_bash_candidates(environment: Mapping[str, str]) -> list[str]:
    """Git Bash candidate paths as strings.

    Built with explicit separators so this stays testable on any platform
    (constructing ``pathlib.Path`` from a Windows path on Linux raises).
    """
    program_files = environment.get("ProgramFiles", r"C:\Program Files").rstrip("\\/")
    program_files_x86 = environment.get(
        "ProgramFiles(x86)", r"C:\Program Files (x86)"
    ).rstrip("\\/")
    local_appdata = environment.get("LOCALAPPDATA", "").rstrip("\\/")
    candidates = [
        f"{program_files}\\Git\\bin\\bash.exe",
        f"{program_files}\\Git\\usr\\bin\\bash.exe",
        f"{program_files_x86}\\Git\\bin\\bash.exe",
    ]
    if local_appdata:
        candidates.append(f"{local_appdata}\\Programs\\Git\\bin\\bash.exe")
    return candidates


def find_bash(
    *,
    os_name: str | None = None,
    environment: Mapping[str, str] | None = None,
    path_exists: Callable[[str], bool] | None = None,
    which: Callable[[str], str | None] | None = None,
) -> str:
    os_name = os.name if os_name is None else os_name
    environment = os.environ if environment is None else environment
    if path_exists is None:
        path_exists = lambda path: Path(path).is_file()  # noqa: E731
    which = shutil.which if which is None else which

    if os_name == "nt":
        for candidate in windows_bash_candidates(environment):
            if path_exists(candidate):
                return candidate
    found = which("bash")
    if not found:
        raise SystemExit(
            "bash is required for maintenance commands "
            "(install Git Bash or run on the Linux Docker host)"
        )
    if os_name == "nt" and _is_wsl_bash(found):
        raise SystemExit(
            "Git Bash is required for backup/restore/destroy on Windows. "
            "WSL bash cannot talk to Docker Desktop."
        )
    return found


def _is_wsl_bash(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    return normalized.endswith("/system32/bash.exe") or "windowsapps" in normalized


def maintenance_script(name: str, *args: str) -> int:
    return run([find_bash(), str(ROOT / "scripts" / name), *args])


def container_running() -> bool:
    result = subprocess.run(
        compose_command("ps", "--status", "running", "-q", "nessus"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and bool(result.stdout.strip())


def require_running() -> None:
    if not container_running():
        raise SystemExit("Nessus container is not running")


def update_status() -> int:
    require_running()
    code = (
        "import json,pathlib;"
        "p=pathlib.Path('/opt/nessus/var/nessus/.manage_update_state.json');"
        "print(json.dumps(json.loads(p.read_text()) if p.exists() "
        "else {'state':'idle'},indent=2))"
    )
    return run(["docker", "exec", "nessus", "python3", "-c", code])


def set_hold(reason: str) -> int:
    require_running()
    code = (
        "import pathlib,sys;"
        "p=pathlib.Path('/opt/nessus/var/nessus/.update_hold');"
        "p.parent.mkdir(parents=True,exist_ok=True);"
        "p.write_text(sys.argv[1].strip()[:200]+'\\n')"
    )
    return run(["docker", "exec", "nessus", "python3", "-c", code, reason])


def release_hold() -> int:
    require_running()
    code = (
        "import pathlib;"
        "pathlib.Path('/opt/nessus/var/nessus/.update_hold').unlink(missing_ok=True)"
    )
    return run(["docker", "exec", "nessus", "python3", "-c", code])


def doctor() -> int:
    compose("config", "--quiet")
    compose("ps", "-a")
    if os.name != "nt":
        return maintenance_script("host-preflight.sh")
    if not container_running():
        print("Windows local check: configuration is valid; Nessus is not running")
        return 0
    code = run(["docker", "exec", "nessus", "/usr/local/bin/healthcheck.sh"])
    if code != 0:
        return code
    return probe_windows_gateway()


def probe_windows_gateway() -> int:
    url = "https://127.0.0.1:8834/manage/v1/health"
    curl = shutil.which("curl.exe") or shutil.which("curl")
    if not curl:
        print(f"Windows local check: container is healthy; install curl to probe {url}")
        return 0
    command = [
        curl,
        "-sS",
        "--fail",
        "--ssl-revoke-best-effort",
        "--connect-timeout",
        "5",
        "--max-time",
        "10",
    ]
    ca_file = ROOT / "certs" / "ca.pem"
    if ca_file.is_file():
        command.extend(["--cacert", str(ca_file)])
    else:
        command.append("-k")
    command.append(url)
    print(f"Probing {url}", flush=True)
    return run(command)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nessusctl",
        description=(
            "Local wrapper for the Compose stack. Use it from the project "
            "directory instead of remembering docker compose, docker exec, "
            "and scripts/*.sh. Plugin updates still run inside the container."
        ),
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("start")
    commands.add_parser("stop")
    commands.add_parser("down")
    commands.add_parser("restart")
    commands.add_parser("update-status")
    commands.add_parser("release")
    commands.add_parser("doctor")

    logs = commands.add_parser("logs")
    logs.add_argument("service", nargs="?", choices=("nessus", "gateway"))

    update = commands.add_parser("update")
    update.add_argument("--force", action="store_true")
    update.add_argument("--plugin-set")
    update.add_argument("source", nargs="?")

    hold = commands.add_parser("hold")
    hold.add_argument("reason")

    backup = commands.add_parser("backup")
    backup.add_argument("directory", nargs="?")

    restore = commands.add_parser("restore")
    restore.add_argument("archive")
    restore.add_argument("--yes", action="store_true")

    destroy = commands.add_parser("destroy")
    destroy.add_argument("--yes", action="store_true")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "status":
        return compose("ps", "-a")
    if args.command == "start":
        return compose("up", "-d")
    if args.command == "stop":
        return compose("stop")
    if args.command == "down":
        return compose("down")
    if args.command == "restart":
        return compose("restart")
    if args.command == "logs":
        command = ["logs", "-f"]
        if args.service:
            command.append(args.service)
        return compose(*command)
    if args.command == "update":
        require_running()
        command = ["docker", "exec", "nessus", "/usr/local/bin/update.sh"]
        if args.force:
            command.append("--force")
        if args.plugin_set:
            command.extend(["--plugin-set", args.plugin_set])
        if args.source:
            command.append(args.source)
        return run(command)
    if args.command == "update-status":
        return update_status()
    if args.command == "hold":
        return set_hold(args.reason)
    if args.command == "release":
        return release_hold()
    if args.command == "backup":
        arguments = [args.directory] if args.directory else []
        return maintenance_script("backup.sh", *arguments)
    if args.command == "restore":
        if not args.yes:
            raise SystemExit("restore requires --yes")
        return maintenance_script("restore.sh", args.archive, "--yes")
    if args.command == "destroy":
        if not args.yes:
            raise SystemExit("destroy requires --yes")
        return maintenance_script("destroy.sh", "--yes")
    if args.command == "doctor":
        return doctor()
    raise SystemExit(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())
