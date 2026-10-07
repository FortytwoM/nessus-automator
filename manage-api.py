#!/usr/bin/env python3
"""Operator API — plugin updates, hold, scan status (same auth as Nessus REST)."""

from __future__ import annotations

import json
import mmap
import os
import signal
import ssl
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from nessus_status_lib import typed_status  # noqa: E402
from nessus_url_policy import host_allowed, redact_url  # noqa: E402

STATE_FILE = Path(os.environ.get(
    "NESSUS_MANAGE_STATE_FILE", "/opt/nessus/var/nessus/.manage_update_state.json"
))
UPDATE_SCRIPT = "/usr/local/bin/update.sh"
UPLOAD_DIR = Path(os.environ.get(
    "NESSUS_MANAGE_UPLOAD_DIR", "/var/lib/nessus-downloads/incoming"
))
MAX_UPLOAD_BYTES = int(os.environ.get("NESSUS_MANAGE_MAX_UPLOAD_BYTES", str(1024 ** 3)))
MAX_JSON_BODY_BYTES = int(os.environ.get("NESSUS_MANAGE_MAX_JSON_BYTES", str(64 * 1024)))
MAX_SIGNATURE_BYTES = int(os.environ.get("NESSUS_MANAGE_MAX_SIGNATURE_BYTES", str(1024 * 1024)))
ARCHIVE_FILE_FIELDS = {"archive", "file", "update_file"}
SIGNATURE_FILE_FIELDS = {"signature", "sig", "signature_file"}
DOWNLOAD_DIR = Path(os.environ.get("NESSUS_DOWNLOAD_DIR", "/var/lib/nessus-downloads"))
ALLOWED_ARCHIVE_ROOTS = (
    Path("/mnt/nessus"),
    DOWNLOAD_DIR,
)
ALLOWED_DOWNLOAD_SCHEMES = {
    item.strip().lower()
    for item in os.environ.get("NESSUS_DOWNLOAD_ALLOWED_SCHEMES", "https").split(",")
    if item.strip()
}
ALLOWED_DOWNLOAD_HOSTS = {
    item.strip().lower().rstrip(".")
    for item in os.environ.get(
        "NESSUS_DOWNLOAD_ALLOWED_HOSTS", "plugins.nessus.org,*.tenable.com"
    ).split(",")
    if item.strip()
}
ALLOWED_DOWNLOAD_PORTS = {
    int(item.strip())
    for item in os.environ.get("NESSUS_DOWNLOAD_ALLOWED_PORTS", "443").split(",")
    if item.strip()
}
HOLD_FILE = Path(os.environ.get(
    "NESSUS_UPDATE_HOLD_FILE", "/opt/nessus/var/nessus/.update_hold"
))
LOCK_FILE = Path("/tmp/nessus_update.lock")
BOOTSTRAP_READY_FILE = Path(os.environ.get(
    "NESSUS_BOOTSTRAP_READY_FILE", "/tmp/nessus_bootstrap_ready"
))
PLUGIN_SET_FILE = Path("/opt/nessus/var/nessus/.plugin_set_last")
UPDATE_SUCCESS_FILE = Path(os.environ.get(
    "NESSUS_UPDATE_SUCCESS_FILE", "/opt/nessus/var/nessus/.update_success_epoch"
))
SCHEDULER_STATE_FILE = Path(os.environ.get(
    "NESSUS_UPDATE_SCHEDULER_STATE_FILE",
    "/opt/nessus/var/nessus/.update_scheduler_state.json",
))
API_PREFIX = "/manage/v1"
OPERATOR_VERSION = "2.5"
NESSUS_API_BASE = os.environ.get("NESSUS_API_BASE", "https://127.0.0.1:8835").rstrip("/")
ADMIN_PERMISSION = int(os.environ.get("NESSUS_MANAGE_ADMIN_PERMISSION", "128"))
_state_lock = threading.Lock()
_proc_lock = threading.Lock()
_update_accept_lock = threading.Lock()
_update_thread: threading.Thread | None = None
_update_proc: subprocess.Popen[str] | None = None
_update_request_reserved = False
_scheduler: "UpdateScheduler | None" = None


def _loopback_api_host(value: str) -> bool:
    host = (urlparse(value).hostname or "").lower()
    return host in {"127.0.0.1", "localhost", "::1"}


def _build_ssl_context(api_base: str) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if _loopback_api_host(api_base):
        # The local Nessus backend presents a self-signed certificate; relax
        # verification only for loopback. A remote NESSUS_API_BASE is verified.
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


_ssl_ctx = _build_ssl_context(NESSUS_API_BASE)



def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{ts}] [operator-api] {msg}", flush=True)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def read_state() -> dict[str, Any]:
    if not STATE_FILE.is_file():
        return {"state": "idle"}
    try:
        return json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"state": "idle"}


def write_state(data: dict[str, Any]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    with _state_lock:
        STATE_FILE.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def update_running() -> bool:
    if not LOCK_FILE.is_file():
        return False
    try:
        pid = int(LOCK_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def reserve_update_request() -> bool:
    global _update_request_reserved
    with _update_accept_lock:
        if (
            _update_request_reserved
            or update_running()
            or (_update_thread is not None and _update_thread.is_alive())
        ):
            return False
        _update_request_reserved = True
        return True


def release_update_request() -> None:
    global _update_request_reserved
    with _update_accept_lock:
        _update_request_reserved = False


def update_in_progress() -> bool:
    with _update_accept_lock:
        accepted = _update_request_reserved or (
            _update_thread is not None and _update_thread.is_alive()
        )
    return accepted or update_running()


def _read_update_pid() -> int | None:
    if not LOCK_FILE.is_file():
        return None
    try:
        return int(LOCK_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


def update_cancel_wait_seconds() -> int:
    raw = os.environ.get("NESSUS_UPDATE_CANCEL_WAIT_SECONDS", "180")
    try:
        return max(30, min(int(raw), 1800))
    except ValueError:
        return 180


def cancel_update_job() -> tuple[bool, str]:
    global _update_proc
    pid = _read_update_pid()
    with _proc_lock:
        proc = _update_proc
    if pid is None and proc is None:
        return False, "No update in progress"
    targets: list[int] = []
    if pid is not None:
        targets.append(pid)
    if proc is not None and proc.pid and proc.pid not in targets:
        targets.append(proc.pid)

    signalled = False
    for target in targets:
        try:
            os.kill(target, signal.SIGTERM)
            signalled = True
        except OSError:
            continue

    if not signalled:
        return False, "Update process not found"

    deadline = time.time() + update_cancel_wait_seconds()
    while time.time() < deadline:
        if not update_running():
            break
        time.sleep(0.5)

    if update_running() and pid is not None:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass

    with _proc_lock:
        if _update_proc is not None:
            try:
                _update_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                _update_proc.kill()
            _update_proc = None

    if not update_running() and LOCK_FILE.is_file():
        try:
            LOCK_FILE.unlink()
        except OSError:
            pass

    st = read_state()
    if st.get("state") not in {None, "running"}:
        return True, str(st.get("message") or "Update cancelled")

    write_state({
        **st,
        "state": "cancelled",
        "finished_at": utc_now(),
        "exit_code": -2,
        "message": "Update cancelled by operator API",
        "in_progress": False,
    })
    return True, "Update cancelled"


def validate_plugin_set(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if not text.isdigit() or len(text) != 12:
        raise ValueError("plugin_set must be a 12-digit feed id (YYYYMMDDHHMM)")
    return text


def safe_archive_path(value: str) -> Path | None:
    try:
        candidate = Path(value).resolve()
    except OSError:
        return None
    if not candidate.is_file():
        return None
    for root in ALLOWED_ARCHIVE_ROOTS:
        try:
            root_resolved = root.resolve()
            candidate.relative_to(root_resolved)
            return candidate
        except ValueError:
            continue
    return None


def validate_update_url(value: str) -> str:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in ALLOWED_DOWNLOAD_SCHEMES:
        raise ValueError(f"source URL scheme '{scheme or '<empty>'}' is not allowed")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("source URL userinfo is not allowed")
    if not host or not host_allowed(host, ALLOWED_DOWNLOAD_HOSTS):
        raise ValueError(f"source URL host '{host or '<empty>'}' is not allowlisted")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError(f"invalid source URL port: {exc}") from exc
    if port not in ALLOWED_DOWNLOAD_PORTS:
        raise ValueError(f"source URL port {port} is not allowed")
    return value


def resolve_update_archive(body: dict[str, Any]) -> str | None:
    """Local archive path inside container (archive field or local source)."""
    for key in ("archive", "update_file", "file"):
        raw = body.get(key)
        if raw is None:
            continue
        if not isinstance(raw, str) or not raw.strip():
            raise ValueError(f"{key} must be a non-empty string path")
        path = safe_archive_path(raw.strip())
        if path is None:
            raise ValueError(
                f"{key} must point to an existing file under /mnt/nessus "
                f"or {DOWNLOAD_DIR}"
            )
        return str(path)

    source = body.get("source")
    if isinstance(source, str) and source.strip():
        parsed = urlparse(source.strip())
        if parsed.scheme:
            validate_update_url(source.strip())
            return None
        path = safe_archive_path(source.strip())
        if path is None:
            raise ValueError("source must be an approved URL or a local archive path")
        return str(path)
    return None


def resolve_update_url(body: dict[str, Any]) -> str | None:
    source = body.get("source")
    if not isinstance(source, str) or not source.strip():
        return None
    parsed = urlparse(source.strip())
    if parsed.scheme:
        return validate_update_url(source.strip())
    return None


def enforce_plugin_set_for_offline(params: dict[str, Any]) -> None:
    if params.get("archive") and not params.get("plugin_set"):
        raise ValueError(
            "offline update requires plugin_set (12-digit feed id from plugins.nessus.org/offline.php)"
        )


def apply_env_plugin_set(params: dict[str, Any]) -> dict[str, Any]:
    if params.get("plugin_set") or not params.get("archive"):
        return params
    env_set = os.environ.get("NESSUS_PLUGIN_SET", "").strip()
    if env_set:
        params["plugin_set"] = validate_plugin_set(env_set)
    return params


def parse_update_request_json(body: dict[str, Any]) -> dict[str, Any]:
    force = bool(body.get("force", False))
    plugin_set = validate_plugin_set(
        body.get("plugin_set") or body.get("plugin_set_id") or body.get("feed_id")
    )
    archive = resolve_update_archive(body)
    url = resolve_update_url(body)
    if archive and url:
        raise ValueError("Provide either a local archive path or source URL, not both")
    return {
        "force": force,
        "plugin_set": plugin_set,
        "archive": archive,
        "url": url,
    }


def _multipart_boundary(content_type: str) -> bytes:
    for segment in content_type.split(";"):
        segment = segment.strip()
        if segment.lower().startswith("boundary="):
            value = segment.split("=", 1)[1].strip()
            if len(value) >= 2 and value[0] == value[-1] == '"':
                value = value[1:-1]
            return value.encode("utf-8", "surrogateescape")
    raise ValueError("multipart boundary missing")


def _parse_content_disposition(value: str) -> dict[str, str]:
    result: dict[str, str] = {}
    if not value.lower().startswith("form-data"):
        return result
    for token in value.split(";")[1:]:
        token = token.strip()
        if "=" not in token:
            continue
        key, raw = token.split("=", 1)
        key = key.strip().lower()
        raw = raw.strip()
        if len(raw) >= 2 and raw[0] == raw[-1] == '"':
            raw = raw[1:-1]
        result[key] = raw
    return result


def _spool_request_body(fp: Any, length: int, max_length: int) -> Path:
    if length <= 0:
        raise ValueError("multipart body required")
    if length > max_length:
        raise ValueError(f"request body exceeds {max_length} bytes")
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    spool = UPLOAD_DIR / f".spool_{int(time.time())}_{os.getpid()}.multipart"
    copied = 0
    with spool.open("wb") as handle:
        while copied < length:
            chunk = fp.read(min(1024 * 1024, length - copied))
            if not chunk:
                break
            handle.write(chunk)
            copied += len(chunk)
    if copied != length:
        spool.unlink(missing_ok=True)
        raise ValueError("multipart body truncated")
    return spool


def _parse_multipart_spool(
    spool: Path, content_type: str
) -> tuple[
    dict[str, str],
    tuple[str, int, int] | None,
    tuple[str, int, int] | None,
]:
    boundary = _multipart_boundary(content_type)
    marker = b"--" + boundary
    fields: dict[str, str] = {}
    archive: tuple[str, int, int] | None = None
    signature: tuple[str, int, int] | None = None

    with spool.open("rb") as handle:
        mm = mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            pos = mm.find(marker)
            if pos < 0:
                raise ValueError("invalid multipart body")

            while 0 <= pos < mm.size():
                header_start = pos + len(marker)
                if mm[header_start:header_start + 2] == b"--":
                    break
                if mm[header_start:header_start + 2] == b"\r\n":
                    header_start += 2

                header_end = mm.find(b"\r\n\r\n", header_start)
                if header_end < 0:
                    raise ValueError("invalid multipart part")

                headers_raw = mm[header_start:header_end].decode("utf-8", errors="replace")
                body_start = header_end + 4
                next_marker = mm.find(b"\r\n" + marker, body_start)
                if next_marker < 0:
                    raise ValueError("invalid multipart body")
                body_end = next_marker

                disposition = ""
                for line in headers_raw.split("\r\n"):
                    if line.lower().startswith("content-disposition:"):
                        disposition = line.split(":", 1)[1].strip()
                        break

                part = _parse_content_disposition(disposition)
                name = part.get("name", "")
                filename = part.get("filename")
                if filename and name in ARCHIVE_FILE_FIELDS:
                    archive = (Path(filename).name, body_start, body_end)
                elif filename and name in SIGNATURE_FILE_FIELDS:
                    signature = (Path(filename).name, body_start, body_end)
                elif name:
                    fields[name] = mm[body_start:body_end].decode("utf-8", errors="replace").strip()

                pos = next_marker + 2
        finally:
            mm.close()

    return fields, archive, signature


def _copy_slice(spool: Path, start: int, size: int, dest: Path) -> None:
    remaining = size
    with spool.open("rb") as src, dest.open("wb") as dst:
        src.seek(start)
        while remaining > 0:
            chunk = src.read(min(1024 * 1024, remaining))
            if not chunk:
                break
            dst.write(chunk)
            remaining -= len(chunk)

    if remaining != 0:
        dest.unlink(missing_ok=True)
        raise ValueError("uploaded data is truncated")


def save_uploaded_slice(spool: Path, filename: str, start: int, end: int) -> Path:
    size = end - start
    if size > MAX_UPLOAD_BYTES:
        raise ValueError(f"upload exceeds {MAX_UPLOAD_BYTES} bytes")
    if size < 10240:
        raise ValueError("uploaded archive is too small")

    if not filename.endswith((".tar.gz", ".tgz")):
        filename = f"{filename}.tar.gz"
    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in filename)
    dest = UPLOAD_DIR / f"{int(time.time())}_{safe_name}"

    _copy_slice(spool, start, size, dest)
    return dest


def save_signature_slice(spool: Path, start: int, end: int, dest: Path) -> Path:
    size = end - start
    if size <= 0:
        raise ValueError("uploaded signature is empty")
    if size > MAX_SIGNATURE_BYTES:
        raise ValueError(f"signature exceeds {MAX_SIGNATURE_BYTES} bytes")

    _copy_slice(spool, start, size, dest)
    return dest


def parse_update_request_multipart(handler: Any) -> dict[str, Any]:
    content_type = handler.headers.get("Content-Type", "")
    length = int(handler.headers.get("Content-Length", 0))
    spool_limit = MAX_UPLOAD_BYTES + MAX_SIGNATURE_BYTES + 65536
    spool = _spool_request_body(handler.rfile, length, spool_limit)
    try:
        fields, archive_part, signature_part = _parse_multipart_spool(spool, content_type)
        if archive_part is None:
            raise ValueError("multipart request must include archive file field")

        filename, start, end = archive_part
        force = fields.get("force", "").lower() in {"1", "true", "yes", "on"}
        plugin_set = validate_plugin_set(
            fields.get("plugin_set") or fields.get("plugin_set_id") or fields.get("feed_id")
        )
        saved = save_uploaded_slice(spool, filename, start, end)
        if signature_part is not None:
            _sig_name, sig_start, sig_end = signature_part
            save_signature_slice(spool, sig_start, sig_end, Path(f"{saved}.sig"))
        return {
            "force": force,
            "plugin_set": plugin_set,
            "archive": str(saved),
            "url": None,
        }
    finally:
        spool.unlink(missing_ok=True)


def resolve_default_feed_source() -> tuple[str | None, str | None]:
    """Default source when POST body is empty (after explicit archive in body).

    Priority: NESSUS_UPDATE_FILE / packages mount > NESSUS_UPDATE_URL.
    Explicit archive in request body is handled before this function runs.
    """
    candidates = [
        os.environ.get("NESSUS_UPDATE_FILE", "").strip(),
        "/mnt/nessus/all-2.0.tar.gz",
    ]
    for raw in candidates:
        if not raw:
            continue
        path = safe_archive_path(raw)
        if path:
            return str(path), None
    url = os.environ.get("NESSUS_UPDATE_URL", "").strip()
    if url and urlparse(url).scheme in {"http", "https"}:
        return None, url
    return None, None


def apply_default_update_source(params: dict[str, Any]) -> dict[str, Any]:
    if params.get("archive") or params.get("url"):
        return params
    archive, url = resolve_default_feed_source()
    if archive:
        params["archive"] = archive
    elif url:
        params["url"] = url
    return params


def fetch_server_status() -> dict[str, Any]:
    req = urllib.request.Request(f"{NESSUS_API_BASE}/server/status")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return data if isinstance(data, dict) else {}
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return {}


def nessus_status_fields(status: dict[str, Any]) -> dict[str, Any]:
    parsed = typed_status(status)
    plugin_set = parsed["plugin_set"]
    if plugin_set is None:
        try:
            cached_plugin_set = PLUGIN_SET_FILE.read_text(encoding="utf-8").strip()
        except OSError:
            cached_plugin_set = ""
        plugin_set = cached_plugin_set if cached_plugin_set.isdigit() else None
    else:
        plugin_set = str(plugin_set)
    strict_health = os.environ.get("NESSUS_HEALTH_STRICT", "1") == "1"
    bootstrap_ready = not strict_health or BOOTSTRAP_READY_FILE.is_file()
    ready = parsed["engine_status"] == "ready" and parsed["plugin_data"] and bootstrap_ready
    return {
        "ready": ready,
        "plugin_set": plugin_set,
        "plugin_data": parsed["plugin_data"],
        "engine_status": parsed["engine_status"],
        "engine_progress": parsed["engine_progress"],
        "nessus_status": parsed["nessus_status"],
    }


def build_health_payload() -> dict[str, Any]:
    st = read_state()
    nessus = nessus_status_fields(fetch_server_status())
    in_progress = update_in_progress()
    return {
        "status": "ok",
        "operator_version": OPERATOR_VERSION,
        "update_state": "running" if in_progress and st.get("state") == "idle" else st.get("state", "idle"),
        "update_in_progress": in_progress,
        "update_started_at": st.get("started_at"),
        "update_message": st.get("message"),
        "hold_active": HOLD_FILE.is_file(),
        "scheduler": _scheduler.status() if _scheduler is not None else {
            "enabled": False,
        },
        **nessus,
    }


def cleanup_incoming_uploads() -> None:
    if not UPLOAD_DIR.is_dir():
        return
    removed = 0
    for path in UPLOAD_DIR.iterdir():
        if not path.is_file():
            continue
        if path.suffix in {".gz", ".tgz", ".sig"} or path.name.endswith(".tar.gz"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
    if removed:
        log(f"Cleaned {removed} file(s) from {UPLOAD_DIR}")


def classify_update_exit(exit_code: int) -> tuple[str, str]:
    if exit_code == 0:
        return "completed", "Update finished successfully"
    if exit_code == 2:
        return "deferred", "Update deferred (scans or hold file)"
    if exit_code == 3:
        return "deferred", "Update deferred (another update holds the lock)"
    if exit_code == 4:
        return "rolled_back", "Update failed; previous plugins were restored"
    if exit_code == 130:
        return "cancelled", "Update cancelled"
    return "failed", f"Update failed with exit code {exit_code}"


def _run_update_job(
    force: bool,
    archive: str | None,
    url: str | None,
    plugin_set: str | None,
    trigger: str = "api",
) -> None:
    global _update_proc
    cmd = [UPDATE_SCRIPT]
    proc_env = os.environ.copy()
    if force:
        cmd.append("--force")
    if plugin_set:
        cmd.extend(["--plugin-set", plugin_set])
        proc_env["NESSUS_PLUGIN_SET"] = plugin_set
    if archive:
        cmd.append(archive)
    elif url:
        proc_env["NESSUS_UPDATE_URL"] = url

    started_at = utc_now()
    safe_source = redact_url(url) if url else archive
    write_state({
        "state": "running",
        "started_at": started_at,
        "force": force,
        "source": safe_source,
        "archive": archive,
        "plugin_set": plugin_set,
        "trigger": trigger,
        "exit_code": None,
        "message": None,
    })

    log_cmd = list(cmd)
    if url:
        log_cmd = [UPDATE_SCRIPT]
        if force:
            log_cmd.append("--force")
        if plugin_set:
            log_cmd.extend(["--plugin-set", plugin_set])
        log_cmd.append(redact_url(url) or url)
    log(f"Starting update: {' '.join(str(part) for part in log_cmd)}")
    try:
        with _proc_lock:
            _update_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=proc_env,
            )
            proc = _update_proc
        assert proc is not None
        stdout, _ = proc.communicate(timeout=86400)
        exit_code = proc.returncode if proc.returncode is not None else -1
        tail = (stdout or "")[-4000:]
        state, msg = classify_update_exit(exit_code)
        if exit_code == 0:
            cleanup_incoming_uploads()
        if exit_code not in {0, 2, 3}:
            cleanup_incoming_uploads()
        current = read_state()
        if current.get("state") == "cancelled":
            write_state({
                **current,
                "exit_code": exit_code,
                "log_tail": tail,
                "in_progress": False,
            })
        else:
            write_state({
                "state": state,
                "started_at": started_at,
                "finished_at": utc_now(),
                "force": force,
                "source": safe_source,
                "archive": archive,
                "plugin_set": plugin_set,
                "trigger": trigger,
                "exit_code": exit_code,
                "message": msg,
                "log_tail": tail,
            })
        log(msg)
    except subprocess.TimeoutExpired:
        cancel_update_job()
        write_state({
            "state": "failed",
            "finished_at": utc_now(),
            "exit_code": -1,
            "message": "Update timed out after 24h",
        })
        log("Update timed out")
    except Exception as exc:  # noqa: BLE001
        write_state({
            "state": "failed",
            "finished_at": utc_now(),
            "exit_code": -1,
            "message": str(exc),
        })
        log(f"Update error: {exc}")
    finally:
        with _proc_lock:
            _update_proc = None


def run_update_job(
    force: bool,
    archive: str | None,
    url: str | None,
    plugin_set: str | None,
    trigger: str = "api",
) -> None:
    """Run one update job, always releasing the request reservation on exit."""
    try:
        _run_update_job(force, archive, url, plugin_set, trigger)
    finally:
        release_update_request()


def parse_update_window(value: str) -> tuple[int, int]:
    try:
        start_text, end_text = value.split("-", 1)
        start_hour, start_minute = (int(item) for item in start_text.split(":", 1))
        end_hour, end_minute = (int(item) for item in end_text.split(":", 1))
    except (ValueError, TypeError) as exc:
        raise ValueError("update window must use HH:MM-HH:MM") from exc
    if not (
        0 <= start_hour <= 23
        and 0 <= end_hour <= 23
        and 0 <= start_minute <= 59
        and 0 <= end_minute <= 59
    ):
        raise ValueError("update window contains an invalid UTC time")
    start = start_hour * 60 + start_minute
    end = end_hour * 60 + end_minute
    if start == end:
        raise ValueError("update window start and end must differ")
    return start, end


def within_update_window(now: datetime, window: tuple[int, int]) -> bool:
    minute = now.hour * 60 + now.minute
    start, end = window
    if start < end:
        return start <= minute < end
    return minute >= start or minute < end


class UpdateScheduler:
    def __init__(self) -> None:
        self.window_text = os.environ.get("NESSUS_UPDATE_WINDOW_UTC", "").strip()
        self.enabled = bool(self.window_text)
        self.window = parse_update_window(self.window_text) if self.enabled else None
        self.max_age_hours = self._positive_int(
            "NESSUS_UPDATE_MAX_FEED_AGE_HOURS",
            48,
        )
        self.retry_initial = self._positive_int(
            "NESSUS_UPDATE_RETRY_INITIAL_SECONDS",
            300,
        )
        self.retry_max = self._positive_int(
            "NESSUS_UPDATE_RETRY_MAX_SECONDS",
            3600,
        )
        if self.retry_initial > self.retry_max:
            raise ValueError(
                "NESSUS_UPDATE_RETRY_INITIAL_SECONDS cannot exceed retry maximum"
            )

    @staticmethod
    def _positive_int(name: str, default: int) -> int:
        raw = os.environ.get(name, str(default))
        try:
            value = int(raw)
        except ValueError as exc:
            raise ValueError(f"{name} must be a positive integer") from exc
        if value <= 0:
            raise ValueError(f"{name} must be a positive integer")
        return value

    @staticmethod
    def _read_scheduler_state() -> dict[str, Any]:
        try:
            value = json.loads(SCHEDULER_STATE_FILE.read_text(encoding="utf-8"))
            return value if isinstance(value, dict) else {}
        except (OSError, json.JSONDecodeError):
            return {}

    @staticmethod
    def _write_scheduler_state(value: dict[str, Any]) -> None:
        SCHEDULER_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        temporary = SCHEDULER_STATE_FILE.with_suffix(".tmp")
        temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, SCHEDULER_STATE_FILE)

    @staticmethod
    def _last_success_epoch() -> int | None:
        try:
            value = int(UPDATE_SUCCESS_FILE.read_text(encoding="utf-8").strip())
            return value if value > 0 else None
        except (OSError, ValueError):
            return None

    def status(self) -> dict[str, Any]:
        if not self.enabled:
            return {"enabled": False}
        state = self._read_scheduler_state()
        next_attempt = state.get("next_attempt_epoch")
        next_attempt_at = None
        if isinstance(next_attempt, (int, float)) and next_attempt > 0:
            next_attempt_at = datetime.fromtimestamp(
                next_attempt,
                timezone.utc,
            ).replace(microsecond=0).isoformat()
        last_success = self._last_success_epoch()
        return {
            "enabled": True,
            "window_utc": self.window_text,
            "max_feed_age_hours": self.max_age_hours,
            "failure_count": state.get("failure_count", 0),
            "next_attempt_at": next_attempt_at,
            "last_success_at": (
                datetime.fromtimestamp(last_success, timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                if last_success
                else None
            ),
        }

    def due(self, now: datetime) -> bool:
        if not self.enabled or self.window is None:
            return False
        if not BOOTSTRAP_READY_FILE.is_file():
            return False
        now = now.astimezone(timezone.utc)
        if not within_update_window(now, self.window):
            return False
        state = self._read_scheduler_state()
        next_attempt = state.get("next_attempt_epoch", 0)
        if isinstance(next_attempt, (int, float)) and now.timestamp() < next_attempt:
            return False
        last_success = self._last_success_epoch()
        return (
            last_success is None
            or now.timestamp() - last_success >= self.max_age_hours * 3600
        )

    def _run_update(self) -> None:
        run_update_job(False, None, None, None, trigger="scheduled")
        update_state = read_state().get("state", "failed")
        scheduler_state = self._read_scheduler_state()
        now_epoch = int(time.time())
        if update_state == "completed":
            scheduler_state.update({
                "failure_count": 0,
                "next_attempt_epoch": now_epoch + self.max_age_hours * 3600,
            })
        else:
            failures = int(scheduler_state.get("failure_count", 0)) + 1
            delay = min(
                self.retry_max,
                self.retry_initial * (2 ** min(failures - 1, 20)),
            )
            scheduler_state.update({
                "failure_count": failures,
                "next_attempt_epoch": now_epoch + delay,
            })
        scheduler_state.update({
            "last_attempt_epoch": now_epoch,
            "last_result": update_state,
        })
        self._write_scheduler_state(scheduler_state)

    def tick(self, now: datetime | None = None) -> bool:
        global _update_thread
        current = now or datetime.now(timezone.utc)
        if not self.due(current) or not reserve_update_request():
            return False
        started = False
        try:
            _update_thread = threading.Thread(
                target=self._run_update,
                daemon=True,
                name="scheduled-plugin-update",
            )
            _update_thread.start()
            started = True
        finally:
            if not started:
                release_update_request()
        return True

    def run_forever(self) -> None:
        while True:
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001
                log(f"Scheduler error: {exc}")
            time.sleep(60)


def active_scans() -> list[dict[str, str]]:
    script = """
source /usr/local/bin/nessus-config.sh 2>/dev/null
source /usr/local/bin/nessus-api.sh 2>/dev/null
nessus_active_scans_report
"""
    proc = subprocess.run(
        ["bash", "-c", script],
        capture_output=True,
        text=True,
        timeout=30,
    )
    scans: list[dict[str, str]] = []
    for line in (proc.stdout or "").splitlines():
        parts = line.split("\t")
        if len(parts) >= 3:
            scans.append({"id": parts[0], "name": parts[1], "status": parts[2]})
    return scans


def fetch_nessus_session(req_headers: dict[str, str]) -> dict[str, Any] | None:
    req = urllib.request.Request(
        f"{NESSUS_API_BASE}/session",
        headers=req_headers,
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            if not isinstance(data, dict) or data.get("error"):
                return None
            return data
    except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, OSError):
        return None


def nessus_session_from_headers(headers: Any) -> dict[str, Any] | None:
    """Validate Nessus API keys via GET /session on the Nessus REST API."""
    api_keys = headers.get("X-ApiKeys", "").strip()
    if not api_keys:
        return None
    return fetch_nessus_session({"X-ApiKeys": api_keys})


def is_nessus_admin(session: dict[str, Any]) -> bool:
    perms = session.get("permissions", 0)
    if isinstance(perms, int) and perms >= ADMIN_PERMISSION:
        return True
    user_type = str(session.get("type", "")).lower()
    return user_type in {"administrator", "admin", "system administrator"}


class OperatorHandler(BaseHTTPRequestHandler):
    server_version = "NessusOperatorAPI/2.2"

    def log_message(self, fmt: str, *args: Any) -> None:
        if not hasattr(self, "path"):
            log(f"{self.address_string()} malformed HTTP request rejected")
            return
        path = urlparse(getattr(self, "path", "")).path.rstrip("/") or "/"
        command = getattr(self, "command", "")
        if (
            path == f"{API_PREFIX}/health"
            and command == "GET"
            and os.environ.get("NESSUS_MANAGE_LOG_HEALTH", "0") != "1"
        ):
            try:
                if int(args[1]) == 200:
                    return
            except (IndexError, ValueError, TypeError):
                pass
        log(f"{self.address_string()} {fmt % args}")

    def _json_response(self, code: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict[str, Any]:
        raw_length = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_length)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"invalid Content-Length: {raw_length!r}") from exc
        if length <= 0:
            return {}
        if length > MAX_JSON_BODY_BYTES:
            raise ValueError(f"JSON body exceeds {MAX_JSON_BODY_BYTES} bytes")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("JSON body must be an object")
        return data

    def _require_auth(self, admin: bool = False) -> dict[str, Any] | None:
        session = nessus_session_from_headers(self.headers)
        if not session:
            self._json_response(401, {
                "error": "Unauthorized",
                "hint": "Use X-ApiKeys: accessKey=...; secretKey=... (admin keys for POST/DELETE)",
            })
            return None
        if admin and not is_nessus_admin(session):
            self._json_response(403, {"error": "Administrator privileges required"})
            return None
        return session

    def _accept_update(self) -> bool:
        global _update_thread
        content_type = self.headers.get("Content-Type", "")
        try:
            if "multipart/form-data" in content_type:
                params = parse_update_request_multipart(self)
            else:
                body = self._read_json()
                params = parse_update_request_json(body)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            self._json_response(400, {"error": "Invalid update request", "message": str(exc)})
            return False
        params = apply_default_update_source(params)
        params = apply_env_plugin_set(params)
        if not params.get("archive") and not params.get("url"):
            self._json_response(400, {
                "error": "No update source",
                "message": (
                    "Provide archive (path or upload), source URL, "
                    "packages/all-2.0.tar.gz, or NESSUS_UPDATE_URL"
                ),
            })
            return False
        try:
            enforce_plugin_set_for_offline(params)
        except ValueError as exc:
            self._json_response(400, {"error": "Invalid update request", "message": str(exc)})
            return False
        resolved = "archive" if params.get("archive") else "url"
        _update_thread = threading.Thread(
            target=run_update_job,
            args=(
                params["force"],
                params.get("archive"),
                params.get("url"),
                params.get("plugin_set"),
            ),
            daemon=True,
        )
        _update_thread.start()
        self._json_response(202, {
            "status": "accepted",
            "message": "Update started",
            "force": params["force"],
            "archive": params.get("archive"),
            "plugin_set": params.get("plugin_set"),
            "source": redact_url(params.get("url")) if params.get("url") else params.get("archive"),
            "resolved_via": resolved,
        })
        return True

    def _route(self, method: str) -> None:
        path = urlparse(self.path).path.rstrip("/") or "/"

        if path == f"{API_PREFIX}/health" and method == "GET":
            self._json_response(200, build_health_payload())
            return

        admin_paths = {
            f"{API_PREFIX}/update",
            f"{API_PREFIX}/update/cancel",
            f"{API_PREFIX}/hold",
        }
        admin_required = method in {"POST", "DELETE"} and path in admin_paths
        if path not in {f"{API_PREFIX}/health"} and not self._require_auth(admin=admin_required):
            return

        if path == f"{API_PREFIX}/update/status" and method == "GET":
            st = read_state()
            st["in_progress"] = update_in_progress()
            self._json_response(200, st)
            return

        if path == f"{API_PREFIX}/update/cancel" and method == "POST":
            if not update_in_progress():
                st = read_state()
                if st.get("state") != "running":
                    self._json_response(409, {"error": "No update in progress"})
                    return
            ok, message = cancel_update_job()
            code = 200 if ok else 409
            self._json_response(code, {"status": "ok" if ok else "error", "message": message})
            return

        if path == f"{API_PREFIX}/update" and method == "POST":
            if not reserve_update_request():
                st = read_state()
                self._json_response(409, {
                    "error": "Update already in progress",
                    "in_progress": True,
                    "update_state": st.get("state", "running"),
                    "started_at": st.get("started_at"),
                    "hint": "Poll GET /manage/v1/health (no auth) or /manage/v1/update/status",
                })
                return
            started = False
            try:
                started = self._accept_update()
            finally:
                if not started:
                    release_update_request()
            return

        if path == f"{API_PREFIX}/hold" and method == "POST":
            try:
                body = self._read_json()
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                self._json_response(400, {"error": "Invalid JSON body", "message": str(exc)})
                return
            reason = str(body.get("reason", "orchestrator hold")).strip()
            if len(reason) > 200:
                reason = reason[:200]
            try:
                HOLD_FILE.parent.mkdir(parents=True, exist_ok=True)
                HOLD_FILE.write_text(reason + "\n", encoding="utf-8")
            except OSError as exc:
                self._json_response(500, {
                    "error": "Cannot write hold file",
                    "path": str(HOLD_FILE),
                    "message": str(exc),
                })
                return
            self._json_response(200, {"status": "ok", "hold_active": True, "reason": reason})
            return

        if path == f"{API_PREFIX}/hold" and method == "DELETE":
            try:
                if HOLD_FILE.is_file():
                    HOLD_FILE.unlink()
            except OSError as exc:
                self._json_response(500, {
                    "error": "Cannot remove hold file",
                    "path": str(HOLD_FILE),
                    "message": str(exc),
                })
                return
            self._json_response(200, {"status": "ok", "hold_active": False})
            return

        if path == f"{API_PREFIX}/scans/active" and method == "GET":
            try:
                scans = active_scans()
                self._json_response(200, {"count": len(scans), "scans": scans})
            except Exception as exc:  # noqa: BLE001
                self._json_response(503, {"error": str(exc)})
            return

        self._json_response(404, {"error": "Not found", "path": path})

    def do_GET(self) -> None:
        self._route("GET")

    def do_POST(self) -> None:
        self._route("POST")

    def do_DELETE(self) -> None:
        self._route("DELETE")


def main() -> None:
    global _scheduler
    host = os.environ.get("NESSUS_MANAGE_BIND", "127.0.0.1")
    port = int(os.environ.get("NESSUS_MANAGE_PORT", "8080"))
    try:
        _scheduler = UpdateScheduler()
    except ValueError as exc:
        raise SystemExit(f"Invalid scheduled update configuration: {exc}") from exc
    server = ThreadingHTTPServer((host, port), OperatorHandler)
    log(f"Listening on {host}:{port} (prefix {API_PREFIX}, auth: X-ApiKeys only)")
    if _scheduler.enabled:
        threading.Thread(
            target=_scheduler.run_forever,
            daemon=True,
            name="update-scheduler",
        ).start()
        log(
            "Scheduled updates enabled: "
            f"window={_scheduler.window_text} UTC, "
            f"max feed age={_scheduler.max_age_hours}h"
        )
    server.serve_forever()


if __name__ == "__main__":
    main()
