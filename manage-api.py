#!/usr/bin/env python3
"""Operator API — plugin updates, hold, scan status (same auth as Nessus REST)."""

from __future__ import annotations

import json
import mmap
import os
import shutil
import signal
import ssl
import subprocess
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

STATE_FILE = Path(os.environ.get(
    "NESSUS_MANAGE_STATE_FILE", "/opt/nessus/var/nessus/.manage_update_state.json"
))
UPDATE_SCRIPT = "/usr/local/bin/update.sh"
UPLOAD_DIR = Path(os.environ.get(
    "NESSUS_MANAGE_UPLOAD_DIR", "/opt/nessus/var/nessus/incoming"
))
MAX_UPLOAD_BYTES = int(os.environ.get("NESSUS_MANAGE_MAX_UPLOAD_BYTES", str(2 * 1024 ** 3)))
ALLOWED_ARCHIVE_ROOTS = (
    Path("/mnt/nessus"),
    Path("/opt/nessus/var/nessus/incoming"),
    Path("/tmp"),
)
HOLD_FILE = Path(os.environ.get(
    "NESSUS_UPDATE_HOLD_FILE", "/opt/nessus/var/nessus/.update_hold"
))
LOCK_FILE = Path("/tmp/nessus_update.lock")
API_PREFIX = "/manage/v1"
OPERATOR_VERSION = "2.2"
NESSUS_API_BASE = os.environ.get("NESSUS_API_BASE", "https://127.0.0.1:8834").rstrip("/")
ADMIN_PERMISSION = int(os.environ.get("NESSUS_MANAGE_ADMIN_PERMISSION", "128"))
_state_lock = threading.Lock()
_proc_lock = threading.Lock()
_update_thread: threading.Thread | None = None
_update_proc: subprocess.Popen[str] | None = None
_ssl_ctx = ssl.create_default_context()
_ssl_ctx.check_hostname = False
_ssl_ctx.verify_mode = ssl.CERT_NONE


def redact_url(value: str | None) -> str | None:
    if not value:
        return value
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value

    redacted_query = []
    for key, item in parse_qsl(parsed.query, keep_blank_values=True):
        if key.lower() in {"u", "p", "user", "username", "password", "token", "key"}:
            redacted_query.append((key, "***"))
        else:
            redacted_query.append((key, item))
    return urlunparse(parsed._replace(query=urlencode(redacted_query)))


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


def _read_update_pid() -> int | None:
    if not LOCK_FILE.is_file():
        return None
    try:
        return int(LOCK_FILE.read_text(encoding="utf-8").strip())
    except (ValueError, OSError):
        return None


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

    deadline = time.time() + 15
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

    if LOCK_FILE.is_file():
        try:
            LOCK_FILE.unlink()
        except OSError:
            pass

    st = read_state()
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
            raise ValueError(f"{key} must point to an existing file under /mnt/nessus, incoming, or /tmp")
        return str(path)

    source = body.get("source")
    if isinstance(source, str) and source.strip():
        parsed = urlparse(source.strip())
        if parsed.scheme in {"http", "https"}:
            return None
        path = safe_archive_path(source.strip())
        if path is None:
            raise ValueError("source must be an http(s) URL or a local archive path")
        return str(path)
    return None


def resolve_update_url(body: dict[str, Any]) -> str | None:
    source = body.get("source")
    if not isinstance(source, str) or not source.strip():
        return None
    parsed = urlparse(source.strip())
    if parsed.scheme in {"http", "https"}:
        return source.strip()
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
) -> tuple[dict[str, str], tuple[str, int, int] | None]:
    boundary = _multipart_boundary(content_type)
    marker = b"--" + boundary
    fields: dict[str, str] = {}
    archive: tuple[str, int, int] | None = None

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
                if filename and name in {"archive", "file", "update_file"}:
                    archive = (Path(filename).name, body_start, body_end)
                elif name:
                    fields[name] = mm[body_start:body_end].decode("utf-8", errors="replace").strip()

                pos = next_marker + 2
        finally:
            mm.close()

    return fields, archive


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

    with spool.open("rb") as src, dest.open("wb") as dst:
        src.seek(start)
        shutil.copyfileobj(src, dst, length=size)

    return dest


def parse_update_request_multipart(handler: Any) -> dict[str, Any]:
    content_type = handler.headers.get("Content-Type", "")
    length = int(handler.headers.get("Content-Length", 0))
    spool = _spool_request_body(handler.rfile, length, MAX_UPLOAD_BYTES + 65536)
    try:
        fields, archive_part = _parse_multipart_spool(spool, content_type)
        if archive_part is None:
            raise ValueError("multipart request must include archive file field")

        filename, start, end = archive_part
        force = fields.get("force", "").lower() in {"1", "true", "yes", "on"}
        plugin_set = validate_plugin_set(
            fields.get("plugin_set") or fields.get("plugin_set_id") or fields.get("feed_id")
        )
        saved = save_uploaded_slice(spool, filename, start, end)
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
    engine = status.get("engine_status")
    engine_state = None
    engine_progress = None
    if isinstance(engine, dict):
        engine_state = engine.get("status")
        engine_progress = engine.get("progress")
    plugin_data = status.get("pluginData") is True
    plugin_set = status.get("pluginSet")
    if plugin_set is not None:
        plugin_set = str(plugin_set)
    ready = engine_state == "ready" and plugin_data
    return {
        "ready": ready,
        "plugin_set": plugin_set,
        "plugin_data": plugin_data,
        "engine_status": engine_state,
        "engine_progress": engine_progress,
        "nessus_status": status.get("status"),
    }


def build_health_payload() -> dict[str, Any]:
    st = read_state()
    nessus = nessus_status_fields(fetch_server_status())
    in_progress = update_running()
    return {
        "status": "ok",
        "operator_version": OPERATOR_VERSION,
        "update_state": "running" if in_progress and st.get("state") == "idle" else st.get("state", "idle"),
        "update_in_progress": in_progress,
        "update_started_at": st.get("started_at"),
        "update_message": st.get("message"),
        "hold_active": HOLD_FILE.is_file(),
        **nessus,
    }


def cleanup_incoming_uploads() -> None:
    if not UPLOAD_DIR.is_dir():
        return
    removed = 0
    for path in UPLOAD_DIR.iterdir():
        if not path.is_file():
            continue
        if path.suffix in {".gz", ".tgz"} or path.name.endswith(".tar.gz"):
            try:
                path.unlink()
                removed += 1
            except OSError:
                continue
    if removed:
        log(f"Cleaned {removed} file(s) from {UPLOAD_DIR}")


def run_update_job(
    force: bool,
    archive: str | None,
    url: str | None,
    plugin_set: str | None,
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
        if exit_code == 0:
            state = "completed"
            msg = "Update finished successfully"
            cleanup_incoming_uploads()
        elif exit_code == 2:
            state = "deferred"
            msg = "Update deferred (scans or hold file)"
        elif exit_code == 130:
            state = "cancelled"
            msg = "Update cancelled"
        else:
            state = "failed"
            msg = f"Update failed with exit code {exit_code}"
        write_state({
            "state": state,
            "started_at": started_at,
            "finished_at": utc_now(),
            "force": force,
            "source": safe_source,
            "archive": archive,
            "plugin_set": plugin_set,
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
        path = urlparse(self.path).path.rstrip("/") or "/"
        if (
            path == f"{API_PREFIX}/health"
            and self.command == "GET"
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
        length = int(self.headers.get("Content-Length", 0))
        if length <= 0:
            return {}
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

    def _route(self, method: str) -> None:
        global _update_thread
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
            st["in_progress"] = update_running()
            self._json_response(200, st)
            return

        if path == f"{API_PREFIX}/update/cancel" and method == "POST":
            if not update_running() and (_update_thread is None or not _update_thread.is_alive()):
                st = read_state()
                if st.get("state") != "running":
                    self._json_response(409, {"error": "No update in progress"})
                    return
            ok, message = cancel_update_job()
            code = 200 if ok else 409
            self._json_response(code, {"status": "ok" if ok else "error", "message": message})
            return

        if path == f"{API_PREFIX}/update" and method == "POST":
            if update_running() or (_update_thread and _update_thread.is_alive()):
                st = read_state()
                self._json_response(409, {
                    "error": "Update already in progress",
                    "in_progress": True,
                    "update_state": st.get("state", "running"),
                    "started_at": st.get("started_at"),
                    "hint": "Poll GET /manage/v1/health (no auth) or /manage/v1/update/status",
                })
                return
            content_type = self.headers.get("Content-Type", "")
            try:
                if "multipart/form-data" in content_type:
                    params = parse_update_request_multipart(self)
                else:
                    body = self._read_json()
                    params = parse_update_request_json(body)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
                self._json_response(400, {"error": "Invalid update request", "message": str(exc)})
                return
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
                return
            try:
                enforce_plugin_set_for_offline(params)
            except ValueError as exc:
                self._json_response(400, {"error": "Invalid update request", "message": str(exc)})
                return
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
    host = os.environ.get("NESSUS_MANAGE_BIND", "0.0.0.0")
    port = int(os.environ.get("NESSUS_MANAGE_PORT", "8080"))
    server = ThreadingHTTPServer((host, port), OperatorHandler)
    log(f"Listening on {host}:{port} (prefix {API_PREFIX}, auth: X-ApiKeys only)")
    server.serve_forever()


if __name__ == "__main__":
    main()
