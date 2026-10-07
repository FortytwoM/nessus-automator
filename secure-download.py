#!/usr/bin/env python3
"""Download one approved HTTPS artifact with redirect and size validation."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import ipaddress
import os
import queue
import socket
import ssl
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urljoin, urlparse

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from nessus_url_policy import host_allowed  # noqa: E402


class DownloadError(RuntimeError):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        return None


@dataclass(frozen=True)
class ValidatedTarget:
    url: str
    host: str
    port: int
    addresses: tuple[str, ...]


@dataclass(frozen=True)
class ProxyTarget:
    host: str
    port: int
    authorization: str | None


class PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(
        self,
        original_host: str,
        pinned_ip: str,
        port: int,
        *,
        timeout: float,
        context: ssl.SSLContext,
        proxy: ProxyTarget | None,
    ) -> None:
        super().__init__(original_host, port, timeout=timeout, context=context)
        self._pinned_ip = pinned_ip
        self._proxy = proxy

    def connect(self) -> None:
        endpoint = (
            (self._proxy.host, self._proxy.port)
            if self._proxy
            else (self._pinned_ip, self.port)
        )
        self.sock = self._create_connection(
            endpoint,
            self.timeout,
            self.source_address,
        )
        if self._proxy:
            tunnel_host = (
                f"[{self._pinned_ip}]" if ":" in self._pinned_ip else self._pinned_ip
            )
            authority = f"{tunnel_host}:{self.port}"
            self._tunnel_host = tunnel_host
            self._tunnel_port = self.port
            self._tunnel_headers = {"Host": authority}
            if self._proxy.authorization:
                self._tunnel_headers["Proxy-Authorization"] = self._proxy.authorization
            self._tunnel()
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


class PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(
        self,
        target: ValidatedTarget,
        context: ssl.SSLContext,
        timeout: float,
        proxy: ProxyTarget | None,
    ) -> None:
        super().__init__(context=context)
        self.target = target
        self.timeout = timeout
        self.proxy = proxy

    def https_open(self, request):  # type: ignore[no-untyped-def]
        def connection_factory(_host, **_kwargs):  # type: ignore[no-untyped-def]
            return PinnedHTTPSConnection(
                self.target.host,
                self.target.addresses[0],
                self.target.port,
                timeout=self.timeout,
                context=self._context,
                proxy=self.proxy,
            )

        return self.do_open(connection_factory, request)


def csv_values(value: str) -> set[str]:
    return {item.strip().lower() for item in value.split(",") if item.strip()}



def resolve_addresses(host: str, port: int, timeout: float) -> set[str]:
    result: queue.Queue[tuple[list[tuple] | None, BaseException | None]] = queue.Queue(1)

    def resolve() -> None:
        try:
            records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            result.put((records, None))
        except BaseException as exc:
            result.put((None, exc))

    threading.Thread(target=resolve, daemon=True).start()
    try:
        records, error = result.get(timeout=timeout)
    except queue.Empty as exc:
        raise DownloadError(f"DNS resolution timed out for {host}") from exc
    if error:
        raise DownloadError(f"DNS resolution failed for {host}: {error}") from error
    assert records is not None
    return {item[4][0] for item in records}


def validate_target(
    value: str,
    allowed_schemes: set[str],
    allowed_hosts: set[str],
    allowed_ports: set[int],
    dns_timeout: float = 10,
) -> ValidatedTarget:
    parsed = urlparse(value)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    if scheme not in allowed_schemes:
        raise DownloadError(f"scheme '{scheme or '<empty>'}' is not allowed")
    if parsed.username is not None or parsed.password is not None:
        raise DownloadError("URL userinfo is not allowed; use query credentials or a proxy")
    if not host or not host_allowed(host, allowed_hosts):
        raise DownloadError(f"host '{host or '<empty>'}' is not allowlisted")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise DownloadError(f"invalid URL port: {exc}") from exc
    if port not in allowed_ports:
        raise DownloadError(f"port {port} is not allowed")

    addresses = resolve_addresses(host, port, dns_timeout)
    if not addresses:
        raise DownloadError(f"DNS returned no addresses for {host}")
    for raw in addresses:
        address = ipaddress.ip_address(raw)
        if not address.is_global:
            raise DownloadError(f"{host} resolves to forbidden address {address}")

    ordered_addresses = tuple(
        sorted(addresses, key=lambda item: (ipaddress.ip_address(item).version, item))
    )
    return ValidatedTarget(parsed.geturl(), host, port, ordered_addresses)


def validate_url(
    value: str,
    allowed_schemes: set[str],
    allowed_hosts: set[str],
    allowed_ports: set[int],
    dns_timeout: float = 10,
) -> str:
    return validate_target(
        value,
        allowed_schemes,
        allowed_hosts,
        allowed_ports,
        dns_timeout,
    ).url


def proxy_target_for(host: str) -> ProxyTarget | None:
    if urllib.request.proxy_bypass(host):
        return None
    value = urllib.request.getproxies().get("https")
    if not value:
        return None
    parsed = urlparse(value if "://" in value else f"http://{value}")
    if parsed.scheme.lower() != "http":
        raise DownloadError("only HTTP CONNECT proxies are supported for HTTPS downloads")
    if not parsed.hostname:
        raise DownloadError("HTTPS proxy has no hostname")
    try:
        port = parsed.port or 80
    except ValueError as exc:
        raise DownloadError(f"invalid HTTPS proxy port: {exc}") from exc
    authorization = None
    if parsed.username is not None:
        username = unquote(parsed.username)
        password = unquote(parsed.password or "")
        token = base64.b64encode(f"{username}:{password}".encode()).decode()
        authorization = f"Basic {token}"
    return ProxyTarget(parsed.hostname, port, authorization)


def open_pinned(
    target: ValidatedTarget,
    context: ssl.SSLContext,
    timeout: float,
    deadline: float | None = None,
):
    if urlparse(target.url).scheme.lower() != "https":
        raise DownloadError("only HTTPS downloads are supported")
    proxy = proxy_target_for(target.host)
    last_error: urllib.error.URLError | None = None
    for address in target.addresses:
        attempt_timeout = timeout
        if deadline is not None:
            attempt_timeout = min(timeout, deadline - time.monotonic())
            if attempt_timeout <= 0:
                raise DownloadError("download timed out")
        pinned = ValidatedTarget(target.url, target.host, target.port, (address,))
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            PinnedHTTPSHandler(pinned, context, attempt_timeout, proxy),
            NoRedirect(),
        )
        request = urllib.request.Request(
            target.url,
            headers={"User-Agent": "nessus-automator-secure-download/1"},
        )
        try:
            return opener.open(request, timeout=attempt_timeout)
        except urllib.error.HTTPError:
            raise
        except urllib.error.URLError as exc:
            last_error = exc
    if last_error is not None:
        raise last_error
    raise DownloadError(f"DNS returned no addresses for {target.host}")


def download(
    url: str,
    output: Path,
    max_bytes: int,
    timeout: int,
    max_redirects: int,
    allowed_schemes: set[str],
    allowed_hosts: set[str],
    allowed_ports: set[int],
    expected_sha256: str | None,
) -> tuple[int, str]:
    if max_bytes < 10240:
        raise DownloadError("max bytes must be at least 10240")
    if timeout < 1:
        raise DownloadError("timeout must be positive")

    context = ssl.create_default_context()
    current = url
    deadline = time.monotonic() + timeout
    output.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None

    try:
        for redirect_count in range(max_redirects + 1):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DownloadError("download timed out")
            target = validate_target(
                current,
                allowed_schemes,
                allowed_hosts,
                allowed_ports,
                dns_timeout=min(10, remaining),
            )
            current = target.url
            try:
                response = open_pinned(
                    target,
                    context,
                    min(30, remaining),
                    deadline,
                )
            except urllib.error.HTTPError as exc:
                if exc.code in {301, 302, 303, 307, 308}:
                    location = exc.headers.get("Location")
                    if not location:
                        raise DownloadError(f"redirect {exc.code} has no Location") from exc
                    if redirect_count >= max_redirects:
                        raise DownloadError("too many redirects") from exc
                    current = urljoin(current, location)
                    continue
                raise DownloadError(f"HTTP {exc.code}") from exc
            except urllib.error.URLError as exc:
                raise DownloadError(f"request failed: {exc.reason}") from exc

            with response:
                status = getattr(response, "status", 200)
                if status != 200:
                    raise DownloadError(f"unexpected HTTP status {status}")
                content_length = response.headers.get("Content-Length")
                if content_length:
                    try:
                        declared = int(content_length)
                    except ValueError as exc:
                        raise DownloadError("invalid Content-Length") from exc
                    if declared > max_bytes:
                        raise DownloadError(
                            f"Content-Length {declared} exceeds limit {max_bytes}"
                        )

                digest = hashlib.sha256()
                copied = 0
                with tempfile.NamedTemporaryFile(
                    mode="wb", dir=output.parent, prefix=".download-", delete=False
                ) as handle:
                    temp_name = handle.name
                    while True:
                        if time.monotonic() > deadline:
                            raise DownloadError("download timed out")
                        chunk = response.read(min(1024 * 1024, max_bytes - copied + 1))
                        if not chunk:
                            break
                        copied += len(chunk)
                        if copied > max_bytes:
                            raise DownloadError(
                                f"download exceeds hard limit {max_bytes} bytes"
                            )
                        handle.write(chunk)
                        digest.update(chunk)

                actual_sha256 = digest.hexdigest()
                if expected_sha256 and actual_sha256.lower() != expected_sha256.lower():
                    raise DownloadError(
                        f"SHA-256 mismatch: expected {expected_sha256.lower()}, "
                        f"got {actual_sha256}"
                    )
                os.replace(temp_name, output)
                temp_name = None
                return copied, actual_sha256

        raise DownloadError("too many redirects")
    finally:
        if temp_name:
            Path(temp_name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("url")
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--max-bytes",
        type=int,
        default=int(os.environ.get("NESSUS_DOWNLOAD_MAX_BYTES", "1073741824")),
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.environ.get("NESSUS_DOWNLOAD_TIMEOUT", "1800")),
    )
    parser.add_argument("--max-redirects", type=int, default=5)
    parser.add_argument(
        "--allowed-schemes",
        default=os.environ.get("NESSUS_DOWNLOAD_ALLOWED_SCHEMES", "https"),
    )
    parser.add_argument(
        "--allowed-hosts",
        default=os.environ.get(
            "NESSUS_DOWNLOAD_ALLOWED_HOSTS", "plugins.nessus.org,*.tenable.com"
        ),
    )
    parser.add_argument(
        "--allowed-ports",
        default=os.environ.get("NESSUS_DOWNLOAD_ALLOWED_PORTS", "443"),
    )
    parser.add_argument("--sha256", default=None)
    args = parser.parse_args()

    try:
        allowed_ports = {int(item) for item in csv_values(args.allowed_ports)}
        size, digest = download(
            args.url,
            args.output,
            args.max_bytes,
            args.timeout,
            args.max_redirects,
            csv_values(args.allowed_schemes),
            csv_values(args.allowed_hosts),
            allowed_ports,
            args.sha256,
        )
    except (DownloadError, ValueError) as exc:
        print(f"secure-download: {exc}", file=os.sys.stderr)
        return 1

    print(f"downloaded={size} sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
