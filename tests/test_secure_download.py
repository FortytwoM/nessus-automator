from __future__ import annotations

import importlib.util
import sys
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "secure-download.py"
SPEC = importlib.util.spec_from_file_location("secure_download", MODULE_PATH)
assert SPEC and SPEC.loader
secure_download = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = secure_download
SPEC.loader.exec_module(secure_download)


class FakeResponse:
    status = 200

    def __init__(self, payload: bytes, content_length: str | None = None) -> None:
        self.payload = payload
        self.position = 0
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self, amount: int) -> bytes:
        chunk = self.payload[self.position:self.position + amount]
        self.position += len(chunk)
        return chunk


def public_dns(*_args, **_kwargs):
    return [(2, 1, 6, "", ("93.184.216.34", 443))]


class SecureDownloadTests(unittest.TestCase):
    def test_exact_and_subdomain_allowlist(self) -> None:
        self.assertTrue(
            secure_download.host_allowed(
                "plugins.nessus.org", {"plugins.nessus.org", "*.tenable.com"}
            )
        )
        self.assertTrue(
            secure_download.host_allowed(
                "downloads.tenable.com", {"plugins.nessus.org", "*.tenable.com"}
            )
        )
        self.assertFalse(
            secure_download.host_allowed("eviltenable.com", {"*.tenable.com"})
        )

    @mock.patch.object(secure_download.socket, "getaddrinfo")
    def test_rejects_private_dns_result(self, resolver: mock.Mock) -> None:
        resolver.return_value = [(2, 1, 6, "", ("127.0.0.1", 443))]
        with self.assertRaisesRegex(secure_download.DownloadError, "forbidden address"):
            secure_download.validate_url(
                "https://plugins.nessus.org/feed",
                {"https"},
                {"plugins.nessus.org"},
                {443},
            )

    @mock.patch.object(secure_download.socket, "getaddrinfo")
    def test_dns_resolution_has_timeout(self, resolver: mock.Mock) -> None:
        resolver.side_effect = lambda *_args, **_kwargs: (
            time.sleep(0.05) or public_dns()
        )
        with self.assertRaisesRegex(secure_download.DownloadError, "timed out"):
            secure_download.resolve_addresses(
                "plugins.nessus.org", 443, timeout=0.001
            )

    @mock.patch.object(secure_download.socket, "getaddrinfo", side_effect=public_dns)
    @mock.patch.object(secure_download, "proxy_target_for", return_value=None)
    @mock.patch.object(secure_download.urllib.request, "build_opener")
    def test_enforces_streamed_byte_limit(
        self, build_opener: mock.Mock, _proxy: mock.Mock, _resolver: mock.Mock
    ) -> None:
        build_opener.return_value.open.return_value = FakeResponse(b"x" * 10241)
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "feed.bin"
            with self.assertRaisesRegex(secure_download.DownloadError, "hard limit"):
                secure_download.download(
                    "https://plugins.nessus.org/feed",
                    output,
                    max_bytes=10240,
                    timeout=10,
                    max_redirects=2,
                    allowed_schemes={"https"},
                    allowed_hosts={"plugins.nessus.org"},
                    allowed_ports={443},
                    expected_sha256=None,
                )
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])

    @mock.patch.object(secure_download.socket, "getaddrinfo")
    @mock.patch.object(secure_download, "proxy_target_for", return_value=None)
    @mock.patch.object(secure_download.urllib.request, "build_opener")
    def test_revalidates_redirect_target(
        self, build_opener: mock.Mock, _proxy: mock.Mock, resolver: mock.Mock
    ) -> None:
        resolver.side_effect = lambda host, *_args, **_kwargs: [
            (2, 1, 6, "", (host if host == "127.0.0.1" else "93.184.216.34", 443))
        ]
        build_opener.return_value.open.side_effect = urllib.error.HTTPError(
            "https://plugins.nessus.org/feed",
            302,
            "Found",
            {"Location": "https://127.0.0.1/private"},
            None,
        )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(secure_download.DownloadError, "forbidden address"):
                secure_download.download(
                    "https://plugins.nessus.org/feed",
                    Path(directory) / "feed.bin",
                    max_bytes=10240,
                    timeout=10,
                    max_redirects=2,
                    allowed_schemes={"https"},
                    allowed_hosts={"plugins.nessus.org", "127.0.0.1"},
                    allowed_ports={443},
                    expected_sha256=None,
                )

    @mock.patch.object(secure_download.socket, "getaddrinfo")
    @mock.patch.object(secure_download, "proxy_target_for", return_value=None)
    @mock.patch.object(secure_download.urllib.request, "build_opener")
    def test_redirect_is_revalidated_and_repinned(
        self,
        build_opener: mock.Mock,
        _proxy: mock.Mock,
        resolver: mock.Mock,
    ) -> None:
        resolver.side_effect = lambda host, *_args, **_kwargs: [
            (
                2,
                1,
                6,
                "",
                (
                    "93.184.216.34"
                    if host == "plugins.nessus.org"
                    else "8.8.8.8",
                    443,
                ),
            )
        ]
        redirect = urllib.error.HTTPError(
            "https://plugins.nessus.org/feed",
            302,
            "Found",
            {"Location": "https://downloads.tenable.com/feed"},
            None,
        )
        first_opener = mock.Mock()
        first_opener.open.side_effect = redirect
        second_opener = mock.Mock()
        second_opener.open.return_value = FakeResponse(b"feed")
        build_opener.side_effect = [first_opener, second_opener]

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "feed.bin"
            secure_download.download(
                "https://plugins.nessus.org/feed",
                output,
                max_bytes=10240,
                timeout=10,
                max_redirects=2,
                allowed_schemes={"https"},
                allowed_hosts={"plugins.nessus.org", "downloads.tenable.com"},
                allowed_ports={443},
                expected_sha256=None,
            )

        handlers = [
            next(
                item
                for item in call.args
                if isinstance(item, secure_download.PinnedHTTPSHandler)
            )
            for call in build_opener.call_args_list
        ]
        self.assertEqual(handlers[0].target.addresses, ("93.184.216.34",))
        self.assertEqual(handlers[1].target.addresses, ("8.8.8.8",))

    def test_pinned_connection_uses_ip_and_original_tls_hostname(self) -> None:
        context = mock.Mock()
        wrapped_socket = mock.Mock()
        context.wrap_socket.return_value = wrapped_socket
        connection = secure_download.PinnedHTTPSConnection(
            "plugins.nessus.org",
            "93.184.216.34",
            443,
            timeout=5,
            context=context,
            proxy=None,
        )
        raw_socket = mock.Mock()
        connection._create_connection = mock.Mock(return_value=raw_socket)

        connection.connect()

        connection._create_connection.assert_called_once_with(
            ("93.184.216.34", 443),
            5,
            None,
        )
        context.wrap_socket.assert_called_once_with(
            raw_socket,
            server_hostname="plugins.nessus.org",
        )
        self.assertIs(connection.sock, wrapped_socket)


if __name__ == "__main__":
    unittest.main()
