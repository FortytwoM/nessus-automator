from __future__ import annotations

import importlib.util
import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "manage-api.py"
SPEC = importlib.util.spec_from_file_location("manage_api", MODULE_PATH)
assert SPEC and SPEC.loader
manage_api = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(manage_api)


def multipart_body(boundary: str, payload: bytes, signature: bytes | None = None) -> bytes:
    body = (
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="force"\r\n'
        "\r\n"
        "true\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="plugin_set"\r\n'
        "\r\n"
        "202609100156\r\n"
        f"--{boundary}\r\n"
        'Content-Disposition: form-data; name="archive"; filename="feed.tar.gz"\r\n'
        "Content-Type: application/octet-stream\r\n"
        "\r\n"
    ).encode("utf-8")
    body += payload + b"\r\n"
    if signature is not None:
        body += (
            f"--{boundary}\r\n"
            'Content-Disposition: form-data; name="signature"; '
            'filename="all-2.0.tar.gz.sig"\r\n'
            "Content-Type: application/octet-stream\r\n"
            "\r\n"
        ).encode("utf-8")
        body += signature + b"\r\n"
    body += f"--{boundary}--\r\n".encode("utf-8")
    return body


class OperatorHandlerTests(unittest.TestCase):
    def test_log_message_handles_request_without_parsed_path(self) -> None:
        handler = object.__new__(manage_api.OperatorHandler)
        handler.client_address = ("127.0.0.1", 12345)

        with mock.patch.object(manage_api, "log") as logger:
            handler.log_message("code %d, message %s", 400, "Bad request")

        logger.assert_called_once()

    def test_nested_nessus_status_and_cached_plugin_set(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            ready_file = Path(directory) / "ready"
            plugin_set_file = Path(directory) / "plugin-set"
            ready_file.touch()
            plugin_set_file.write_text("202609100156\n", encoding="utf-8")
            status = {
                "detailed_status": {
                    "engine_status": {"progress": 100, "status": "ready"}
                },
                "pluginSet": True,
                "pluginData": True,
                "status": "ready",
            }
            with (
                mock.patch.object(manage_api, "BOOTSTRAP_READY_FILE", ready_file),
                mock.patch.object(manage_api, "PLUGIN_SET_FILE", plugin_set_file),
                mock.patch.dict(manage_api.os.environ, {"NESSUS_HEALTH_STRICT": "1"}),
            ):
                fields = manage_api.nessus_status_fields(status)

        self.assertTrue(fields["ready"])
        self.assertEqual(fields["plugin_set"], "202609100156")
        self.assertEqual(fields["engine_status"], "ready")
        self.assertEqual(fields["engine_progress"], 100)

    def test_update_exit_code_three_is_deferred(self) -> None:
        state, message = manage_api.classify_update_exit(3)

        self.assertEqual(state, "deferred")
        self.assertIn("lock", message)

    def test_update_exit_code_two_is_deferred(self) -> None:
        state, message = manage_api.classify_update_exit(2)

        self.assertEqual(state, "deferred")
        self.assertIn("scans", message)

    def test_update_exit_code_interrupt_is_cancelled(self) -> None:
        state, _message = manage_api.classify_update_exit(130)

        self.assertEqual(state, "cancelled")

    def test_cancel_wait_seconds_are_bounded(self) -> None:
        with mock.patch.dict(manage_api.os.environ, {"NESSUS_UPDATE_CANCEL_WAIT_SECONDS": "10"}):
            self.assertEqual(manage_api.update_cancel_wait_seconds(), 30)
        with mock.patch.dict(manage_api.os.environ, {"NESSUS_UPDATE_CANCEL_WAIT_SECONDS": "9999"}):
            self.assertEqual(manage_api.update_cancel_wait_seconds(), 1800)
        with mock.patch.dict(manage_api.os.environ, {"NESSUS_UPDATE_CANCEL_WAIT_SECONDS": "180"}):
            self.assertEqual(manage_api.update_cancel_wait_seconds(), 180)

    def test_update_exit_code_four_is_rolled_back(self) -> None:
        state, message = manage_api.classify_update_exit(4)

        self.assertEqual(state, "rolled_back")
        self.assertIn("restored", message)

    def test_scheduler_window_and_feed_age(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            success_file = Path(directory) / "success"
            scheduler_file = Path(directory) / "scheduler.json"
            ready_file = Path(directory) / "ready"
            ready_file.touch()
            environment = {
                "NESSUS_UPDATE_WINDOW_UTC": "23:00-02:00",
                "NESSUS_UPDATE_MAX_FEED_AGE_HOURS": "48",
                "NESSUS_UPDATE_RETRY_INITIAL_SECONDS": "300",
                "NESSUS_UPDATE_RETRY_MAX_SECONDS": "3600",
            }
            with (
                mock.patch.dict(manage_api.os.environ, environment),
                mock.patch.object(manage_api, "UPDATE_SUCCESS_FILE", success_file),
                mock.patch.object(manage_api, "SCHEDULER_STATE_FILE", scheduler_file),
                mock.patch.object(manage_api, "BOOTSTRAP_READY_FILE", ready_file),
            ):
                scheduler = manage_api.UpdateScheduler()
                now = datetime(2026, 9, 10, 0, 30, tzinfo=timezone.utc)
                self.assertTrue(scheduler.due(now))

                success_file.write_text(str(int(now.timestamp())), encoding="utf-8")
                self.assertFalse(scheduler.due(now))
                self.assertFalse(
                    scheduler.due(
                        datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
                    )
                )

    def test_old_feed_outside_window_is_not_due(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            success_file = Path(directory) / "success"
            scheduler_file = Path(directory) / "scheduler.json"
            ready_file = Path(directory) / "ready"
            ready_file.touch()
            success_file.write_text("1", encoding="utf-8")
            environment = {
                "NESSUS_UPDATE_WINDOW_UTC": "02:00-05:00",
                "NESSUS_UPDATE_MAX_FEED_AGE_HOURS": "1",
            }
            with (
                mock.patch.dict(manage_api.os.environ, environment),
                mock.patch.object(manage_api, "UPDATE_SUCCESS_FILE", success_file),
                mock.patch.object(manage_api, "SCHEDULER_STATE_FILE", scheduler_file),
                mock.patch.object(manage_api, "BOOTSTRAP_READY_FILE", ready_file),
            ):
                scheduler = manage_api.UpdateScheduler()
                now = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
                self.assertFalse(scheduler.due(now))
                self.assertTrue(
                    scheduler.due(datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc))
                )

    def test_scheduler_backoff_on_deferred_and_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scheduler_file = Path(directory) / "scheduler.json"
            environment = {
                "NESSUS_UPDATE_WINDOW_UTC": "02:00-05:00",
                "NESSUS_UPDATE_RETRY_INITIAL_SECONDS": "300",
                "NESSUS_UPDATE_RETRY_MAX_SECONDS": "3600",
            }
            with (
                mock.patch.dict(manage_api.os.environ, environment),
                mock.patch.object(manage_api, "SCHEDULER_STATE_FILE", scheduler_file),
                mock.patch.object(manage_api, "run_update_job"),
                mock.patch.object(
                    manage_api,
                    "read_state",
                    side_effect=[{"state": "deferred"}, {"state": "rolled_back"}],
                ),
                mock.patch.object(manage_api.time, "time", return_value=2000),
            ):
                scheduler = manage_api.UpdateScheduler()
                scheduler._run_update()
                first = json.loads(scheduler_file.read_text(encoding="utf-8"))
                scheduler._run_update()
                second = json.loads(scheduler_file.read_text(encoding="utf-8"))

        self.assertEqual(first["last_result"], "deferred")
        self.assertEqual(first["next_attempt_epoch"], 2300)
        self.assertEqual(second["last_result"], "rolled_back")
        self.assertEqual(second["failure_count"], 2)
        self.assertEqual(second["next_attempt_epoch"], 2600)

    def test_overnight_window_parsing(self) -> None:
        window = manage_api.parse_update_window("23:00-02:00")
        inside = datetime(2026, 9, 10, 0, 15, tzinfo=timezone.utc)
        outside = datetime(2026, 9, 10, 12, 0, tzinfo=timezone.utc)
        self.assertTrue(manage_api.within_update_window(inside, window))
        self.assertFalse(manage_api.within_update_window(outside, window))

    def test_scheduler_rejects_invalid_window(self) -> None:
        with mock.patch.dict(
            manage_api.os.environ,
            {"NESSUS_UPDATE_WINDOW_UTC": "25:00-26:00"},
        ):
            with self.assertRaisesRegex(ValueError, "invalid UTC time"):
                manage_api.UpdateScheduler()

    def test_scheduler_applies_bounded_backoff(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            scheduler_file = Path(directory) / "scheduler.json"
            environment = {
                "NESSUS_UPDATE_WINDOW_UTC": "02:00-05:00",
                "NESSUS_UPDATE_RETRY_INITIAL_SECONDS": "300",
                "NESSUS_UPDATE_RETRY_MAX_SECONDS": "600",
            }
            with (
                mock.patch.dict(manage_api.os.environ, environment),
                mock.patch.object(manage_api, "SCHEDULER_STATE_FILE", scheduler_file),
                mock.patch.object(manage_api, "run_update_job"),
                mock.patch.object(manage_api, "read_state", return_value={"state": "failed"}),
                mock.patch.object(manage_api.time, "time", return_value=1000),
            ):
                scheduler = manage_api.UpdateScheduler()
                scheduler._run_update()
                first = json.loads(scheduler_file.read_text(encoding="utf-8"))
                scheduler._run_update()
                second = json.loads(scheduler_file.read_text(encoding="utf-8"))

        self.assertEqual(first["failure_count"], 1)
        self.assertEqual(first["next_attempt_epoch"], 1300)
        self.assertEqual(second["failure_count"], 2)
        self.assertEqual(second["next_attempt_epoch"], 1600)

    def test_only_one_concurrent_update_request_is_reserved(self) -> None:
        worker_count = 8
        barrier = threading.Barrier(worker_count)
        results: list[bool] = []
        manage_api._update_thread = None
        manage_api._update_request_reserved = False

        def reserve() -> None:
            barrier.wait()
            results.append(manage_api.reserve_update_request())

        with mock.patch.object(manage_api, "update_running", return_value=False):
            workers = [threading.Thread(target=reserve) for _ in range(worker_count)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join()

        manage_api.release_update_request()
        self.assertEqual(results.count(True), 1)
        self.assertEqual(results.count(False), worker_count - 1)


    def test_parse_multipart_extracts_fields_and_archive(self) -> None:
        boundary = "----nessustest"
        with tempfile.TemporaryDirectory() as directory:
            upload_dir = Path(directory) / "incoming"
            upload_dir.mkdir()
            spool = Path(directory) / "spool.multipart"
            spool.write_bytes(multipart_body(boundary, b"x" * 10240))
            content_type = f"multipart/form-data; boundary={boundary}"
            with mock.patch.object(manage_api, "UPLOAD_DIR", upload_dir):
                fields, archive, signature = manage_api._parse_multipart_spool(
                    spool, content_type
                )
                self.assertIsNone(signature)
                self.assertEqual(fields.get("force"), "true")
                self.assertEqual(fields.get("plugin_set"), "202609100156")
                self.assertIsNotNone(archive)
                filename, start, end = archive  # type: ignore[misc]
                self.assertEqual(filename, "feed.tar.gz")
                self.assertEqual(end - start, 10240)
                saved = manage_api.save_uploaded_slice(spool, filename, start, end)
                self.assertTrue(saved.is_file())
                self.assertEqual(saved.stat().st_size, 10240)
                self.assertTrue(saved.name.endswith(".tar.gz"))

    def test_validate_update_url_enforces_allowlist(self) -> None:
        source = "https://plugins.nessus.org/v2/nessus.php?f=all-2.0.tar.gz"
        self.assertEqual(manage_api.validate_update_url(source), source)
        self.assertEqual(
            manage_api.validate_update_url("https://downloads.tenable.com/feed"),
            "https://downloads.tenable.com/feed",
        )
        with self.assertRaises(ValueError):
            manage_api.validate_update_url("http://plugins.nessus.org/feed")
        with self.assertRaises(ValueError):
            manage_api.validate_update_url("https://evil.example.com/feed")
        with self.assertRaises(ValueError):
            manage_api.validate_update_url("https://plugins.nessus.org:8443/feed")

    def test_safe_archive_path_confined_to_allowed_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "mnt"
            root.mkdir()
            inside = root / "all-2.0.tar.gz"
            inside.write_bytes(b"x")
            outside = Path(directory) / "outside.tar.gz"
            outside.write_bytes(b"x")
            with mock.patch.object(manage_api, "ALLOWED_ARCHIVE_ROOTS", (root,)):
                self.assertEqual(manage_api.safe_archive_path(str(inside)), inside.resolve())
                self.assertIsNone(manage_api.safe_archive_path(str(outside)))
                self.assertIsNone(
                    manage_api.safe_archive_path(str(root / "missing.tar.gz"))
                )

    def test_validate_plugin_set_requires_twelve_digits(self) -> None:
        self.assertIsNone(manage_api.validate_plugin_set(None))
        self.assertEqual(
            manage_api.validate_plugin_set("202609100156"), "202609100156"
        )
        with self.assertRaises(ValueError):
            manage_api.validate_plugin_set("123")
        with self.assertRaises(ValueError):
            manage_api.validate_plugin_set("20260910015a")

    def test_redact_url_hides_credentials(self) -> None:
        redacted = manage_api.redact_url(
            "https://plugins.nessus.org/x?u=alice&p=secret&f=all"
        )
        self.assertNotIn("alice", redacted or "")
        self.assertNotIn("secret", redacted or "")
        self.assertIn("f=all", redacted or "")

    def test_read_json_rejects_oversized_and_invalid_length(self) -> None:
        handler = object.__new__(manage_api.OperatorHandler)
        handler.headers = {"Content-Length": str(manage_api.MAX_JSON_BODY_BYTES + 1)}
        with self.assertRaises(ValueError):
            handler._read_json()

        handler.headers = {"Content-Length": "not-a-number"}
        with self.assertRaises(ValueError):
            handler._read_json()

    def test_run_update_job_releases_reservation(self) -> None:
        class FakeProc:
            pid = 4242
            returncode = 0

            def communicate(self, timeout=None):  # type: ignore[no-untyped-def]
                return ("done", None)

        with (
            mock.patch.object(manage_api.subprocess, "Popen", return_value=FakeProc()),
            mock.patch.object(manage_api, "write_state"),
            mock.patch.object(manage_api, "read_state", return_value={"state": "running"}),
            mock.patch.object(manage_api, "cleanup_incoming_uploads"),
            mock.patch.object(manage_api, "log"),
            mock.patch.object(manage_api, "release_update_request") as release,
        ):
            manage_api.run_update_job(False, "/tmp/feed.tar.gz", None, "202609100156")

        release.assert_called_once()

    def test_parse_multipart_extracts_archive_and_signature(self) -> None:
        boundary = "----nessussig"
        sig_bytes = b"SIGNATURE" + b"\x00" * 1024
        with tempfile.TemporaryDirectory() as directory:
            upload_dir = Path(directory) / "incoming"
            upload_dir.mkdir()
            spool = Path(directory) / "spool.multipart"
            spool.write_bytes(multipart_body(boundary, b"x" * 10240, signature=sig_bytes))
            content_type = f"multipart/form-data; boundary={boundary}"
            with mock.patch.object(manage_api, "UPLOAD_DIR", upload_dir):
                fields, archive, signature = manage_api._parse_multipart_spool(
                    spool, content_type
                )
                self.assertEqual(fields.get("plugin_set"), "202609100156")
                self.assertIsNotNone(archive)
                self.assertIsNotNone(signature)
                filename, start, end = archive  # type: ignore[misc]
                _name, sig_start, sig_end = signature  # type: ignore[misc]
                saved = manage_api.save_uploaded_slice(spool, filename, start, end)
                saved_sig = manage_api.save_signature_slice(
                    spool, sig_start, sig_end, Path(f"{saved}.sig")
                )
                self.assertEqual(saved_sig, Path(f"{saved}.sig"))
                self.assertEqual(saved_sig.read_bytes(), sig_bytes)

    def test_save_signature_slice_rejects_empty_and_oversized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            spool = Path(directory) / "spool"
            spool.write_bytes(b"abcdef")
            dest = Path(directory) / "out.sig"
            with self.assertRaises(ValueError):
                manage_api.save_signature_slice(spool, 0, 0, dest)
            with mock.patch.object(manage_api, "MAX_SIGNATURE_BYTES", 2):
                with self.assertRaises(ValueError):
                    manage_api.save_signature_slice(spool, 0, 6, dest)


if __name__ == "__main__":
    unittest.main()
