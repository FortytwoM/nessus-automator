from __future__ import annotations

import importlib.util
import os
import sys
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).parents[1] / "nessusctl.py"
SPEC = importlib.util.spec_from_file_location("nessusctl", MODULE_PATH)
assert SPEC and SPEC.loader
nessusctl = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = nessusctl
SPEC.loader.exec_module(nessusctl)


class NessusCtlTests(unittest.TestCase):
    def test_update_arguments(self) -> None:
        args = nessusctl.build_parser().parse_args([
            "update",
            "--force",
            "--plugin-set",
            "202609100156",
            "/tmp/all-2.0.tar.gz",
        ])

        self.assertEqual(args.command, "update")
        self.assertTrue(args.force)
        self.assertEqual(args.plugin_set, "202609100156")
        self.assertEqual(args.source, "/tmp/all-2.0.tar.gz")

    def test_restore_requires_confirmation_flag_in_command_model(self) -> None:
        args = nessusctl.build_parser().parse_args([
            "restore",
            "backup.tar.gz",
        ])

        self.assertFalse(args.yes)

    def test_start_dispatches_compose(self) -> None:
        with mock.patch.object(nessusctl, "compose", return_value=0) as compose:
            with mock.patch.object(sys, "argv", ["nessusctl", "start"]):
                self.assertEqual(nessusctl.main(), 0)
        compose.assert_called_once_with("up", "-d")

    def test_restore_without_yes_exits(self) -> None:
        with mock.patch.object(sys, "argv", ["nessusctl", "restore", "backup.tar.gz"]):
            with self.assertRaises(SystemExit) as raised:
                nessusctl.main()
        self.assertEqual(str(raised.exception), "restore requires --yes")

    def test_backup_dispatches_maintenance_script(self) -> None:
        with mock.patch.object(nessusctl, "maintenance_script", return_value=0) as script:
            with mock.patch.object(sys, "argv", ["nessusctl", "backup", "C:/backups"]):
                self.assertEqual(nessusctl.main(), 0)
        script.assert_called_once_with("backup.sh", "C:/backups")

    def test_compose_command_adds_desktop_overlay_when_forced(self) -> None:
        nessusctl.using_desktop_compose.cache_clear()
        with mock.patch.dict(os.environ, {"NESSUS_COMPOSE_DESKTOP": "1"}):
            nessusctl.using_desktop_compose.cache_clear()
            self.assertEqual(
                nessusctl.compose_command("up", "-d"),
                [
                    "docker",
                    "compose",
                    "-f",
                    "docker-compose.yml",
                    "-f",
                    "docker-compose.desktop.yml",
                    "up",
                    "-d",
                ],
            )

    def test_compose_command_without_desktop_overlay(self) -> None:
        nessusctl.using_desktop_compose.cache_clear()
        with mock.patch.dict(os.environ, {"NESSUS_COMPOSE_DESKTOP": "0"}):
            nessusctl.using_desktop_compose.cache_clear()
            self.assertEqual(
                nessusctl.compose_command("up", "-d"),
                ["docker", "compose", "-f", "docker-compose.yml", "up", "-d"],
            )

    def test_windows_bash_candidates_include_local_appdata(self) -> None:
        candidates = nessusctl.windows_bash_candidates(
            {"ProgramFiles": r"C:\Program Files", "LOCALAPPDATA": r"C:\Users\me\AppData\Local"}
        )

        self.assertEqual(
            candidates[0],
            r"C:\Program Files\Git\bin\bash.exe",
        )
        self.assertEqual(
            candidates[-1],
            r"C:\Users\me\AppData\Local\Programs\Git\bin\bash.exe",
        )

    def test_windows_bash_candidates_skip_empty_local_appdata(self) -> None:
        candidates = nessusctl.windows_bash_candidates({"ProgramFiles": r"C:\Program Files"})

        self.assertEqual(len(candidates), 3)

    def test_find_bash_prefers_git_bash_on_windows(self) -> None:
        git_bash = r"C:\Program Files\Git\bin\bash.exe"

        result = nessusctl.find_bash(
            os_name="nt",
            environment={"ProgramFiles": r"C:\Program Files"},
            path_exists=lambda path: path == git_bash,
            which=lambda _name: None,
        )

        self.assertEqual(result, git_bash)

    def test_find_bash_rejects_wsl_bash_on_windows(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            nessusctl.find_bash(
                os_name="nt",
                environment={},
                path_exists=lambda _path: False,
                which=lambda _name: r"C:\Windows\System32\bash.exe",
            )

        self.assertIn("Git Bash", str(raised.exception))

    def test_find_bash_requires_bash_on_linux(self) -> None:
        with self.assertRaises(SystemExit) as raised:
            nessusctl.find_bash(
                os_name="posix",
                environment={},
                path_exists=lambda _path: False,
                which=lambda _name: None,
            )

        self.assertIn("bash is required", str(raised.exception))

    def test_find_bash_accepts_plain_bash_on_linux(self) -> None:
        result = nessusctl.find_bash(
            os_name="posix",
            environment={},
            path_exists=lambda _path: False,
            which=lambda _name: "/usr/bin/bash",
        )

        self.assertEqual(result, "/usr/bin/bash")


if __name__ == "__main__":
    unittest.main()
