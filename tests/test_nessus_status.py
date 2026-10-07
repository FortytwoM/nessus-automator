from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "nessus-status.py"
SPEC = importlib.util.spec_from_file_location("nessus_status", MODULE_PATH)
assert SPEC and SPEC.loader
nessus_status = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = nessus_status
SPEC.loader.exec_module(nessus_status)


class NessusStatusTests(unittest.TestCase):
    def test_nested_status_shape(self) -> None:
        fields = nessus_status.status_fields({
            "detailed_status": {
                "engine_status": {"progress": 100, "status": "ready"}
            },
            "pluginSet": True,
            "pluginData": True,
            "status": "ready",
        })

        self.assertEqual(fields["engine_status"], "ready")
        self.assertEqual(fields["engine_progress"], "100")
        self.assertEqual(fields["plugin_data"], "true")
        self.assertEqual(fields["plugin_set"], "")

    def test_legacy_status_shape(self) -> None:
        fields = nessus_status.status_fields({
            "engine_status": {"progress": 42, "status": "loading"},
            "pluginSet": "202609100156",
            "pluginData": False,
        })

        self.assertEqual(fields["engine_status"], "loading")
        self.assertEqual(fields["engine_progress"], "42")
        self.assertEqual(fields["plugin_data"], "false")
        self.assertEqual(fields["plugin_set"], "202609100156")


if __name__ == "__main__":
    unittest.main()
