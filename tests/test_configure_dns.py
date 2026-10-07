from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).parents[1] / "configure-dns.py"
SPEC = importlib.util.spec_from_file_location("configure_dns", MODULE_PATH)
assert SPEC and SPEC.loader
configure_dns = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = configure_dns
SPEC.loader.exec_module(configure_dns)


class ConfigureDnsTests(unittest.TestCase):
    def test_renders_servers_search_and_preserves_options(self) -> None:
        rendered = configure_dns.render_resolver(
            "nameserver 192.0.2.1\noptions ndots:0\n",
            "10.10.0.53,10.10.0.54",
            "corp.example.internal",
        )

        self.assertEqual(
            rendered,
            (
                "nameserver 10.10.0.53\n"
                "nameserver 10.10.0.54\n"
                "search corp.example.internal\n"
                "options ndots:0\n"
            ),
        )

    def test_rejects_invalid_server_without_replacing_resolver(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid DNS server"):
            configure_dns.render_resolver(
                "nameserver 192.0.2.1\n",
                "10.10.0.53,not-an-ip",
                "corp.example.internal",
            )


if __name__ == "__main__":
    unittest.main()
