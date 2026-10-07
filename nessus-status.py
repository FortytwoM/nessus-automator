#!/usr/bin/env python3
"""Parse Nessus /server/status JSON into stable shell-friendly fields."""

from __future__ import annotations

import argparse
import json
import os
import sys

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

from nessus_status_lib import status_fields  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--field",
        choices=("engine_status", "engine_progress", "plugin_data", "plugin_set", "status"),
    )
    args = parser.parse_args()
    try:
        payload = json.load(sys.stdin)
        if not isinstance(payload, dict):
            raise ValueError("status response must be a JSON object")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"nessus-status: {exc}", file=sys.stderr)
        return 1

    fields = status_fields(payload)
    if args.field:
        print(fields[args.field])
    else:
        print("\t".join(fields[name] for name in (
            "engine_status",
            "engine_progress",
            "plugin_data",
            "plugin_set",
            "status",
        )))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
