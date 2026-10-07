#!/usr/bin/env python3
"""Validate and render the resolver configuration used by Nessus."""

from __future__ import annotations

import argparse
import ipaddress
import re
from pathlib import Path


DOMAIN_RE = re.compile(
    r"^(?=.{1,253}\.?$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.?$"
)


def render_resolver(current: str, raw_servers: str, raw_search: str) -> str:
    current_lines = current.splitlines()
    server_parts = [item.strip() for item in raw_servers.split(",")]
    if raw_servers and any(not item for item in server_parts):
        raise ValueError("DNS server list contains an empty address")
    servers = server_parts if raw_servers else [
        line.split(None, 1)[1]
        for line in current_lines
        if line.strip().startswith("nameserver ") and len(line.split(None, 1)) == 2
    ]
    if not 1 <= len(servers) <= 3:
        raise ValueError("DNS server list must contain 1-3 addresses")
    for server in servers:
        try:
            ipaddress.ip_address(server)
        except ValueError as exc:
            raise ValueError(f"invalid DNS server address '{server}': {exc}") from exc

    domains = [item for item in re.split(r"[\s,]+", raw_search.strip()) if item]
    if len(domains) > 6 or len(" ".join(domains)) > 256:
        raise ValueError("DNS search list exceeds resolver limits")
    for domain in domains:
        if not DOMAIN_RE.fullmatch(domain):
            raise ValueError(f"invalid DNS search domain '{domain}'")

    lines = [f"nameserver {server}" for server in servers]
    if domains:
        lines.append("search " + " ".join(domains))
    lines.extend(
        line for line in current_lines if line.strip().startswith("options ")
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--servers", default="")
    parser.add_argument("--search", default="")
    args = parser.parse_args()
    try:
        rendered = render_resolver(
            args.source.read_text(encoding="utf-8", errors="replace"),
            args.servers,
            args.search,
        )
    except (OSError, ValueError) as exc:
        parser.exit(1, f"configure-dns: {exc}\n")
    args.output.write_text(rendered, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
