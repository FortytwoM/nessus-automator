#!/usr/bin/env python3
"""Shared URL policy helpers: host allowlist matching and credential redaction.

Imported by secure-download.py and manage-api.py so both apply the same rules.
"""

from __future__ import annotations

import fnmatch
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

REDACTED_QUERY_KEYS = {"u", "p", "user", "username", "password", "token", "key"}


def host_allowed(host: str, patterns: set[str]) -> bool:
    host = host.lower().rstrip(".")
    for pattern in patterns:
        pattern = pattern.rstrip(".")
        if pattern.startswith("*."):
            suffix = pattern[1:]
            if host.endswith(suffix) and host != suffix[1:]:
                return True
        elif fnmatch.fnmatchcase(host, pattern):
            return True
    return False


def redact_url(value: str | None) -> str | None:
    if not value:
        return value
    parsed = urlparse(value)
    if not parsed.scheme or not parsed.netloc:
        return value

    redacted_query = [
        (key, "***" if key.lower() in REDACTED_QUERY_KEYS else item)
        for key, item in parse_qsl(parsed.query, keep_blank_values=True)
    ]
    return urlunparse(parsed._replace(query=urlencode(redacted_query)))
