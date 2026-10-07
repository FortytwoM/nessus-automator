#!/usr/bin/env python3
"""Single source of truth for parsing Nessus /server/status payloads.

Used by nessus-status.py (shell-friendly string fields) and manage-api.py
(typed fields) so both interpret the same JSON shapes identically.
"""

from __future__ import annotations

from typing import Any


def _detailed(payload: dict[str, Any]) -> dict[str, Any]:
    detailed = payload.get("detailed_status")
    return detailed if isinstance(detailed, dict) else {}


def _engine(payload: dict[str, Any], detailed: dict[str, Any]) -> dict[str, Any]:
    engine = detailed.get("engine_status")
    if not isinstance(engine, dict):
        engine = payload.get("engine_status")
    return engine if isinstance(engine, dict) else {}


def parse_status(payload: dict[str, Any]) -> dict[str, Any]:
    detailed = _detailed(payload)
    engine = _engine(payload, detailed)
    plugin_set = payload.get("pluginSet", detailed.get("pluginSet"))
    if isinstance(plugin_set, bool):
        plugin_set = None
    return {
        "engine_status": engine.get("status"),
        "engine_progress": engine.get("progress"),
        "plugin_data": payload.get("pluginData", detailed.get("pluginData")),
        "plugin_set": plugin_set,
        "status": payload.get("status", detailed.get("status")),
    }


def scalar(value: Any) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return ""
    return str(value)


def status_fields(payload: dict[str, Any]) -> dict[str, str]:
    """Stable string fields consumed by the shell scripts (nessus-status.py)."""
    parsed = parse_status(payload)
    return {
        "engine_status": scalar(parsed["engine_status"]),
        "engine_progress": scalar(parsed["engine_progress"]),
        "plugin_data": scalar(parsed["plugin_data"]),
        "plugin_set": scalar(parsed["plugin_set"]),
        "status": scalar(parsed["status"]),
    }


def typed_status(payload: dict[str, Any]) -> dict[str, Any]:
    """Typed fields consumed by the Operator API."""
    parsed = parse_status(payload)
    return {
        "engine_status": parsed["engine_status"],
        "engine_progress": parsed["engine_progress"],
        "plugin_data": parsed["plugin_data"] is True,
        "plugin_set": parsed["plugin_set"],
        "nessus_status": parsed["status"],
    }
