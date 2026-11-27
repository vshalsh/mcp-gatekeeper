"""JSON report schema (JSON Schema draft 2020-12) and a tiny stdlib validator.

The validator implements only the keywords this schema uses (type, required,
properties, additionalProperties, items, enum, minimum, const) so that the
report contract can be checked without third-party dependencies.
"""

from __future__ import annotations

from typing import Any

from .models import SEVERITY_LABELS

SCHEMA_VERSION = "1"

_SEVERITY_COUNTS = {
    "type": "object",
    "required": SEVERITY_LABELS,
    "properties": {s: {"type": "integer", "minimum": 0} for s in SEVERITY_LABELS},
    "additionalProperties": False,
}

FINDING_SCHEMA: dict = {
    "type": "object",
    "required": ["rule", "severity", "title", "message", "file", "json_path", "line", "column",
                 "matched_text", "redacted", "server", "tool", "remediation"],
    "properties": {
        "rule": {"type": "string", "enum": ["GK00", "GK01", "GK02", "GK03", "GK04", "GK04R", "GK05", "GK06"]},
        "severity": {"type": "string", "enum": SEVERITY_LABELS},
        "title": {"type": "string"},
        "message": {"type": "string"},
        "file": {"type": "string"},
        "json_path": {"type": "string"},
        "line": {"type": "integer", "minimum": 1},
        "column": {"type": "integer", "minimum": 1},
        "matched_text": {"type": "string"},
        "redacted": {"type": "boolean"},
        "server": {"type": ["string", "null"]},
        "tool": {"type": ["string", "null"]},
        "remediation": {"type": "string"},
    },
    "additionalProperties": False,
}

REPORT_SCHEMA: dict = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "mcp-gatekeeper report",
    "type": "object",
    "required": ["tool", "version", "schema_version", "fail_on", "passed", "exit_code",
                 "scanned_files", "skipped_files", "errors", "summary", "findings"],
    "properties": {
        "tool": {"const": "mcp-gatekeeper"},
        "version": {"type": "string"},
        "schema_version": {"const": SCHEMA_VERSION},
        "fail_on": {"type": "string", "enum": SEVERITY_LABELS + ["none"]},
        "passed": {"type": "boolean"},
        "exit_code": {"type": "integer", "enum": [0, 1, 2]},
        "scanned_files": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file", "kind", "flavor", "servers", "tools", "findings"],
                "properties": {
                    "file": {"type": "string"},
                    "kind": {"type": "string", "enum": ["client_config", "tool_manifest"]},
                    "flavor": {"type": "string", "enum": ["claude_desktop", "mcp_json", "mcp_servers",
                                                          "vscode_settings", "vscode_mcp", "tool_manifest"]},
                    "servers": {"type": "integer", "minimum": 0},
                    "tools": {"type": "integer", "minimum": 0},
                    "findings": {"type": "integer", "minimum": 0},
                },
                "additionalProperties": False,
            },
        },
        "skipped_files": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file", "reason"],
                "properties": {"file": {"type": "string"}, "reason": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        "errors": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["file", "message"],
                "properties": {"file": {"type": "string"}, "message": {"type": "string"}},
                "additionalProperties": False,
            },
        },
        "summary": {
            "type": "object",
            "required": ["total", "by_severity", "by_rule"],
            "properties": {
                "total": {"type": "integer", "minimum": 0},
                "by_severity": _SEVERITY_COUNTS,
                "by_rule": {"type": "object"},
            },
            "additionalProperties": False,
        },
        "findings": {"type": "array", "items": FINDING_SCHEMA},
    },
    "additionalProperties": False,
}

_TYPES = {
    "object": dict, "array": list, "string": str, "boolean": bool, "null": type(None),
}


def _type_ok(value: Any, t: str) -> bool:
    if t == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if t == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    return isinstance(value, _TYPES[t])


def validate(instance: Any, schema: dict = REPORT_SCHEMA, path: str = "$") -> list[str]:
    """Return a list of human-readable violations (empty means valid)."""
    errs: list[str] = []
    if "const" in schema and instance != schema["const"]:
        errs.append(f"{path}: expected {schema['const']!r}, got {instance!r}")
    if "type" in schema:
        types = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(_type_ok(instance, t) for t in types):
            return errs + [f"{path}: expected type {'/'.join(types)}, got {type(instance).__name__}"]
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{path}: {instance!r} not in {schema['enum']!r}")
    if "minimum" in schema and isinstance(instance, (int, float)) and instance < schema["minimum"]:
        errs.append(f"{path}: {instance} < minimum {schema['minimum']}")
    if isinstance(instance, dict):
        for key in schema.get("required", []):
            if key not in instance:
                errs.append(f"{path}: missing required key {key!r}")
        props = schema.get("properties", {})
        for key, val in instance.items():
            if key in props:
                errs.extend(validate(val, props[key], f"{path}.{key}"))
            elif schema.get("additionalProperties") is False:
                errs.append(f"{path}: unexpected key {key!r}")
    if isinstance(instance, list) and "items" in schema:
        for i, val in enumerate(instance):
            errs.extend(validate(val, schema["items"], f"{path}[{i}]"))
    return errs
