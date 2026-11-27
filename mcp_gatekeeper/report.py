"""Reporting: scan orchestration result -> JSON document or terminal text."""

from __future__ import annotations

import json
import os
import unicodedata
from dataclasses import dataclass, field
from typing import Optional, TextIO

from . import __version__
from .models import SEVERITY_LABELS, Finding, Severity, SourceDoc, redact
from .schema import SCHEMA_VERSION

EXIT_OK, EXIT_FINDINGS, EXIT_ERROR = 0, 1, 2


@dataclass
class ScanResult:
    docs: list[SourceDoc]
    findings: list[Finding]
    errors: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)
    fail_on: Optional[Severity] = Severity.HIGH  # None means never fail on findings

    @property
    def failing(self) -> list[Finding]:
        if self.fail_on is None:
            return []
        return [f for f in self.findings if f.severity >= self.fail_on]

    @property
    def exit_code(self) -> int:
        # An incomplete scan (unreadable input, or nothing scannable) cannot vouch
        # for anything, so it outranks findings.
        if self.errors or not self.docs:
            return EXIT_ERROR
        return EXIT_FINDINGS if self.failing else EXIT_OK


def counts(findings: list[Finding]) -> dict[str, int]:
    out = {s: 0 for s in SEVERITY_LABELS}
    for f in findings:
        out[f.severity.label] += 1
    return out


def to_report(result: ScanResult, redact_secrets: bool = False) -> dict:
    by_rule: dict[str, int] = {}
    for f in result.findings:
        by_rule[f.rule] = by_rule.get(f.rule, 0) + 1
    per_file: dict[str, int] = {}
    for f in result.findings:
        per_file[f.file] = per_file.get(f.file, 0) + 1
    findings = []
    for f in result.findings:
        d = f.to_dict()
        if redact_secrets and f.sensitive:
            d["matched_text"] = redact(f.matched_text)
            d["redacted"] = True
        findings.append(d)
    return {
        "tool": "mcp-gatekeeper",
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "fail_on": result.fail_on.label if result.fail_on is not None else "none",
        "passed": result.exit_code == EXIT_OK,
        "exit_code": result.exit_code,
        "scanned_files": [
            {"file": d.path, "kind": d.kind, "flavor": d.flavor, "servers": len(d.servers),
             "tools": len(d.tools), "findings": per_file.get(d.path, 0)}
            for d in result.docs
        ],
        "skipped_files": list(result.skipped),
        "errors": list(result.errors),
        "summary": {
            "total": len(result.findings),
            "by_severity": counts(result.findings),
            "by_rule": dict(sorted(by_rule.items())),
        },
        "findings": findings,
    }


def render_json(result: ScanResult, out: TextIO, redact_secrets: bool = False) -> None:
    json.dump(to_report(result, redact_secrets), out, indent=2, ensure_ascii=True)
    out.write("\n")


# ---------------------------------------------------------------------------
# Text
# ---------------------------------------------------------------------------

_SEV_COLOR = {
    Severity.CRITICAL: "1;31",
    Severity.HIGH: "33",
    Severity.MEDIUM: "33",
    Severity.LOW: "32",
    Severity.INFO: "32",
}


def use_color(mode: str, stream: TextIO) -> bool:
    if mode == "never":
        return False
    if mode == "always":
        return True
    if os.environ.get("NO_COLOR"):
        return False
    isatty = getattr(stream, "isatty", None)
    return bool(isatty and isatty())


def printable(text: str, limit: int = 160) -> str:
    """Escape invisible / control characters so they are visible in a terminal."""
    out = []
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in ("Cc", "Cf", "Co", "Cn", "Zl", "Zp") or ch == "­":
            o = ord(ch)
            out.append(f"\\u{o:04x}" if o <= 0xFFFF else f"\\U{o:08x}")
        else:
            out.append(ch)
    s = "".join(out)
    return s if len(s) <= limit else s[: limit - 3] + "..."


def render_text(result: ScanResult, out: TextIO, color: bool = False) -> None:
    def paint(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if color else s

    dim = lambda s: paint("2", s)  # noqa: E731
    configs = sum(1 for d in result.docs if d.kind == "client_config")
    manifests = len(result.docs) - configs
    out.write(f"mcp-gatekeeper {__version__}: scanned {len(result.docs)} file(s) "
              f"({configs} client config(s), {manifests} tool manifest(s))\n")

    by_file: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_file.setdefault(f.file, []).append(f)

    for d in result.docs:
        items = by_file.get(d.path, [])
        size = f"{len(d.servers)} server(s)" if d.kind == "client_config" else f"{len(d.tools)} tool(s)"
        out.write(f"\n{d.path}  [{d.flavor}, {size}]\n")
        if not items:
            out.write(f"  {paint(_SEV_COLOR[Severity.INFO], 'PASS')}  no findings\n")
            continue
        for f in items:
            sev = f.severity.name.ljust(8)
            who = f"server={f.server}" if f.server else (f"tool={f.tool}" if f.tool else "")
            out.write(f"  {paint(_SEV_COLOR[f.severity], sev)}  {f.rule}  {f.title}"
                      f"{'  ' + dim(who) if who else ''}\n")
            out.write(f"            {f.message}\n")
            out.write(dim(f"            at {f.file}:{f.line}:{f.column}  {f.json_path}") + "\n")
            shown = redact(f.matched_text) if f.sensitive else f.matched_text
            out.write(dim(f"            matched: {printable(shown)}") + "\n")
            out.write(dim(f"            fix: {f.remediation}") + "\n")

    for s in result.skipped:
        out.write(dim(f"\nskipped {s['file']}: {s['reason']}") + "\n")
    for e in result.errors:
        out.write(f"\n{paint('1;31', 'ERROR')}  {e['file']}: {e['message']}\n")
    if not result.docs and not result.errors:
        out.write(f"\n{paint('1;31', 'ERROR')}  no MCP client config or tool manifest found\n")

    c = counts(result.findings)
    parts = ", ".join(f"{c[s]} {s}" for s in reversed(SEVERITY_LABELS))
    code = result.exit_code
    verdict = {EXIT_OK: ("PASS", _SEV_COLOR[Severity.INFO]), EXIT_FINDINGS: ("FAIL", "1;31"),
               EXIT_ERROR: ("ERROR", "1;31")}[code]
    threshold = result.fail_on.label if result.fail_on is not None else "none"
    out.write(f"\n{paint(verdict[1], verdict[0])}  {len(result.findings)} finding(s): {parts}  "
              f"(fail-on: {threshold}, exit {code})\n")
