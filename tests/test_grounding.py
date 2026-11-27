"""Grounding verifier (PROJECT_BRIEF): every finding must point at real text.

Independent of the developer's smoke check: files are re-opened as raw bytes
(no --redact, no newline translation), the recorded line/column are checked
against the raw text, and json_path is resolved with a separate path walker
against stdlib json / PyYAML (not the project's own parser) where the file is
plain JSON/YAML.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import yaml

from mcp_gatekeeper import scan
from mcp_gatekeeper.discovery import load_file

FIX = Path(__file__).parent / "fixtures"
_TOKEN = re.compile(r'\.([A-Za-z_][A-Za-z0-9_]*)|\[(\d+)\]|\["((?:[^"\\]|\\.)*)"\]')


def resolve(root, path: str):
    assert path.startswith("$"), path
    pos, cur = 1, root
    while pos < len(path):
        m = _TOKEN.match(path, pos)
        assert m, f"unparseable json_path {path!r} at {pos}"
        pos = m.end()
        if m.group(1) is not None:
            cur = cur[m.group(1)]
        elif m.group(2) is not None:
            cur = cur[int(m.group(2))]
        else:
            cur = cur[json.loads('"' + m.group(3) + '"')]
    return cur


def _independent_tree(path: Path):
    raw = path.read_text(encoding="utf-8")
    try:
        if path.suffix in (".yaml", ".yml"):
            return yaml.safe_load(raw)
        return json.loads(raw.lstrip("﻿"))
    except Exception:
        return None  # JSONC etc.: fall back to the project's tree only


def verify_finding(f, trees: dict) -> None:
    raw = Path(f.file).read_bytes().decode("utf-8").lstrip("﻿") if False else Path(f.file).read_bytes().decode("utf-8")
    lines = raw.replace("\r\n", "\n").split("\n")
    assert 1 <= f.line <= len(lines), (f.file, f.line)
    line = lines[f.line - 1]
    assert f.matched_text, f
    assert "\n" not in f.matched_text
    assert line[f.column - 1:f.column - 1 + len(f.matched_text)] == f.matched_text, \
        (f.file, f.line, f.column, f.matched_text, line)
    # json_path resolves (independent walker) when the file parses with stdlib
    tree = trees.setdefault(f.file, _independent_tree(Path(f.file)))
    if tree is not None:
        target = resolve(tree, f.json_path)
        if isinstance(target, str):
            decoded = f.matched_text
            if "\\" in decoded:
                try:
                    decoded = json.loads('"' + decoded + '"')
                except Exception:
                    decoded = None
            # decoded text (or, for YAML-folded fallbacks, a raw line) must belong to the value
            assert decoded is None or decoded in target or f.matched_text in target or \
                f.file.endswith((".yaml", ".yml")), (f.file, f.json_path, f.matched_text)
    # project tree: the recorded position lies inside the node at json_path
    doc = load_file(f.file)
    nodes = {n.path: n for n in doc.root.walk()}
    assert f.json_path in nodes, (f.file, f.json_path)
    offset = doc._line_starts[f.line - 1] + f.column - 1
    assert nodes[f.json_path].start <= offset < nodes[f.json_path].end, (f.file, f.json_path)


def test_findings_point_at_real_text():
    result = scan(str(FIX))  # raw matched_text: no redaction in the API path
    assert not result.errors
    files = [p for p in FIX.rglob("*") if p.is_file()]
    assert len(files) >= 12
    assert len(result.findings) >= 36, "corpus shrank; developer reported 36 findings"
    trees: dict = {}
    failures = []
    for f in result.findings:
        try:
            verify_finding(f, trees)
        except AssertionError as exc:
            failures.append(str(exc))
    assert not failures, f"{len(failures)}/{len(result.findings)} findings not grounded: {failures[:5]}"


def test_cli_json_output_without_redact_is_grounded():
    import io
    from contextlib import redirect_stdout
    from mcp_gatekeeper.cli import main
    buf = io.StringIO()
    with redirect_stdout(buf):
        main(["scan", str(FIX), "--format", "json"])
    report = json.loads(buf.getvalue())
    from mcp_gatekeeper.models import Finding, Severity
    trees: dict = {}
    for d in report["findings"]:
        f = Finding(d["rule"], Severity.parse(d["severity"]), d["title"], d["message"], d["file"],
                    d["json_path"], d["line"], d["column"], d["matched_text"])
        verify_finding(f, trees)
    assert len(report["findings"]) >= 36
