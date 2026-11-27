"""Smoke tests: prove the L-001 handover runs end to end.

The full system-test and grounding suite is owned by the test seat; these
tests only show that each rule fires, clean inputs stay silent, the JSON
contract holds, exit codes are right and provenance points at real text.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

from mcp_gatekeeper import scan
from mcp_gatekeeper.cli import main
from mcp_gatekeeper.discovery import load_file
from mcp_gatekeeper.schema import validate

FIX = Path(__file__).parent / "fixtures"

POSITIVE = [
    ("GK01", "gk01_unpinned_npx.json"),
    ("GK02", "gk02_inline_secret.json"),
    ("GK03", "gk03_http_transport.json"),
    ("GK04", "gk04_injection_manifest.json"),
    ("GK04", "gk04_injection_manifest.yaml"),
    ("GK04", "manifest_injection.json"),
    ("GK05", "gk05_overprivileged_config.json"),
    ("GK05", "gk05_overprivileged_tools.json"),
    ("GK06", "gk06_suspicious_launch.json"),
]
CLEAN = ["clean_config.json", "manifest_clean.json", "manifest_clean.yaml"]


def run_cli(*args: str) -> tuple[int, str]:
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


def test_fixture_corpus_size():
    files = [p for p in FIX.rglob("*") if p.is_file()]
    assert len(files) >= 12


@pytest.mark.parametrize("rule_id,fixture", POSITIVE)
def test_rule_fires_on_positive_fixture(rule_id, fixture):
    result = scan(str(FIX / fixture))
    assert not result.errors
    assert rule_id in {f.rule for f in result.findings}, f"{rule_id} did not fire on {fixture}"


@pytest.mark.parametrize("fixture", CLEAN)
def test_clean_fixture_is_silent(fixture):
    result = scan(str(FIX / fixture))
    assert len(result.docs) == 1 and not result.errors
    assert result.findings == []
    assert result.exit_code == 0


def test_zero_width_and_bidi_detected():
    result = scan(str(FIX / "manifest_injection.json"))
    messages = " ".join(f.message for f in result.findings)
    assert "U+200B" in messages
    assert "U+202E" in messages
    assert "send keys" in messages  # decoded Unicode tag-character payload


@pytest.mark.parametrize("path,flavor", [
    ("realistic/claude_desktop_config.json", "claude_desktop"),
    ("project/.mcp.json", "mcp_json"),
    ("vscode/settings.json", "vscode_settings"),
    ("manifest_injection.json", "tool_manifest"),
])
def test_config_flavours_are_recognised(path, flavor):
    result = scan(str(FIX / path))
    assert [d.flavor for d in result.docs] == [flavor]
    assert result.findings, "realistic fixtures are expected to carry findings"


def test_json_output_parses_and_matches_schema():
    code, out = run_cli("scan", str(FIX), "--format", "json")
    report = json.loads(out)
    assert validate(report) == []
    assert report["exit_code"] == code == 1
    assert report["summary"]["total"] == len(report["findings"]) > 0
    assert {f["rule"] for f in report["findings"]} >= {"GK01", "GK02", "GK03", "GK04", "GK05", "GK06"}


def test_json_output_for_clean_input():
    code, out = run_cli("scan", str(FIX / "clean_config.json"), "--format", "json")
    report = json.loads(out)
    assert validate(report) == []
    assert code == 0 and report["passed"] is True and report["findings"] == []


def test_every_finding_points_at_real_text():
    """Re-open each flagged file and confirm matched_text sits at line:column."""
    result = scan(str(FIX))
    assert result.findings
    for f in result.findings:
        with open(f.file, encoding="utf-8") as fh:
            lines = fh.read().split("\n")
        line = lines[f.line - 1]
        assert f.matched_text, f
        assert line[f.column - 1:].startswith(f.matched_text), (f.file, f.line, f.column, f.matched_text)
        # json_path must resolve to a value whose raw span contains the match.
        doc = load_file(f.file)
        nodes = {n.path: n for n in doc.root.walk()}
        assert f.json_path in nodes, f.json_path
        node = nodes[f.json_path]
        offset = doc._line_starts[f.line - 1] + f.column - 1
        assert node.start <= offset < node.end, (f.json_path, offset)


@pytest.mark.parametrize("args,expected", [
    (["scan", str(FIX / "clean_config.json")], 0),
    (["scan", str(FIX / "gk01_unpinned_npx.json")], 1),
    (["scan", str(FIX / "gk01_unpinned_npx.json"), "--fail-on", "critical"], 0),
    (["scan", str(FIX / "gk02_inline_secret.json"), "--fail-on", "critical"], 1),
    (["scan", str(FIX / "gk06_suspicious_launch.json"), "--fail-on", "none"], 0),
    (["scan", str(FIX / "does-not-exist.json")], 2),
])
def test_exit_codes(args, expected):
    code, _ = run_cli(*args)
    assert code == expected


def test_unparseable_file_exits_2(tmp_path):
    bad = tmp_path / "claude_desktop_config.json"
    bad.write_text('{"mcpServers": {"x": ', encoding="utf-8")
    code, out = run_cli("scan", str(bad), "--format", "json")
    assert code == 2
    assert json.loads(out)["errors"]


def test_empty_directory_exits_2(tmp_path):
    code, _ = run_cli("scan", str(tmp_path))
    assert code == 2


def test_text_output_severity_words_and_no_colour_when_piped():
    code, out = run_cli("scan", str(FIX / "gk02_inline_secret.json"))
    assert code == 1
    assert "CRITICAL" in out and "GK02" in out
    assert "\033[" not in out
    assert "FAKEFAKE" not in out  # secrets are masked in text output


def test_colour_forced_and_no_color_env(monkeypatch):
    _, out = run_cli("scan", str(FIX / "gk02_inline_secret.json"), "--color", "always")
    assert "\033[" in out
    from mcp_gatekeeper.report import use_color

    class Tty(io.StringIO):
        def isatty(self):
            return True

    monkeypatch.setenv("NO_COLOR", "1")
    assert use_color("auto", Tty()) is False
    monkeypatch.delenv("NO_COLOR")
    assert use_color("auto", Tty()) is True


def test_redact_flag_masks_json():
    _, out = run_cli("scan", str(FIX / "gk02_inline_secret.json"), "--format", "json", "--redact")
    report = json.loads(out)
    assert validate(report) == []
    assert all(f["redacted"] for f in report["findings"])
    assert "FAKEFAKE" not in out


def test_console_module_runs():
    env = dict(os.environ, NO_COLOR="1")
    proc = subprocess.run([sys.executable, "-m", "mcp_gatekeeper", "scan",
                           str(FIX / "realistic" / "claude_desktop_config.json")],
                          capture_output=True, text=True, env=env)
    assert proc.returncode == 1
    assert "GK01" in proc.stdout and "GK02" in proc.stdout and "GK03" in proc.stdout
