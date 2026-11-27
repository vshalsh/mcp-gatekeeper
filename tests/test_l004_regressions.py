"""L-004 regressions: detection hardening from the black-box round.

Sev-1 repros live as fixtures under tests/fixtures/ (so the grounding verifier
covers them too); Sev-2/3 cases are built in tmp_path.
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
from mcp_gatekeeper.schema import validate

FIX = Path(__file__).parent / "fixtures"
BB = FIX / "blackbox"
ENV = dict(os.environ, NO_COLOR="1")


def cli(*args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


def sub(*args, **kw):
    return subprocess.run([sys.executable, "-m", "mcp_gatekeeper", *args], capture_output=True, text=True,
                          env=ENV, timeout=30, **kw)


def grounded(path, f):
    lines = Path(path).read_text(encoding="utf-8").split("\n")
    return lines[f.line - 1][f.column - 1:].startswith(f.matched_text)


def by_tool(path):
    res = scan(str(path))
    assert not res.errors
    hits: dict = {}
    for f in res.findings:
        hits.setdefault(f.tool, set()).add(f.rule)
    return res, hits


def cfg(tmp_path, servers, name=".mcp.json"):
    p = tmp_path / name
    p.write_text(json.dumps({"mcpServers": servers}))
    return p


# ---- Sev-1 #1: literal home directories (GK05) ---------------------------

def test_sev1_home_directories_fire():
    res = scan(str(FIX / "gk05_home_directories.json"))
    flagged = {f.server for f in res.findings if f.rule == "GK05"}
    assert flagged == {"files-mac", "files-linux", "files-windows", "files-root"}
    assert all(f.severity.label == "medium" for f in res.findings if f.rule == "GK05")


@pytest.mark.parametrize("path", ["/Users/alex/projects", "/home/priya/code/site", "/Users/Shared",
                                  "C:\\Users\\Public", "/srv/data"])
def test_scoped_directories_stay_silent(tmp_path, path):
    res = scan(str(cfg(tmp_path, {"fs": {"command": "/usr/local/bin/fs", "args": [path]}})))
    assert not [f for f in res.findings if f.rule == "GK05"], path


# ---- Sev-1 #2: MCP config files as sensitive references (GK04) -----------

def test_sev1_mcp_config_references_fire():
    _res, hits = by_tool(FIX / "gk04_mcp_config_reference.json")
    assert {"sync_notes", "sync_settings", "backup_project"} <= {t for t, r in hits.items() if "GK04" in r}


# ---- Sev-1 #3: obfuscation bypasses (GK04 / GK04R) -----------------------

OBFUSCATED = ["format_text", "search_docs_spaced", "search_docs_dotted", "homoglyph_override",
              "fullwidth_override", "leet_override", "concealment_paraphrase", "override_paraphrase",
              "notes_summarize"]


@pytest.mark.parametrize("manifest", ["manifest_obfuscation.json", "manifest_obfuscation_escaped.json"])
def test_sev1_obfuscation_corpus_never_silent(manifest):
    res, hits = by_tool(BB / manifest)
    names = [t.name for d in res.docs for t in d.tools]
    silent = [n for n in names if n not in hits and n != "fetch_remote_data"]
    assert not silent, f"silent on: {silent}"
    assert "fetch_remote_data" not in hits  # negative control stays clean
    for n in OBFUSCATED:
        assert hits[n] & {"GK04", "GK04R"}, n
    assert all(grounded(BB / manifest, f) for f in res.findings)


def test_sev1_slip_only_all_caught():
    res, hits = by_tool(BB / "manifest_slip_only.json")
    assert set(hits) == {t.name for d in res.docs for t in d.tools}


def test_fuzzy_matches_are_medium_review():
    res = scan(str(BB / "manifest_obfuscation.json"))
    fuzzy = [f for f in res.findings if f.rule == "GK04R"]
    assert fuzzy and all(f.severity.label == "medium" for f in fuzzy)


def test_base64_payload_decoded_and_reported_high():
    res = scan(str(BB / "manifest_slip_only.json"))
    b64 = [f for f in res.findings if f.tool == "format_text"]
    assert b64 and b64[0].rule == "GK04" and b64[0].severity.label == "high"
    assert "decodes to injection text" in b64[0].message


@pytest.mark.parametrize("desc", [
    "Returns the current weather for a city.",
    "Lists the 10 most recent issues (max 100).",
    "Computes sha256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 of a file.",
    "Sends a password reset link to the given address.",
    "Formats a d.a.t.e string.",
])
def test_benign_descriptions_stay_clean(tmp_path, desc):
    p = tmp_path / "m.json"
    p.write_text(json.dumps({"tools": [{"name": "t", "description": desc}]}))
    assert scan(str(p)).findings == [], desc


# ---- Sev-2 #4: malformed entries fail closed (GK00, exit 2) --------------

@pytest.mark.parametrize("server", [
    {"command": ["npx", "-y", "pkg"]},
    {"command": 42},
    {"command": "npx", "args": "-y pkg"},
    {"command": "node", "args": ["/opt/s.js"], "env": ["GITHUB_TOKEN=" + "ghp_" + "FAKE" * 8 + "0000"]},
    "npx -y evil",
])
def test_malformed_entry_is_unverifiable(tmp_path, server):
    p = cfg(tmp_path, {"s": server})
    code, out = cli("scan", str(p), "--format", "json")
    rep = json.loads(out)
    assert code == 2 and rep["exit_code"] == 2 and validate(rep) == []
    assert any(f["rule"] == "GK00" and f["severity"] == "high" for f in rep["findings"])
    assert rep["errors"] and "unexpected shape" in rep["errors"][0]["message"]
    res = scan(str(p))
    assert all(grounded(p, f) for f in res.findings)


def test_token_inside_env_array_still_reported(tmp_path):
    p = cfg(tmp_path, {"s": {"command": "node", "env": ["T=" + "ghp_" + "FAKE" * 8 + "0000"]}})
    assert any(f.rule == "GK02" and f.severity.label == "critical" for f in scan(str(p)).findings)


def test_server_list_not_an_object(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text('{"mcpServers": ["x"]}')
    res = scan(str(p))
    assert res.exit_code == 2 and any(f.rule == "GK00" for f in res.findings)


def test_numeric_env_value_is_fine(tmp_path):
    p = cfg(tmp_path, {"s": {"command": "/usr/bin/srv", "env": {"PORT": 8080}}})
    res = scan(str(p))
    assert res.exit_code == 0 and res.findings == []


# ---- Sev-2 #5: shell wrappers are looked inside -------------------------

def test_shell_wrapper_unpinned_fixture():
    res = scan(str(FIX / "gk01_shell_wrapper.json"))
    assert any(f.rule == "GK01" and "shell wrapper" in f.message for f in res.findings)
    assert res.exit_code == 1


def test_shell_wrapper_secret_root_and_http(tmp_path):
    script = "API_TOKEN=Zx9Kq2Lm8Rt4Vw7Yb3Nc npx -y @x/srv@latest / && npx mcp-remote@1.0.0 http://mcp.vendor.example.com/sse"
    p = cfg(tmp_path, {"s": {"command": "sh", "args": ["-c", script]}})
    res = scan(str(p))
    rules = {f.rule for f in res.findings}
    assert {"GK01", "GK02", "GK03", "GK05", "GK06"} <= rules
    assert all(grounded(p, f) for f in res.findings)
    assert len([f for f in res.findings if f.rule == "GK03"]) == 1  # no duplicate for the same span


def test_powershell_encoded_command_decoded(tmp_path):
    import base64
    enc = base64.b64encode("npx -y evil-pkg".encode("utf-16-le")).decode()
    p = cfg(tmp_path, {"s": {"command": "powershell", "args": ["-EncodedCommand", enc]}})
    res = scan(str(p))
    gk01 = [f for f in res.findings if f.rule == "GK01"]
    assert gk01 and gk01[0].matched_text == enc and "EncodedCommand" in gk01[0].message


# ---- Sev-3/4 hygiene ----------------------------------------------------

@pytest.mark.parametrize("host", ["wiki.acme-corp.internal", "nas.local", "build.corp", "intranet"])
def test_internal_hostnames_are_medium(tmp_path, host):
    p = cfg(tmp_path, {"s": {"url": f"http://{host}/mcp"}})
    gk03 = [f for f in scan(str(p)).findings if f.rule == "GK03"]
    assert [f.severity.label for f in gk03] == ["medium"]


def test_stripe_key_in_url_is_critical(tmp_path):
    key = "sk_" + "live_" + "ABCDEFGHIJKLMNOP123456"  # assembled so no key-shaped literal is committed
    p = cfg(tmp_path, {"w": {"url": f"https://wiki.acme-corp.internal/mcp?api_key={key}"}})
    gk02 = [f for f in scan(str(p)).findings if f.rule == "GK02"]
    assert [f.severity.label for f in gk02] == ["critical"] and gk02[0].matched_text == key


def test_fifo_in_directory_walk_does_not_hang(tmp_path):
    os.mkfifo(tmp_path / "pipe.json")
    (tmp_path / "ok.json").write_text(json.dumps({"tools": [{"name": "t", "description": "fine"}]}))
    r = sub("scan", str(tmp_path), "--format", "json")
    rep = json.loads(r.stdout)
    assert r.returncode == 2 and any(e["message"] == "not a regular file" for e in rep["errors"])


@pytest.mark.parametrize("make", ["devnull", "fifo"])
def test_non_regular_explicit_path_message(tmp_path, make):
    if make == "fifo":
        target = str(tmp_path / "f.json")
        os.mkfifo(target)
    else:
        target = os.devnull
    r = sub("scan", target)
    assert r.returncode == 2 and "not a regular file" in r.stdout and "does not exist" not in r.stdout


def test_duplicate_keys_warn(tmp_path):
    p = tmp_path / ".mcp.json"
    p.write_text('{"mcpServers":{"s":{"command":"npx","args":["-y","a@1.0.0"],"args":["-y","b@1.0.0"]}}}')
    res = scan(str(p))
    dup = [f for f in res.findings if f.rule == "GK00"]
    assert len(dup) == 1 and dup[0].severity.label == "medium" and "shadowed" in dup[0].message
    assert res.exit_code == 0 and all(grounded(p, f) for f in res.findings)


def test_stdout_write_failure_exit_2():
    with open("/dev/full", "w") as full:
        r = subprocess.run([sys.executable, "-m", "mcp_gatekeeper", "scan", str(FIX)], stdout=full,
                           stderr=subprocess.PIPE, text=True, env=ENV, timeout=30)
    assert r.returncode == 2
    assert "Traceback" not in r.stderr and "Exception ignored" not in r.stderr


def test_broken_pipe_exit_2():
    p = subprocess.Popen([sys.executable, "-m", "mcp_gatekeeper", "scan", str(FIX), "--format", "json"],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV)
    p.stdout.read(10)
    p.stdout.close()
    err = p.stderr.read().decode()
    assert p.wait(timeout=30) == 2
    assert "Traceback" not in err and "Exception ignored" not in err


def test_fail_on_none_prints_report_not_pass():
    code, out = cli("scan", str(FIX / "gk06_suspicious_launch.json"), "--fail-on", "none")
    last = out.strip().splitlines()[-1]
    assert code == 0 and last.startswith("REPORT") and "PASS" not in last
    code, out = cli("scan", str(FIX / "clean_config.json"), "--fail-on", "none")
    assert out.strip().splitlines()[-1].startswith("PASS")


def test_color_always_beats_no_color():
    r = sub("scan", str(FIX / "gk02_inline_secret.json"), "--color", "always")
    assert "\033[" in r.stdout  # documented: an explicit --color always overrides NO_COLOR
