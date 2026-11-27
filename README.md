# mcp-gatekeeper

A pre-flight security gate for MCP (Model Context Protocol) setups. `mcp-gatekeeper` audits MCP **client configurations** and **server tool manifests** *before* you connect an agent to them, and fails your CI or shell script when it finds something risky.

- Offline and deterministic. It makes no network calls and no LLM calls, and the same input always gives the same output.
- Light on dependencies. It needs the Python standard library plus PyYAML, and nothing else.
- Every finding carries provenance (`file`, `json_path`, `line`, `column`, `matched_text`), so you can check it by opening the file at that location.

## Why

Teams now wire agents to dozens of third-party MCP servers, usually by pasting a snippet into `claude_desktop_config.json` or `.mcp.json`. Those few lines decide what code runs on your machine, which secrets it sees, and what text your model reads as instructions. The common failure modes are well known:

- The package is unpinned, so `npx -y` fetches whatever was published five minutes ago.
- Tokens are pasted into `env` blocks and then committed.
- Remote servers are reached over plaintext `http://`.
- Tool descriptions carry prompt injection, sometimes hidden in zero-width or bidi unicode.
- Servers are handed `/` or a shell tool.
- Launch commands are `curl ... | bash` one-liners.

None of these needs a runtime proxy to detect. A static review before connecting catches them, and this tool is that review.

## Install

Requires Python 3.10+.

```bash
git clone <this repository> mcp-gatekeeper
cd mcp-gatekeeper
pip install .            # or: pip install -e '.[test]' for development
```

This installs the `mcp-gatekeeper` console command. `python -m mcp_gatekeeper` also works.

## Usage

```bash
mcp-gatekeeper scan PATH [PATH ...] [--format text|json] [--fail-on SEVERITY|none]
                                    [--color auto|always|never] [--redact]
mcp-gatekeeper rules     # list the rule pack
mcp-gatekeeper schema    # print the JSON Schema of --format json output
```

`PATH` can be a file or a directory. Directories are walked recursively in sorted order (`.git`, `node_modules`, `.venv`, `__pycache__`, `dist` and `build` are skipped). Every `*.json`, `*.jsonc`, `*.yaml` and `*.yml` file is classified by its content:

| Recognised as | How |
|---|---|
| Claude Desktop config | `mcpServers` object in `claude_desktop_config.json` |
| Project config (`.mcp.json`) | `mcpServers` object in `.mcp.json` |
| Other `mcpServers` config | `mcpServers` object in any other file (e.g. Cursor, Windsurf) |
| VS Code user/workspace settings | `"mcp": {"servers": {...}}` in `settings.json` (JSONC: comments and trailing commas accepted) |
| VS Code `mcp.json` | top-level `servers` object |
| Tool manifest | top-level `tools` array (a `tools/list` result), a JSON-RPC response with `result.tools`, or a bare array of tool objects, in JSON or YAML |

Files with no MCP content are listed as skipped and do not affect the result.

### Example output

Scanning the realistic Claude Desktop config fixture in this repo:

```text
$ mcp-gatekeeper scan tests/fixtures/realistic/claude_desktop_config.json
mcp-gatekeeper 0.1.0: scanned 1 file(s) (1 client config(s), 0 tool manifest(s))

tests/fixtures/realistic/claude_desktop_config.json  [claude_desktop, 6 server(s)]
  HIGH      GK01  Unpinned server package  server=github
            Server 'github' package '@modelcontextprotocol/server-github' has no version, so the newest release is fetched on every launch.
            at tests/fixtures/realistic/claude_desktop_config.json:14:23  $.mcpServers.github.args[1]
            matched: @modelcontextprotocol/server-github
            fix: Pin an exact version (pkg@1.2.3, pkg==1.2.3) or an image digest (@sha256:...), and review upgrades deliberately.
  CRITICAL  GK02  Inline secret in config  server=github
            GitHub token stored in plain text in env var 'GITHUB_PERSONAL_ACCESS_TOKEN' of server 'github'.
            at tests/fixtures/realistic/claude_desktop_config.json:16:42  $.mcpServers.github.env.GITHUB_PERSONAL_ACCESS_TOKEN
            matched: ghp_...[redacted 40 chars]
            fix: Move the secret to the OS keychain / environment and reference it (e.g. ${input:token} in VS Code, or set it in the launching shell); rotate any secret that was committed.
  HIGH      GK03  Insecure transport  server=linear
            Server 'linear' connects to a remote host over plaintext http://; traffic and credentials can be read or modified in transit.
            at tests/fixtures/realistic/claude_desktop_config.json:36:44  $.mcpServers.linear.args[2]
            matched: http://mcp.tracker-vendor.example.com/sse
            fix: Use https:// / wss:// for every non-local server; tunnel local-network servers over TLS.

FAIL  3 finding(s): 1 critical, 2 high, 0 medium, 0 low, 0 info  (fail-on: high, exit 1)
```

Notes on the text output:

- Colour is used only when stdout is a TTY. Set `NO_COLOR` or pass `--color never` to disable it, or `--color always` to force it. The severity word is always printed, so colour is only a secondary cue.
- Secret values (GK02) are always masked in text output.
- Invisible characters in `matched:` are shown as `\uXXXX` escapes so you can see them.

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed and no finding is at or above `--fail-on` |
| `1` | At least one finding is at or above `--fail-on` (default `high`) |
| `2` | Scan incomplete: bad arguments, a path that does not exist, an unreadable or unparseable config, or nothing scannable found |

An incomplete scan returns `2` even when findings also exist, because the tool cannot vouch for input it could not read. Use `--fail-on none` to report findings without failing on them.

Severity order: `info < low < medium < high < critical`.

### CI example

```bash
mcp-gatekeeper scan .mcp.json .vscode/ --format json --redact > mcp-audit.json
```

## JSON output

`--format json` prints one JSON document with no colour, indented with 2 spaces and ASCII-escaped. Run `mcp-gatekeeper schema` to get the full JSON Schema (draft 2020-12). `mcp_gatekeeper.schema.validate(report)` checks a report against it using only the standard library.

```text
{
  "tool": "mcp-gatekeeper",            // const
  "version": "0.1.0",
  "schema_version": "1",               // bumped on breaking changes
  "fail_on": "high",                   // info|low|medium|high|critical|none
  "passed": false,                     // true iff exit_code == 0
  "exit_code": 1,                      // 0|1|2
  "scanned_files": [
    {"file": "...", "kind": "client_config|tool_manifest",
     "flavor": "claude_desktop|mcp_json|mcp_servers|vscode_settings|vscode_mcp|tool_manifest",
     "servers": 6, "tools": 0, "findings": 3}
  ],
  "skipped_files": [{"file": "...", "reason": "..."}],
  "errors":        [{"file": "...", "message": "..."}],
  "summary": {
    "total": 3,
    "by_severity": {"info": 0, "low": 0, "medium": 0, "high": 2, "critical": 1},
    "by_rule": {"GK01": 1, "GK02": 1, "GK03": 1}
  },
  "findings": [
    {
      "rule": "GK03",                  // GK01..GK06
      "severity": "high",
      "title": "Insecure transport",
      "message": "Server 'analytics' connects to a remote host over plaintext http://; ...",
      "file": "tests/fixtures/gk03_http_transport.json",   // path as passed / walked
      "json_path": "$.mcpServers.analytics.url",           // JSONPath to the value
      "line": 5,                       // 1-based
      "column": 15,                    // 1-based, in characters, start of matched_text
      "matched_text": "http://mcp.analytics-vendor.example.com/mcp",  // exact raw source text
      "redacted": false,               // true only when --redact masked a secret
      "server": "analytics",           // server name (configs) or null
      "tool": null,                    // tool name (manifests) or null
      "remediation": "Use https:// / wss:// for every non-local server; ..."
    }
  ]
}
```

Findings are sorted by `file`, `line`, `column` and then `rule`. `json_path` uses dot notation for identifier keys and bracket notation for any other key (`$.mcp.servers["my-internal-api"].url`).

**Sensitive data:** without `--redact`, `matched_text` for a GK02 finding is the secret itself, because that is what makes the finding verifiable. Treat unredacted JSON reports as sensitive, or pass `--redact` in CI.

## Rule reference

| Rule | Applies to | Severity | Fires on | Fix |
|---|---|---|---|---|
| **GK01** Unpinned server package | client config | high | `npx`/`bunx`/`pnpm dlx`/`yarn dlx`/`npm exec` packages with no version, a dist-tag (`@latest`, `@next`) or a range; `uvx`/`uv tool run`/`pipx run` without `==`/`@x.y.z`; git sources without a commit; `docker`/`podman run` images with no tag or `:latest`. Local paths are ignored. | Pin `pkg@1.2.3`, `pkg==1.2.3`, or `image@sha256:...` |
| **GK02** Inline secret in config | client config | critical: known key format (`sk-ant-`, `sk-`, `ghp_`/`gho_`/..., `github_pat_`, `glpat-`, `AKIA`/`ASIA`, `xox?-`, `AIza`, `sk_live_`, PEM private key, JWT)<br>high: secret-named key (`*_TOKEN`, `*_KEY`, `*PASSWORD*`, `Authorization`, ...) with a high-entropy literal, or credentials in a URL<br>medium: secret-named key with a low-entropy literal, or a high-entropy value under any key | Values in `env` and `headers`, `--flag=value` and `docker -e K=V` arguments, any argument containing a known key format, and `url` userinfo or `?token=` query parameters. Placeholders such as `${VAR}`, `${input:id}`, `$VAR`, `<your-token>` and `{{x}}` are ignored. | Reference the secret from the environment or keychain, and rotate it |
| **GK03** Insecure transport | client config | high (public host), medium (private network) | `http://` or `ws://` in `url`/`serverUrl`/`endpoint` or in arguments (e.g. `mcp-remote http://...`). Loopback (`localhost`, `127.0.0.0/8`, `::1`, `0.0.0.0`) is exempt. | Use `https://` / `wss://` |
| **GK04** Injection-style text in tool metadata | tool manifest | critical: zero-width, bidi-control, soft-hyphen or Unicode tag characters (the hidden tag payload is decoded in the message)<br>high: instruction-override phrases ("ignore previous instructions"), concealment ("do not tell the user", "without telling the user"), role reassignment ("from now on you"), sensitive-file references (`~/.ssh`, `id_rsa`, `.aws/credentials`, MCP config files), hidden `<!-- -->` comments<br>medium: pseudo-system tags (`<IMPORTANT>`), "before using this tool you must" | Every string in the manifest: names, descriptions, titles and the whole `inputSchema` | Do not connect, and report it to the maintainer |
| **GK05** Over-privileged tool surface | client config | high: `/`, a drive root, `--privileged`, a host-root mount (`-v /:/host`), a `docker.sock` mount<br>medium: an entire home directory (`~`, `$HOME`, `/Users`) | Server arguments | Scope access to the directories the server needs |
| **GK05** Over-privileged tool surface | tool manifest | high | Tool names that contain the tokens `shell`, `exec`, `eval`, `bash`, `sh`, `powershell`, `terminal`, `subprocess`, `spawn`, `rm`, `sudo` or `system`, or the pairs `run_command`, `execute_code`, `run_script` and similar (snake, kebab and camelCase are all split) | Narrow the tools, sandbox the server, and require per-call approval |
| **GK06** Suspicious launch command | client config | critical: download-and-execute (`curl ... \| bash`, `wget ... \| sh`, `$(curl ...)`, `iwr ... \| iex`, `base64 -d \| sh`), or hidden unicode in `command`/`args`<br>high: a program or interpreter script in a world-writable directory (`/tmp`, `/var/tmp`, `/dev/shm`, `%TEMP%`), or `powershell -EncodedCommand`<br>medium: a path-relative `command` (`./bin/server`), or an inline shell wrapper (`bash -c`, `cmd /c`) | `command` and `args` | Install a pinned package or reviewed checkout and launch it by absolute path |

## Grounding & traceability

`mcp-gatekeeper` is deterministic and produces no AI-generated output, so grounding here means **finding provenance**: every finding must point at real text in a real file.

- **Every finding carries provenance.** Each finding records `file`, `json_path`, `line`, `column`, `matched_text`, `rule` and `severity`.
- **Locations come from the parser, not from re-searching.** The bundled JSON/JSONC parser (`mcp_gatekeeper/discovery.py`) records the raw source offset of every value and of every decoded character inside strings. Rules never compute locations themselves. They hand a node and a span of its decoded value to one helper (`_finding` in `mcp_gatekeeper/rules.py`), which calls `Node.locate` (`mcp_gatekeeper/models.py`) to map the span back to raw source text. So `matched_text` is the exact text as it appears on disk, escapes included: a zero-width space written as `​` in the file is reported as `​`. YAML manifests use PyYAML's composer marks in the same way.
- **Verification approach.** A verifier re-opens each flagged file, reads line `line`, and confirms that `matched_text` appears there starting at `column`, and that `json_path` resolves to the value containing it. A finding that does not point at real text counts as a Sev-1 bug. The smoke suite runs this check, including `json_path` resolution, over the whole fixture corpus (`tests/test_smoke.py::test_every_finding_points_at_real_text`). The full grounding verifier (`tests/test_grounding.py`) belongs to the system-test suite.
- **No hidden inputs.** Output depends only on the bytes of the scanned files and the CLI flags. There is no network, clock, randomness or model involved.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test]'
pytest
```

The fixtures in `tests/fixtures/` cover one positive fixture per rule, clean config and manifest fixtures (JSON and YAML) that must produce zero findings, a realistic `claude_desktop_config.json`, a `.mcp.json`, a VS Code `settings.json` with an MCP block, and an injection-laced manifest with literal zero-width characters, escaped bidi overrides and Unicode tag characters. Every credential-shaped value in the fixtures is fake (for example `ghp_FAKEFAKE...` and the AWS documentation example key).

## Out of scope (v0.1)

Runtime proxying or interception, live traffic inspection, automatic fixing, Windows registry configs, auto-discovery of per-user config locations (pass paths explicitly), and fetching manifests from live servers. Export `tools/list` output to a file and scan that file instead.

## License

MIT. See [LICENSE](LICENSE).
