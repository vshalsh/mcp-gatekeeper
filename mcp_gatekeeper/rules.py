"""Rule pack v1 (GK01-GK06) and the engine that runs it.

Each rule is a plain function registered with :func:`rule`. A rule receives a
classified :class:`SourceDoc` and yields findings built with :func:`_finding`,
which is the single place provenance (file, json_path, line, column,
matched_text) is attached. Rules are pure and deterministic: no I/O beyond the
already-loaded document, no network, no randomness.
"""

from __future__ import annotations

import ipaddress
import math
import os
import re
import unicodedata
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, Optional
from urllib.parse import urlsplit

from .models import Entry, Finding, Node, Severity, SourceDoc


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    applies_to: str  # "client_config" | "tool_manifest"
    severities: tuple[Severity, ...]
    summary: str
    remediation: str
    check: Callable[[SourceDoc], Iterable[Finding]]


RULES: list[Rule] = []


def rule(rule_id: str, title: str, applies_to: str, severities: tuple[Severity, ...],
         summary: str, remediation: str):
    def deco(fn: Callable[[SourceDoc], Iterable[Finding]]):
        RULES.append(Rule(rule_id, title, applies_to, severities, summary, remediation, fn))
        return fn
    return deco


def rule_by_id(rule_id: str, applies_to: Optional[str] = None) -> Rule:
    for r in RULES:
        if r.id == rule_id and (applies_to is None or r.applies_to == applies_to):
            return r
    raise KeyError(rule_id)


def _finding(rule_id: str, severity: Severity, node: Node, message: str, *,
             begin: int = 0, end: Optional[int] = None, server: Optional[str] = None,
             tool: Optional[str] = None, sensitive: bool = False) -> Finding:
    """Create a finding whose provenance is taken from ``node`` (never guessed)."""
    r = rule_by_id(rule_id, node.doc.kind)
    loc = node.locate(begin, end)
    return Finding(
        rule=rule_id, severity=severity, title=r.title, message=message,
        file=node.doc.path, json_path=node.path, line=loc.line, column=loc.column,
        matched_text=loc.text, remediation=r.remediation, server=server, tool=tool,
        sensitive=sensitive,
    )


def run_rules(doc: SourceDoc) -> list[Finding]:
    findings: list[Finding] = []
    for r in RULES:
        if r.applies_to == doc.kind:
            findings.extend(r.check(doc))
    # De-duplicate identical rule hits on the same span.
    uniq: dict[tuple, Finding] = {}
    for f in findings:
        uniq.setdefault((f.rule, f.json_path, f.line, f.column, f.matched_text, f.message), f)
    return sorted(uniq.values(), key=Finding.sort_key)


# ---------------------------------------------------------------------------
# Shared helpers for server entries
# ---------------------------------------------------------------------------

def _cmd_name(cmd: str) -> str:
    base = re.split(r"[\\/]", cmd)[-1].lower()
    for ext in (".cmd", ".exe", ".bat", ".ps1"):
        if base.endswith(ext):
            base = base[: -len(ext)]
    return base


def _server_parts(entry: Entry) -> tuple[Optional[Node], list[Node]]:
    cmd = entry.node.get("command")
    args = entry.node.get("args")
    return (cmd if cmd is not None and cmd.is_str else None,
            args.string_list() if args is not None else [])


def _launcher(cmd: Optional[Node], args: list[Node]) -> tuple[Optional[str], list[Node]]:
    """Identify a package launcher and return (ecosystem, remaining args)."""
    if cmd is None:
        return None, args
    name = _cmd_name(cmd.value)
    first = args[0].value if args else ""
    if name in ("npx", "bunx", "pnpx"):
        return "npm", args
    if name in ("npm",) and first in ("exec", "x"):
        return "npm", args[1:]
    if name in ("pnpm", "yarn") and first == "dlx":
        return "npm", args[1:]
    if name == "uvx":
        return "pypi", args
    if name == "uv" and first == "tool" and len(args) > 1 and args[1].value == "run":
        return "pypi", args[2:]
    if name == "pipx" and first == "run":
        return "pipx", args[1:]
    if name in ("docker", "podman") and first == "run":
        return "docker", args[1:]
    return None, args


_NPM_VALUE_FLAGS = {"-p", "--package", "-c", "--call", "--registry", "--cache", "--prefix", "--userconfig"}
_UV_VALUE_FLAGS = {"--from", "--with", "--python", "-p", "--index", "--index-url", "--extra-index-url",
                   "--with-requirements", "--constraint", "-c", "--with-editable", "--spec"}
_DOCKER_VALUE_FLAGS = {"-e", "--env", "-v", "--volume", "--name", "--network", "--net", "-p", "--publish",
                       "--env-file", "-w", "--workdir", "--mount", "--entrypoint", "-u", "--user",
                       "--platform", "--label", "-l", "--add-host", "--cap-add", "--cap-drop", "--pull",
                       "-m", "--memory", "--cpus", "--hostname", "-h", "--device", "--security-opt",
                       "--ipc", "--pid", "--userns", "--tmpfs", "--restart", "--log-driver"}


def _package_specs(eco: str, args: list[Node]) -> list[Node]:
    """Return the arg nodes that name the package/image being fetched."""
    explicit: list[Node] = []
    positional: Optional[Node] = None
    value_flags = {"npm": _NPM_VALUE_FLAGS, "pypi": _UV_VALUE_FLAGS, "pipx": _UV_VALUE_FLAGS,
                   "docker": _DOCKER_VALUE_FLAGS}[eco]
    package_flags = {"npm": {"-p", "--package"}, "pypi": {"--from"}, "pipx": {"--spec"}, "docker": set()}[eco]
    i = 0
    while i < len(args):
        a = args[i].value
        if a == "--":
            if positional is None and i + 1 < len(args):
                positional = args[i + 1]
            break
        if a.startswith("-"):
            flag = a.split("=", 1)[0]
            if "=" in a:
                if flag in package_flags:
                    explicit.append(args[i])  # handled via prefix offset below
            elif flag in value_flags:
                if flag in package_flags and i + 1 < len(args):
                    explicit.append(args[i + 1])
                i += 1
            i += 1
            continue
        positional = args[i]
        break
    if explicit:
        return explicit
    return [positional] if positional is not None else []


_SEMVER = re.compile(r"^v?\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?$")
_LOCAL_SPEC = re.compile(r"^(?:\.{1,2}[\\/]|[\\/]|~|[A-Za-z]:[\\/]|file:)")


def _npm_pin(spec: str) -> tuple[bool, str]:
    if re.match(r"^(?:git\+|git:|github:|gitlab:|bitbucket:|https?:)", spec):
        if re.search(r"#[0-9a-f]{7,40}$", spec):
            return True, ""
        return False, "is fetched from a git/URL source without a pinned commit"
    at = spec.find("@", 1) if spec.startswith("@") else spec.find("@")
    if at <= 0:
        return False, "has no version, so the newest release is fetched on every launch"
    version = spec[at + 1:]
    if _SEMVER.match(version):
        return True, ""
    if version in ("latest", "next", "*", ""):
        return False, f"uses the moving tag '@{version}', so whatever is newest is fetched on every launch"
    return False, f"uses the range '@{version}' instead of an exact version"


def _pypi_pin(spec: str) -> tuple[bool, str]:
    if spec.startswith(("git+", "http://", "https://")):
        if re.search(r"@(?:[0-9a-f]{7,40}|v?\d+(?:\.\d+)+)$", spec):
            return True, ""
        return False, "is fetched from a git/URL source without a pinned commit or tag"
    if re.search(r"==\s*\d[\w.+-]*$", spec) or re.search(r"@\s*v?\d+(?:\.\d+)+[\w.+-]*$", spec):
        return True, ""
    if spec.endswith("@latest"):
        return False, "uses '@latest', so the newest release is fetched on every launch"
    if re.search(r"(>=|<=|~=|>|<|!=)", spec):
        return False, "uses a version range instead of an exact '==' pin"
    return False, "has no version, so the newest release is fetched on every launch"


def _docker_pin(spec: str) -> tuple[bool, str]:
    if "@sha256:" in spec:
        return True, ""
    last = spec.rsplit("/", 1)[-1]
    if ":" not in last:
        return False, "has no tag, so ':latest' is pulled"
    tag = last.split(":", 1)[1]
    if tag == "latest":
        return False, "uses the moving ':latest' tag"
    return True, ""


# ---------------------------------------------------------------------------
# GK01 unpinned server packages
# ---------------------------------------------------------------------------

@rule("GK01", "Unpinned server package", "client_config", (Severity.HIGH,),
      "Server launched via npx/bunx/pnpm dlx/uvx/pipx/docker run without an exact version, "
      "or with a moving tag such as @latest.",
      "Pin an exact version (pkg@1.2.3, pkg==1.2.3) or an image digest (@sha256:...), "
      "and review upgrades deliberately.")
def check_gk01(doc: SourceDoc) -> Iterator[Finding]:
    for entry in doc.servers:
        cmd, args = _server_parts(entry)
        eco, rest = _launcher(cmd, args)
        if eco is None:
            continue
        for node in _package_specs(eco, rest):
            spec = node.value
            offset = 0
            if spec.startswith("-") and "=" in spec:  # --package=foo / --from=foo
                offset = spec.index("=") + 1
                spec = spec[offset:]
            if not spec or _LOCAL_SPEC.match(spec):
                continue
            pinned, why = {"npm": _npm_pin, "pypi": _pypi_pin, "pipx": _pypi_pin,
                           "docker": _docker_pin}[eco](spec)
            if pinned:
                continue
            what = "image" if eco == "docker" else "package"
            yield _finding("GK01", Severity.HIGH, node,
                           f"Server '{entry.name}' {what} '{spec}' {why}.",
                           begin=offset, server=entry.name)


# ---------------------------------------------------------------------------
# GK02 inline secrets
# ---------------------------------------------------------------------------

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("Anthropic API key", re.compile(r"(?<![A-Za-z0-9])sk-ant-[A-Za-z0-9_\-]{20,}")),
    ("OpenAI-style API key", re.compile(r"(?<![A-Za-z0-9])sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}")),
    ("GitHub token", re.compile(r"(?<![A-Za-z0-9])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}")),
    ("GitHub fine-grained token", re.compile(r"(?<![A-Za-z0-9])github_pat_[A-Za-z0-9_]{22,}")),
    ("GitLab token", re.compile(r"(?<![A-Za-z0-9])glpat-[A-Za-z0-9_\-]{20,}")),
    ("AWS access key id", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("Slack token", re.compile(r"(?<![A-Za-z0-9])xox[abposr]-[A-Za-z0-9\-]{10,}")),
    ("Google API key", re.compile(r"(?<![A-Za-z0-9])AIza[0-9A-Za-z_\-]{35}")),
    ("Stripe secret key", re.compile(r"(?<![A-Za-z0-9])(?:sk|rk)_live_[A-Za-z0-9]{16,}")),
    ("Private key block", re.compile(r"-----BEGIN (?:[A-Z]+ )?PRIVATE KEY-----")),
    ("JSON Web Token", re.compile(r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")),
]
_SECRET_KEY = re.compile(
    r"(?i)(?:^|[_\-.])(?:token|secret|password|passwd|pwd|pass|apikey|api[_\-]?key|key|"
    r"credentials?|auth|authorization|bearer|cookie|session)(?:$|[_\-.])"
)
_PLACEHOLDER = re.compile(
    r"(?ix)^(?: \$\{[^}]*\} | \$[A-Za-z_][A-Za-z0-9_]* | %[A-Za-z_][A-Za-z0-9_]*% | <[^>]*> | \{\{[^}]*\}\} "
    r"| (?:your|my|insert|replace|enter)[\s_\-].* | .*(?:changeme|placeholder|redacted).* | x{3,} | \*{3,} )$"
)
_BEARER = re.compile(r"(?i)^(?:bearer|token|basic)\s+")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_placeholder(value: str) -> bool:
    v = value.strip()
    return not v or "${" in v or bool(_PLACEHOLDER.match(v))


def _known_secrets(node: Node) -> Iterator[tuple[str, int, int]]:
    for label, pat in _SECRET_PATTERNS:
        for m in pat.finditer(node.value):
            yield label, m.start(), m.end()
            break  # one hit per pattern per value is enough


def _secret_findings(node: Node, key: str, server: str, where: str, start: int = 0) -> Iterator[Finding]:
    """Classify ``node.value[start:]`` (the value assigned to ``key``) as a secret or not."""
    value = node.value[start:]
    hits = [(lbl, b, e) for lbl, b, e in _known_secrets(node) if b >= start]
    if hits:
        # Patterns are ordered most-specific first, so the first hit wins.
        label, b, e = hits[0]
        yield _finding("GK02", Severity.CRITICAL, node,
                       f"{label} stored in plain text in {where} '{key}' of server '{server}'.",
                       begin=b, end=e, server=server, sensitive=True)
        return
    if _is_placeholder(value) or value.lower() in ("true", "false", "null", "none", "0", "1"):
        return
    if not _SECRET_KEY.search(key):
        token = value
        if len(token) >= 32 and _entropy(token) >= 4.5 and re.fullmatch(r"[A-Za-z0-9+/=_\-]+", token):
            yield _finding("GK02", Severity.MEDIUM, node,
                           f"High-entropy value in {where} '{key}' of server '{server}' looks like a credential.",
                           begin=start, server=server, sensitive=True)
        return
    m = _BEARER.match(value)
    b = start + (m.end() if m else 0)
    token = node.value[b:]
    if _is_placeholder(token) or re.match(r"^(?:https?://|/|\./|~/)", token):
        return
    if len(token) <= 20 and re.fullmatch(r"[a-z]+(?:[-_][a-z]+)*", token):
        return  # identifier-like setting value (e.g. AUTH_MODE=browser), not a credential
    if len(token) >= 16 and _entropy(token) >= 3.5:
        yield _finding("GK02", Severity.HIGH, node,
                       f"Secret-named {where} '{key}' of server '{server}' holds a high-entropy literal.",
                       begin=b, server=server, sensitive=True)
    elif len(token) >= 6:
        yield _finding("GK02", Severity.MEDIUM, node,
                       f"Secret-named {where} '{key}' of server '{server}' holds a literal value.",
                       begin=b, server=server, sensitive=True)


_URL_CRED_PARAM = re.compile(r"(?i)[?&](?:api[_\-]?key|apikey|token|access[_\-]?token|secret|password|key)=([^&#\s]+)")


@rule("GK02", "Inline secret in config", "client_config", (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL),
      "Key-shaped or high-entropy secrets written literally into env blocks, headers, args or URLs.",
      "Move the secret to the OS keychain / environment and reference it (e.g. ${input:token} in VS Code, "
      "or set it in the launching shell); rotate any secret that was committed.")
def check_gk02(doc: SourceDoc) -> Iterator[Finding]:
    for entry in doc.servers:
        for block, where in (("env", "env var"), ("headers", "header")):
            container = entry.node.get(block)
            if container is None:
                continue
            for key, _kn, vn in container.items():
                if vn.is_str:
                    yield from _secret_findings(vn, key, entry.name, where)
        _cmd, args = _server_parts(entry)
        for idx, a in enumerate(args):
            prev = args[idx - 1].value if idx else ""
            kv = re.match(r"^(--?[A-Za-z][\w\-]*|[A-Za-z_][A-Za-z0-9_]*)=(.+)$", a.value)
            if kv and (kv.group(1).startswith("-") or prev in ("-e", "--env")):
                # --api-key=VALUE or `docker run -e TOKEN=VALUE`
                yield from _secret_findings(a, kv.group(1).lstrip("-"), entry.name, "argument", kv.start(2))
                continue
            for label, b, e in _known_secrets(a):
                yield _finding("GK02", Severity.CRITICAL, a,
                               f"{label} passed in plain text as a command-line argument of server '{entry.name}'.",
                               begin=b, end=e, server=entry.name, sensitive=True)
                break
        url = entry.node.get("url")
        if url is not None and url.is_str:
            parts = urlsplit(url.value) if "://" in url.value else None
            if parts is not None and parts.password and not _is_placeholder(parts.password):
                b = url.value.find(parts.password, url.value.find("://") + 3)
                yield _finding("GK02", Severity.HIGH, url,
                               f"Password embedded in the URL of server '{entry.name}'.",
                               begin=b, end=b + len(parts.password), server=entry.name, sensitive=True)
            for m in _URL_CRED_PARAM.finditer(url.value):
                if not _is_placeholder(m.group(1)):
                    yield _finding("GK02", Severity.HIGH, url,
                                   f"Credential-like query parameter in the URL of server '{entry.name}'.",
                                   begin=m.start(1), end=m.end(1), server=entry.name, sensitive=True)


# ---------------------------------------------------------------------------
# GK03 insecure transport
# ---------------------------------------------------------------------------

_PLAIN_URL = re.compile(r"(?i)\b(?:http|ws)://[^\s\"'<>`]+")


def _host_class(url: str) -> str:
    try:
        host = (urlsplit(url).hostname or "").lower()
    except ValueError:
        return "public"
    if host in ("localhost", "0.0.0.0") or host.endswith(".localhost"):
        return "loopback"
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "public"
    if ip.is_loopback or ip.is_unspecified:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


@rule("GK03", "Insecure transport", "client_config", (Severity.MEDIUM, Severity.HIGH),
      "Remote MCP server reached over plaintext http:// or ws:// (loopback addresses are exempt).",
      "Use https:// / wss:// for every non-local server; tunnel local-network servers over TLS.")
def check_gk03(doc: SourceDoc) -> Iterator[Finding]:
    for entry in doc.servers:
        candidates: list[Node] = []
        for key in ("url", "serverUrl", "endpoint"):
            n = entry.node.get(key)
            if n is not None and n.is_str:
                candidates.append(n)
        _cmd, args = _server_parts(entry)
        candidates.extend(args)
        for node in candidates:
            for m in _PLAIN_URL.finditer(node.value):
                cls = _host_class(m.group(0))
                if cls == "loopback":
                    continue
                sev = Severity.HIGH if cls == "public" else Severity.MEDIUM
                scope = "a remote host" if cls == "public" else "a private-network host"
                yield _finding("GK03", sev, node,
                               f"Server '{entry.name}' connects to {scope} over plaintext "
                               f"{m.group(0).split(':', 1)[0].lower()}://; traffic and credentials can be "
                               f"read or modified in transit.",
                               begin=m.start(), end=m.end(), server=entry.name)


# ---------------------------------------------------------------------------
# GK04 injection-style text in tool descriptions
# ---------------------------------------------------------------------------

_INVISIBLE_RANGES = [
    (0x200B, 0x200F),  # zero-width space/joiners, LRM/RLM
    (0x202A, 0x202E),  # bidi embeddings / overrides
    (0x2060, 0x2064),  # word joiner, invisible operators
    (0x2066, 0x2069),  # bidi isolates
    (0xFEFF, 0xFEFF),  # zero-width no-break space
    (0x180E, 0x180E),  # mongolian vowel separator
    (0x00AD, 0x00AD),  # soft hyphen
    (0xE0000, 0xE007F),  # Unicode tag characters ("ASCII smuggling")
]


def _is_invisible(ch: str) -> bool:
    o = ord(ch)
    return any(lo <= o <= hi for lo, hi in _INVISIBLE_RANGES)


def _flex(phrase: str) -> str:
    return phrase.replace(" ", r"\s+")


_INJECTION_PATTERNS: list[tuple[Severity, str, re.Pattern]] = [
    (Severity.HIGH, "instruction-override phrase", re.compile(_flex(
        r"(?:ignore|disregard|forget|override) (?:all |any |the )?(?:previous|prior|above|earlier|preceding|"
        r"system|other) (?:instructions?|prompts?|messages?|rules|directions|guidelines)"), re.I)),
    (Severity.HIGH, "concealment-from-user phrase", re.compile(_flex(
        r"(?:do not|don't|dont|never|must not) (?:tell|inform|mention|reveal|show|disclose|notify|alert) "
        r"(?:this |it |anything |that )?(?:to )?the user"), re.I)),
    (Severity.HIGH, "concealment-from-user phrase", re.compile(_flex(
        r"without (?:telling|informing|notifying|alerting|asking) the user"), re.I)),
    (Severity.HIGH, "sensitive-file reference", re.compile(
        r"~/\.ssh|\bid_rsa\b|\bid_ed25519\b|\.aws/credentials|\.netrc\b|/etc/(?:passwd|shadow)\b|"
        r"\.npmrc\b|claude_desktop_config\.json|\.mcp\.json", re.I)),
    (Severity.HIGH, "role-reassignment phrase", re.compile(_flex(
        r"(?:you are now|from now on you|new instructions:|act as (?:an? )?(?:admin|root|system))"), re.I)),
    (Severity.MEDIUM, "pseudo-system tag", re.compile(
        r"<\s*/?\s*(?:important|system|instructions?|secret|admin)\s*>", re.I)),
    (Severity.MEDIUM, "pre-call directive", re.compile(_flex(
        r"before (?:using|calling|invoking) this tool,? (?:you )?(?:must|always|first|should)"), re.I)),
]
_HTML_COMMENT = re.compile(r"<!--.*?-->", re.S)


def _describe_invisible(run: str) -> str:
    tags = "".join(chr(ord(c) - 0xE0000) for c in run if 0xE0020 <= ord(c) <= 0xE007E)
    names = []
    for c in run:
        label = f"U+{ord(c):04X} {unicodedata.name(c, 'UNNAMED')}"
        if label not in names:
            names.append(label)
    desc = f"{len(run)} invisible character(s): {', '.join(names[:4])}" + (", ..." if len(names) > 4 else "")
    if tags:
        desc += f"; tag characters spell hidden text {tags!r}"
    return desc


@rule("GK04", "Injection-style text in tool metadata", "tool_manifest",
      (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL),
      "Tool names/descriptions/schemas containing prompt-injection phrasing, concealment instructions, "
      "sensitive-file references, hidden HTML comments, or zero-width / bidi / tag unicode.",
      "Do not connect the server until the text is explained; report it to the maintainer. "
      "Tool metadata is read by the model as instructions.")
def check_gk04(doc: SourceDoc) -> Iterator[Finding]:
    if doc.root is None:
        return
    tool_of: dict[int, str] = {}
    for t in doc.tools:
        for n in t.node.walk():
            tool_of[id(n)] = t.name
    for node in doc.root.strings():
        text = node.value
        tool = tool_of.get(id(node))
        where = f"tool '{tool}'" if tool else "manifest"
        i = 0
        while i < len(text):
            if _is_invisible(text[i]):
                j = i
                while j < len(text) and _is_invisible(text[j]):
                    j += 1
                yield _finding("GK04", Severity.CRITICAL, node,
                               f"Hidden unicode in {where}: {_describe_invisible(text[i:j])}.",
                               begin=i, end=j, tool=tool)
                i = j
            else:
                i += 1
        for m in _HTML_COMMENT.finditer(text):
            yield _finding("GK04", Severity.HIGH, node,
                           f"Hidden HTML comment in {where}; models read it, users usually do not see it.",
                           begin=m.start(), end=m.end(), tool=tool)
        for sev, label, pat in _INJECTION_PATTERNS:
            for m in pat.finditer(text):
                yield _finding("GK04", sev, node, f"Prompt-injection {label} in {where}.",
                               begin=m.start(), end=m.end(), tool=tool)


# ---------------------------------------------------------------------------
# GK05 over-privileged tool surface
# ---------------------------------------------------------------------------

_DANGER_TOKENS = {"shell", "exec", "eval", "bash", "sh", "zsh", "powershell", "pwsh", "cmd", "terminal",
                  "subprocess", "spawn", "rm", "rmrf", "sudo", "system"}
_DANGER_PAIRS = {("run", "command"), ("execute", "command"), ("run", "script"), ("execute", "script"),
                 ("run", "code"), ("execute", "code"), ("run", "shell"), ("exec", "command"),
                 ("delete", "directory"), ("remove", "directory"), ("execute", "python"), ("run", "python")}


def _name_tokens(name: str) -> list[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return [t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t]


def _dangerous_tool(name: str) -> Optional[str]:
    toks = _name_tokens(name)
    for t in toks:
        if t in _DANGER_TOKENS:
            return t
    for a, b in zip(toks, toks[1:]):
        if (a, b) in _DANGER_PAIRS:
            return f"{a}_{b}"
    return None


_ROOT_PATH = re.compile(r"^(?:/|[A-Za-z]:[\\/]?|\\\\)$")
_HOME_PATH = re.compile(r"^(?:~|~/|\$HOME|\$\{HOME\}|\$\{userHome\}|%USERPROFILE%|/home/?|/Users/?|/root/?)$")


@rule("GK05", "Over-privileged tool surface", "client_config", (Severity.MEDIUM, Severity.HIGH),
      "Filesystem access rooted at '/' (or a drive root / whole home directory), privileged containers, "
      "host-root or docker.sock mounts.",
      "Scope filesystem servers to the specific project directories they need; drop --privileged and "
      "host-root mounts.")
def check_gk05_config(doc: SourceDoc) -> Iterator[Finding]:
    for entry in doc.servers:
        cmd, args = _server_parts(entry)
        eco, _rest = _launcher(cmd, args)
        for a in args:
            v = a.value
            if _ROOT_PATH.match(v):
                yield _finding("GK05", Severity.HIGH, a,
                               f"Server '{entry.name}' is granted the filesystem root '{v}'.", server=entry.name)
            elif _HOME_PATH.match(v):
                yield _finding("GK05", Severity.MEDIUM, a,
                               f"Server '{entry.name}' is granted an entire home directory '{v}'.",
                               server=entry.name)
            if eco == "docker":
                if v == "--privileged":
                    yield _finding("GK05", Severity.HIGH, a,
                                   f"Server '{entry.name}' runs in a privileged container.", server=entry.name)
                mount = v.split("=", 1)[1] if v.startswith(("--volume=", "-v=")) else v
                if re.match(r"^/:", mount):
                    yield _finding("GK05", Severity.HIGH, a,
                                   f"Server '{entry.name}' mounts the host root filesystem.", server=entry.name)
                elif "docker.sock" in mount:
                    k = v.find("docker.sock")
                    yield _finding("GK05", Severity.HIGH, a,
                                   f"Server '{entry.name}' mounts the Docker socket (host root equivalent).",
                                   begin=k, end=k + len("docker.sock"), server=entry.name)


# GK05 also applies to tool manifests (same rule id, separate check).
def check_gk05_manifest(doc: SourceDoc) -> Iterator[Finding]:
    for t in doc.tools:
        name = t.node.get("name")
        if name is None or not name.is_str:
            continue
        hit = _dangerous_tool(name.value)
        if hit:
            yield _finding("GK05", Severity.HIGH, name,
                           f"Tool '{name.value}' exposes arbitrary command/code execution ('{hit}').",
                           tool=name.value)


RULES.append(Rule("GK05", "Over-privileged tool surface", "tool_manifest", (Severity.HIGH,),
                  "Tools named like shell/exec/eval/run_command/rm that hand the model arbitrary execution.",
                  "Prefer narrowly-scoped tools; if a shell tool is required, run the server sandboxed and require "
                  "per-call human approval.", check_gk05_manifest))


# ---------------------------------------------------------------------------
# GK06 suspicious launch commands
# ---------------------------------------------------------------------------

_PIPE_TO_SHELL = re.compile(
    r"(?i)(?:\b(?:curl|wget|fetch|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^|;&]*\|\s*(?:sudo\s+)?"
    r"(?:ba|z|k|da|fi)?sh\b|\b(?:curl|wget)\b[^|;&]*\|\s*(?:sudo\s+)?(?:python3?|node|perl|ruby)\b|"
    r"\|\s*(?:iex|invoke-expression)\b|\$\((?:curl|wget)\b[^)]*\)|`(?:curl|wget)\b[^`]*`|"
    r"\bbase64\s+(?:-d|--decode)\b[^|]*\|\s*(?:ba|z)?sh\b)"
)
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh", "fish", "cmd", "powershell", "pwsh"}
_INTERPRETERS = {"node", "python", "python3", "deno", "bun", "ruby", "perl", "php"} | _SHELLS
_WORLD_WRITABLE = re.compile(r"^(?:/tmp/|/var/tmp/|/dev/shm/|C:\\Windows\\Temp\\|%TEMP%|\$TMPDIR)", re.I)


@rule("GK06", "Suspicious launch command", "client_config", (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL),
      "Download-and-execute (curl|bash, iwr|iex), programs launched from world-writable directories, "
      "path-relative commands, inline shell wrappers, hidden unicode in command lines.",
      "Install the server through a pinned package or a reviewed local checkout and launch it by absolute path.")
def check_gk06(doc: SourceDoc) -> Iterator[Finding]:
    for entry in doc.servers:
        cmd, args = _server_parts(entry)
        if cmd is None:
            continue
        parts = [cmd] + args
        for node in parts:
            m = _PIPE_TO_SHELL.search(node.value)
            if m:
                yield _finding("GK06", Severity.CRITICAL, node,
                               f"Server '{entry.name}' downloads and executes remote code at launch.",
                               begin=m.start(), end=m.end(), server=entry.name)
            for i, ch in enumerate(node.value):
                if _is_invisible(ch):
                    j = i
                    while j < len(node.value) and _is_invisible(node.value[j]):
                        j += 1
                    yield _finding("GK06", Severity.CRITICAL, node,
                                   f"Hidden unicode in the launch command of server '{entry.name}' "
                                   f"({_describe_invisible(node.value[i:j])}).",
                                   begin=i, end=j, server=entry.name)
                    break
        c = cmd.value.strip()
        name = _cmd_name(c)
        if _WORLD_WRITABLE.match(c):
            yield _finding("GK06", Severity.HIGH, cmd,
                           f"Server '{entry.name}' runs a program from a world-writable directory.",
                           server=entry.name)
        elif not os.path.isabs(c) and not re.match(r"^[A-Za-z]:[\\/]", c) and (
                c.startswith(".") or "/" in c or "\\" in c):
            yield _finding("GK06", Severity.MEDIUM, cmd,
                           f"Server '{entry.name}' uses the path-relative command '{c}', which resolves against "
                           f"an unpredictable working directory.", server=entry.name)
        if name in _INTERPRETERS:
            script = next((a for a in args if not a.value.startswith("-")), None)
            if script is not None and _WORLD_WRITABLE.match(script.value):
                yield _finding("GK06", Severity.HIGH, script,
                               f"Server '{entry.name}' executes a script from a world-writable directory.",
                               server=entry.name)
        if name in _SHELLS and any(a.value.lower() in ("-c", "/c", "-command", "-encodedcommand", "-enc")
                                   for a in args):
            flag = next(a for a in args if a.value.lower() in ("-c", "/c", "-command", "-encodedcommand", "-enc"))
            sev = Severity.HIGH if flag.value.lower() in ("-encodedcommand", "-enc") else Severity.MEDIUM
            yield _finding("GK06", sev, flag,
                           f"Server '{entry.name}' is launched through an inline shell wrapper "
                           f"('{cmd.value} {flag.value} ...'), hiding what actually runs.", server=entry.name)
