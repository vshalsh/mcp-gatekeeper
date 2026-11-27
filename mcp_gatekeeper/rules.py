"""Rule pack (GK00-GK06, GK04R) and the engine that runs it.

Each rule is a plain function registered with :func:`rule`. A rule receives a
classified :class:`SourceDoc` and yields findings built with :func:`_finding`,
which is the single place provenance (file, json_path, line, column,
matched_text) is attached. Rules are pure and deterministic: no I/O beyond the
already-loaded document, no network, no randomness.
"""

from __future__ import annotations

import base64
import binascii
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
             tool: Optional[str] = None, sensitive: bool = False, incomplete: bool = False) -> Finding:
    """Create a finding whose provenance is taken from ``node`` (never guessed)."""
    r = rule_by_id(rule_id, node.doc.kind)
    loc = node.locate(begin, end)
    return Finding(
        rule=rule_id, severity=severity, title=r.title, message=message,
        file=node.doc.path, json_path=node.path, line=loc.line, column=loc.column,
        matched_text=loc.text, remediation=r.remediation, server=server, tool=tool,
        sensitive=sensitive, incomplete=incomplete,
    )


def run_rules(doc: SourceDoc) -> list[Finding]:
    findings: list[Finding] = []
    for r in RULES:
        if r.applies_to == doc.kind:
            findings.extend(r.check(doc))
    # De-duplicate: one finding per rule per exact span (the first, most specific, wins).
    uniq: dict[tuple, Finding] = {}
    for f in findings:
        uniq.setdefault((f.rule, f.json_path, f.line, f.column, f.matched_text), f)
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


# ---- shell wrappers: `bash -c "npx -y pkg"`, `powershell -EncodedCommand <b64>` -------------

_SCRIPT_TOKEN = re.compile(r'"((?:[^"\\]|\\.)*)"|\'([^\']*)\'|([^\s"\';&|]+)|(&&|\|\||[;&|])')
_SHELL_C_FLAGS = {"-c", "/c", "/k", "-command"}
_PS_ENC_FLAGS = {"-encodedcommand", "-enc", "-ec", "-e"}


@dataclass
class _Launch:
    cmd: Optional[Node]
    args: list[Node]
    via: str = ""  # "" for the entry itself, else a phrase describing the wrapper
    assigns: tuple = ()  # leading NAME=value tokens of a wrapped command


def _sub_node(parent: Node, b: int, e: int, opaque: bool) -> Node:
    """String node for decoded span [b, e) of ``parent`` that keeps parent provenance.

    ``opaque`` nodes (text decoded from an encoded blob) always locate to the
    whole parent string, because their text does not appear in the file.
    """
    value = parent.value[b:e]
    offs = None
    if parent.offsets is not None:
        if opaque:
            offs = [parent.offsets[0]] * len(value) + [parent.offsets[-1]]
        else:
            offs = parent.offsets[b:e] + [parent.offsets[e]]
    return Node("string", value, parent.path, parent.doc, parent.start, parent.end, offsets=offs)


def _split_script(node: Node, opaque: bool = False) -> list[list[Node]]:
    cmds: list[list[Node]] = [[]]
    for m in _SCRIPT_TOKEN.finditer(node.value):
        if m.group(4):
            cmds.append([])
            continue
        g = 1 if m.group(1) is not None else 2 if m.group(2) is not None else 3
        cmds[-1].append(_sub_node(node, m.start(g), m.end(g), opaque))
    return [c for c in cmds if c]


def _decode_ps(node: Node) -> Optional[str]:
    try:
        text = base64.b64decode(node.value, validate=True).decode("utf-16-le")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    return text if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text) else None


def _launches(entry: Entry) -> Iterator[_Launch]:
    """The entry's own command, plus every command inside a shell wrapper."""
    cmd, args = _server_parts(entry)
    yield _Launch(cmd, args)
    if cmd is None or _cmd_name(cmd.value) not in _SHELLS:
        return
    for i, a in enumerate(args[:-1]):
        flag = a.value.lower()
        parts: list[list[Node]] = []
        if flag in _SHELL_C_FLAGS:
            parts, via = _split_script(args[i + 1]), " (inside its shell wrapper)"
        elif flag in _PS_ENC_FLAGS:
            text = _decode_ps(args[i + 1])
            if text is None:
                break
            blob = args[i + 1]
            virtual = Node("string", text, blob.path, blob.doc, blob.start, blob.end,
                           offsets=None if blob.offsets is None else [blob.offsets[0]] * len(text) + [blob.offsets[-1]])
            parts, via = _split_script(virtual, opaque=True), " (inside its decoded -EncodedCommand)"
        else:
            continue
        for part in parts:
            assigns = []
            while part and re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", part[0].value):
                assigns.append(part.pop(0))
            yield _Launch(part[0] if part else None, part[1:], via, tuple(assigns))
        break


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
# GK00 config integrity (fail closed)
# ---------------------------------------------------------------------------

_SERVER_FIELD_KINDS = {"command": ("string",), "args": ("array",), "env": ("object",), "headers": ("object",),
                       "url": ("string",), "serverUrl": ("string",), "endpoint": ("string",),
                       "type": ("string",), "cwd": ("string",)}
_ARTICLE = {"object": "an object", "array": "an array", "string": "a string", "number": "a number",
            "bool": "a boolean", "null": "null"}


def _shape(node: Node, what: str, expected: str, *, server: Optional[str] = None,
           tool: Optional[str] = None) -> Finding:
    return _finding("GK00", Severity.HIGH, node,
                    f"Could not verify {what} (unexpected shape): it is {_ARTICLE[node.kind]}, expected "
                    f"{expected}. Clients may still load it, so the scan is incomplete.",
                    server=server, tool=tool, incomplete=True)


def _duplicate_keys(doc: SourceDoc) -> Iterator[Finding]:
    if doc.root is None:
        return
    for obj in doc.root.walk():
        if obj.kind != "object":
            continue
        seen: dict[str, list[Node]] = {}
        for key, kn, _vn in obj.items():
            seen.setdefault(key, []).append(kn)
        for key, knodes in seen.items():
            if len(knodes) < 2:
                continue
            earlier = ", ".join(str(doc.line_col(k.start)[0]) for k in knodes[:-1])
            yield _finding("GK00", Severity.MEDIUM, knodes[-1],
                           f"Key '{key}' is defined {len(knodes)} times in {obj.path}; the first definition "
                           f"(line {earlier}) is shadowed by this one, because JSON parsers keep the last. "
                           f"A reviewer reading top-down sees a different value than the client loads.")


@rule("GK00", "Config integrity", "client_config", (Severity.MEDIUM, Severity.HIGH),
      "Server entries whose shape cannot be verified (command not a string, args not an array, env not an "
      "object, ...) and duplicate keys that shadow an earlier definition.",
      "Fix the entry so it matches the client's documented schema, and remove duplicate keys.")
def check_gk00_config(doc: SourceDoc) -> Iterator[Finding]:
    for c in doc.containers:
        if c.kind != "object":
            yield _shape(c, f"the server list at {c.path}", "an object mapping server names to entries")
    for entry in doc.servers:
        n = entry.node
        if n.kind != "object":
            yield _shape(n, f"server entry '{entry.name}'", "an object", server=entry.name)
            continue
        for key, _kn, v in n.items():
            kinds = _SERVER_FIELD_KINDS.get(key)
            if kinds and v.kind not in kinds:
                yield _shape(v, f"'{key}' of server '{entry.name}'", _ARTICLE[kinds[0]], server=entry.name)
            elif key == "args":
                for el in v.elements():
                    if el.kind in ("object", "array"):
                        yield _shape(el, f"an argument of server '{entry.name}'", "a string", server=entry.name)
            elif key in ("env", "headers"):
                for k2, _kn2, v2 in v.items():
                    if v2.kind in ("object", "array"):
                        yield _shape(v2, f"{key} '{k2}' of server '{entry.name}'", "a string",
                                     server=entry.name)
    yield from _duplicate_keys(doc)


def check_gk00_manifest(doc: SourceDoc) -> Iterator[Finding]:
    for c in doc.containers:
        if c.kind != "array":
            yield _shape(c, f"the tool list at {c.path}", "an array of tool objects")
    for t in doc.tools:
        if t.node.kind != "object":
            yield _shape(t.node, f"tool entry {t.node.path}", "an object")
            continue
        name = t.node.get("name")
        if name is None or not name.is_str:
            target = name if name is not None else t.node
            yield _shape(target, f"the name of tool {t.node.path}", "a string")
    yield from _duplicate_keys(doc)


RULES.append(Rule("GK00", "Config integrity", "tool_manifest", (Severity.MEDIUM, Severity.HIGH),
                  "Tool entries that are not objects or have no string name, and duplicate keys that shadow an "
                  "earlier definition.",
                  "Fix the manifest so every tool is an object with a string name; remove duplicate keys.",
                  check_gk00_manifest))


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
        for launch in _launches(entry):
            yield from _gk01_launch(entry, launch)


def _gk01_launch(entry: Entry, launch: _Launch) -> Iterator[Finding]:
    eco, rest = _launcher(launch.cmd, launch.args)
    if eco is None:
        return
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
                       f"Server '{entry.name}' {what} '{spec}'{launch.via} {why}.",
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
        done: set[int] = set()  # ids of nodes already analysed
        for block, where in (("env", "env var"), ("headers", "header")):
            container = entry.node.get(block)
            if container is None:
                continue
            for key, _kn, vn in container.items():
                if vn.is_str:
                    done.add(id(vn))
                    yield from _secret_findings(vn, key, entry.name, where)
        for launch in _launches(entry):
            tokens = list(launch.assigns) + launch.args
            for idx, a in enumerate(tokens):
                if not launch.via:
                    done.add(id(a))
                prev = tokens[idx - 1].value if idx else ""
                kv = re.match(r"^(--?[A-Za-z][\w\-]*|[A-Za-z_][A-Za-z0-9_]*)=(.+)$", a.value)
                if kv and (kv.group(1).startswith("-") or prev in ("-e", "--env")
                           or (launch.via and a in launch.assigns)):
                    # --api-key=VALUE, `docker run -e TOKEN=VALUE`, or `TOKEN=VALUE cmd` in a wrapper
                    yield from _secret_findings(a, kv.group(1).lstrip("-"), entry.name, "argument", kv.start(2))
                    continue
                for label, b, e in _known_secrets(a):
                    yield _finding("GK02", Severity.CRITICAL, a,
                                   f"{label} passed in plain text as a command-line argument of server "
                                   f"'{entry.name}'{launch.via}.",
                                   begin=b, end=e, server=entry.name, sensitive=True)
                    break
        url = entry.node.get("url")
        if url is not None and url.is_str:
            done.add(id(url))
            known = list(_known_secrets(url))
            for label, b, e in known:
                yield _finding("GK02", Severity.CRITICAL, url,
                               f"{label} embedded in the URL of server '{entry.name}'.",
                               begin=b, end=e, server=entry.name, sensitive=True)
            parts = urlsplit(url.value) if "://" in url.value else None
            if parts is not None and parts.password and not _is_placeholder(parts.password):
                b = url.value.find(parts.password, url.value.find("://") + 3)
                yield _finding("GK02", Severity.HIGH, url,
                               f"Password embedded in the URL of server '{entry.name}'.",
                               begin=b, end=b + len(parts.password), server=entry.name, sensitive=True)
            for m in _URL_CRED_PARAM.finditer(url.value):
                if any(b < m.end(1) and m.start(1) < e for _l, b, e in known):
                    continue  # already reported as a known key format
                if not _is_placeholder(m.group(1)):
                    yield _finding("GK02", Severity.HIGH, url,
                                   f"Credential-like query parameter in the URL of server '{entry.name}'.",
                                   begin=m.start(1), end=m.end(1), server=entry.name, sensitive=True)
        # Fail-closed sweep: a key-shaped secret anywhere else in the entry (including
        # malformed shapes such as an env *array*) is still reported.
        for sn in entry.node.strings():
            if id(sn) in done:
                continue
            for label, b, e in _known_secrets(sn):
                yield _finding("GK02", Severity.CRITICAL, sn,
                               f"{label} stored in plain text in server '{entry.name}' ({sn.path}).",
                               begin=b, end=e, server=entry.name, sensitive=True)
                break


# ---------------------------------------------------------------------------
# GK03 insecure transport
# ---------------------------------------------------------------------------

_PRIVATE_SUFFIXES = (".internal", ".local", ".corp", ".lan", ".intranet", ".home.arpa", ".private", ".localdomain")
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
        if "." not in host or host.endswith(_PRIVATE_SUFFIXES):
            return "private"  # single-label or internal-only DNS name
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
        for launch in _launches(entry):  # includes commands inside shell wrappers
            if launch.via and launch.cmd is not None:
                candidates.append(launch.cmd)
            candidates.extend(launch.args)
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


_INVISIBLE_RUN = re.compile("[" + "".join(f"{chr(lo)}-{chr(hi)}" for lo, hi in _INVISIBLE_RANGES) + "]+")


def _is_invisible(ch: str) -> bool:
    o = ord(ch)
    return any(lo <= o <= hi for lo, hi in _INVISIBLE_RANGES)


def _flex(phrase: str) -> str:
    return phrase.replace(" ", r"\s+")


_VERBS_CONCEAL = r"(?:tell|inform|mention|reveal|show|disclose|notify|alert|warn|say)"
_INJECTION_PATTERNS: list[tuple[Severity, str, re.Pattern]] = [
    (Severity.HIGH, "instruction-override phrase", re.compile(_flex(
        r"(?:ignore|disregard|forget|override) (?:all |any |the )?(?:previous|prior|above|earlier|preceding|"
        r"system|other) (?:instructions?|prompts?|messages?|rules|directions|guidelines)"), re.I)),
    (Severity.HIGH, "instruction-override phrase", re.compile(_flex(
        r"(?:ignore|disregard|forget|override|discard|bypass) (?:(?:all|any|the|your|my|these|those) )*"
        r"(?:\w+ ){0,2}?(?:instructions?|guidance|guidelines|rules|directions|prompts?|directives|context) "
        r"(?:you (?:were|have been|got) (?:given|told|provided)|(?:given|provided|received) "
        r"(?:to you |earlier|before|previously|above)|from (?:before|earlier|the system))"), re.I)),
    (Severity.HIGH, "instruction-override phrase", re.compile(_flex(
        r"(?:ignore|disregard|forget) (?:everything|anything|all) (?:above|before|previously|you were told|"
        r"you have been told)"), re.I)),
    (Severity.HIGH, "instruction-override phrase", re.compile(_flex(
        r"(?:follow|obey) only (?:this|these|my|the following) (?:description|instructions?|rules|text)"), re.I)),
    (Severity.HIGH, "concealment-from-user phrase", re.compile(_flex(
        r"(?:do not|don't|dont|never|must not|should not|shouldn't) " + _VERBS_CONCEAL +
        r"\b(?: \w+){0,3}? (?:to |with )?the user"), re.I)),
    (Severity.HIGH, "concealment-from-user phrase", re.compile(_flex(
        r"without (?:telling|informing|notifying|alerting|asking|warning) the user"), re.I)),
    (Severity.HIGH, "concealment-from-user phrase", re.compile(_flex(
        r"(?:keep (?:this|it|that) (?:secret|hidden|private) from the user|"
        r"the user (?:must|should) (?:not|never) (?:know|see|find out|be told))"), re.I)),
    (Severity.MEDIUM, "silent-action phrase", re.compile(_flex(
        r"(?:(?:runs?|happens?|executes?|proceeds?|works?|do (?:this|it)) silently|"
        r"(?:needs|requires) no (?:user )?(?:confirmation|approval|consent)|"
        r"without (?:any )?(?:user )?(?:confirmation|approval|consent))"), re.I)),
    (Severity.HIGH, "exfiltration phrase", re.compile(_flex(
        r"(?:forward|send|upload|post|transmit|exfiltrate|leak|share|copy|email|relay|mirror) "
        r"(?:\w+ ){0,3}?(?:conversation|chat history|chat log|transcript|message history|system prompt|"
        r"(?:all|every|each) (?:user )?messages?)"), re.I)),
    (Severity.HIGH, "exfiltration phrase", re.compile(_flex(
        r"(?:forward|send|upload|post|transmit|exfiltrate|leak|share|email|paste|include|append|attach) "
        r"(?:(?:the|your|their|user'?s?|all|any|its|his|her) )+(?:\w+ ){0,2}?"
        r"(?:api keys?|access keys?|tokens?|credentials|passwords?|secrets?|private keys?|session cookies?)\b"),
        re.I)),
    (Severity.HIGH, "exfiltration phrase", re.compile(_flex(
        r"(?:copy|forward|send|include|paste|append|attach|put|dump|log|record|store) (?:all (?:of )?)?(?:the )?"
        r"(?:user's|users'|user|their|your) (?:\w+ ){0,2}?(?:messages?|conversation|chat|prompts?|inputs?|"
        r"history|queries)"), re.I)),
    (Severity.HIGH, "exfiltration phrase", re.compile(_flex(
        r"(?:include|put|copy|paste|append|embed|place) (?:the |this |full |entire |whole |complete )*"
        r"(?:conversation|chat|transcript|message history|chat history) (?:in|into) (?:the |a |this )?"
        r"(?:\w+ )?(?:notes?|field|parameter|argument|payload)"), re.I)),
    (Severity.HIGH, "concealment-from-user phrase", re.compile(_flex(
        r"keep (?:this|it|that)(?: \w+){0,2}? between (?:us|you and me|ourselves)"), re.I)),
    (Severity.HIGH, "concealment-from-user phrase", re.compile(_flex(
        r"(?:do not|don't|dont|never) (?:surface|mention|reveal|disclose|expose) (?:this|it|that|these|"
        r"this step|the step|this call|the call) (?:\w+ )?(?:in|to) (?:the|your) (?:answer|response|reply|"
        r"output|user)"), re.I)),
    (Severity.HIGH, "sensitive-file reference", re.compile(
        r"~/\.ssh|[\\/]\.ssh[\\/]|\bid_rsa\b|\bid_ed25519\b|\bid_ecdsa\b|\.aws[\\/]credentials|\.netrc\b|"
        r"/etc/(?:passwd|shadow)\b|\.npmrc\b|\.pypirc\b|\.docker[\\/]config\.json|\.kube[\\/]config|"
        r"claude_desktop_config\.json|(?<![\w-])\.mcp\.json|\.claude\.json|\.claude[\\/]settings(?:\.local)?\.json|"
        r"\.cursor[\\/]mcp\.json|\.vscode[\\/]mcp\.json|windsurf[\\/]mcp_config\.json|\.continue[\\/]config\.",
        re.I)),
    (Severity.HIGH, "role-reassignment phrase", re.compile(_flex(
        r"(?:you are now|from now on you|new instructions:|act as (?:an? )?(?:admin|root|system))"), re.I)),
    (Severity.MEDIUM, "pseudo-system tag", re.compile(
        r"<\s*/?\s*(?:important|system|instructions?|secret|admin)\s*>", re.I)),
    (Severity.MEDIUM, "pre-call directive", re.compile(_flex(
        r"before (?:using|calling|invoking) this tool,? (?:you )?(?:must|always|first|should)"), re.I)),
]
# Same patterns for the normalised (de-obfuscated) text: whitespace becomes optional,
# because letter-spacing collapse can glue words together.
_FUZZY_PATTERNS = [(label, re.compile(p.pattern.replace(r"\s+", r"\s*"), p.flags))
                   for _sev, label, p in _INJECTION_PATTERNS]

# Homoglyphs that NFKC does not fold (Cyrillic / Greek letters that look Latin).
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "ԁ": "d", "ԛ": "q", "ԝ": "w", "һ": "h", "ӏ": "l", "в": "b", "к": "k", "м": "m", "н": "h", "т": "t",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "ɡ": "g", "ı": "i", "ȷ": "j", "ℓ": "l",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_LEET_ADJ = re.compile(r"[a-z][0-9@$!][a-z]|\b[0-9@$!][a-z]{2}|[a-z]{2}[0-9@$!]\b")
_SPACED_RUN = re.compile(r"(?<![a-z0-9])[a-z0-9]([ .\-_*·•/|])[a-z0-9](?:\1[a-z0-9])+(?![a-z0-9])")


_TEXT_ESCAPE = re.compile(
    r"&#(\d{1,7});|&#[xX]([0-9a-fA-F]{1,6});|&(amp|lt|gt|quot|apos|nbsp);|\\x([0-9a-fA-F]{2})|"
    r"\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})")
_NAMED_ENTITIES = {"amp": "&", "lt": "<", "gt": ">", "quot": '"', "apos": "'", "nbsp": " "}


def _decode_escape(m: re.Match) -> Optional[str]:
    if m.group(3):
        return _NAMED_ENTITIES[m.group(3)]
    num = m.group(1)
    code = int(num) if num else int(next(g for g in m.groups()[1:] if g and g not in _NAMED_ENTITIES), 16)
    return chr(code) if 0 < code <= 0x10FFFF and not 0xD800 <= code <= 0xDFFF else None


def _normalise(text: str) -> tuple[str, list[int], list[int]]:
    """De-obfuscate ``text`` for matching.

    Returns ``(normalised, starts, ends)``: normalised character ``k`` came from
    ``text[starts[k]:ends[k]]``, so a match can be mapped back to raw text.
    Steps: decode textual escapes (HTML entities, ``\x69``, ``i``), NFKC
    folding (fullwidth, ligatures), homoglyph folding, lowercase, leetspeak,
    removal of invisible / combining / emoji-and-symbol characters, and collapse
    of letter-spaced runs ("i g n o r e", "i.g.n.o.r.e").
    """
    units: list[tuple[str, int, int]] = []  # (char, raw start, raw end) after escape decoding
    pos = 0
    has_escape = "&" in text or "\\" in text
    for m in (_TEXT_ESCAPE.finditer(text) if has_escape else ()):
        units.extend((ch, i, i + 1) for i, ch in enumerate(text[pos:m.start()], pos))
        dec = _decode_escape(m)
        if dec is None:
            units.extend((ch, i, i + 1) for i, ch in enumerate(m.group(0), m.start()))
        else:
            units.append((dec, m.start(), m.end()))
        pos = m.end()
    units.extend((ch, i, i + 1) for i, ch in enumerate(text[pos:], pos))

    chars: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    for ch, b, e in units:
        if ch < "\x80":
            chars.append(ch.lower().translate(_LEET))
            starts.append(b)
            ends.append(e)
            continue
        if _is_invisible(ch) or unicodedata.category(ch) in ("So", "Sk", "Cs"):
            continue  # zero-width / bidi / emoji / symbol: never part of a word
        for c in unicodedata.normalize("NFKC", ch).lower().translate(_CONFUSABLES):
            if unicodedata.category(c) in ("Mn", "Me", "So", "Sk"):
                continue
            chars.append(c.translate(_LEET))
            starts.append(b)
            ends.append(e)
    norm = "".join(chars)
    drop: set[int] = set()
    for m in _SPACED_RUN.finditer(norm):
        drop.update(k for k in range(m.start() + 1, m.end(), 2))
    if drop:
        keep = [k for k in range(len(norm)) if k not in drop]
        norm = "".join(norm[k] for k in keep)
        starts = [starts[k] for k in keep]
        ends = [ends[k] for k in keep]
    return norm, starts, ends


def _folded_chars(raw: str) -> str:
    """Describe the non-ASCII characters in ``raw`` (what the fold had to undo)."""
    names: list[str] = []
    for c in raw:
        if c >= "\x80" and not _is_invisible(c):
            label = f"U+{ord(c):04X} {unicodedata.name(c, 'UNNAMED')}"
            if label not in names:
                names.append(label)
    if not names:
        return ""
    return "; confusable characters: " + ", ".join(names[:4]) + (", ..." if len(names) > 4 else "")


# Blobs of 24+ characters are considered; 24-39 only when they decode to text and sit
# beside decode/follow language, so ordinary identifiers do not trip the check.
_B64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=_-])[A-Za-z0-9+/]{20,}={0,2}(?![A-Za-z0-9+/=_-])")
_B64_SHORT = 24
_B64_LONG = 40
_DECODE_LANGUAGE = re.compile(
    r"(?i)\b(?:decod\w*|base\s*64|follow\s+(?:the|these|it|them|its)|execute|eval\w*|run\s+(?:it|the|this)|"
    r"instructions?)\b")


def _decode_b64_text(blob: str) -> Optional[str]:
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    if not text or sum(ch.isprintable() or ch in "\r\n\t" for ch in text) < 0.95 * len(text):
        return None
    return text


def _injection_labels(text: str) -> list[str]:
    labels = []
    for _sev, label, pat in _INJECTION_PATTERNS:
        if pat.search(text) and label not in labels:
            labels.append(label)
    return labels


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
    name_nodes: set[int] = set()
    for t in doc.tools:
        for n in t.node.walk():
            tool_of[id(n)] = t.name
        name = t.node.get("name") if t.node.kind == "object" else None
        if name is not None and name.is_str:
            name_nodes.add(id(name))
    for node in doc.root.strings():
        is_name = id(node) in name_nodes
        # Tool names are identifiers: read "ignore_previous_instructions" as words.
        # The substitution is 1:1, so match offsets still index the raw value.
        text = re.sub(r"[_\-.]", " ", node.value) if is_name else node.value
        tool = tool_of.get(id(node))
        where = (f"tool name '{tool}'" if is_name else f"tool '{tool}'") if tool else "manifest"
        for m in _INVISIBLE_RUN.finditer(text):
            yield _finding("GK04", Severity.CRITICAL, node,
                           f"Hidden unicode in {where}: {_describe_invisible(m.group(0))}.",
                           begin=m.start(), end=m.end(), tool=tool)
        for m in _HTML_COMMENT.finditer(text):
            yield _finding("GK04", Severity.HIGH, node,
                           f"Hidden HTML comment in {where}; models read it, users usually do not see it.",
                           begin=m.start(), end=m.end(), tool=tool)
        strict: list[tuple[int, int]] = []
        for sev, label, pat in _INJECTION_PATTERNS:
            for m in pat.finditer(text):
                strict.append((m.start(), m.end()))
                yield _finding("GK04", sev, node, f"Prompt-injection {label} in {where}.",
                               begin=m.start(), end=m.end(), tool=tool)
        yield from _encoded_payloads(node, text, where, tool)
        yield from _obfuscated(node, text, where, tool, strict, force=is_name)


def _encoded_payloads(node: Node, text: str, where: str, tool: Optional[str]) -> Iterator[Finding]:
    for m in _B64_BLOB.finditer(text):
        blob = m.group(0)
        decoded = _decode_b64_text(blob)
        labels = _injection_labels(decoded) if decoded else []
        if not labels and decoded:
            norm = _normalise(decoded)[0]
            labels = [lbl for lbl, pat in _FUZZY_PATTERNS if pat.search(norm)]
        window = text[max(0, m.start() - 160):m.start()] + " " + text[m.end():m.end() + 160]
        near = bool(_DECODE_LANGUAGE.search(window))
        if len(blob) < _B64_SHORT or (len(blob) < _B64_LONG and not (decoded and near)):
            continue
        if not decoded and not re.search(r"[0-9+/=]", blob):
            continue  # a long run of letters only (an identifier), not an encoding
        if labels:
            preview = decoded if len(decoded) <= 80 else decoded[:77] + "..."
            yield _finding("GK04", Severity.HIGH, node,
                           f"Base64 payload in {where} decodes to injection text ({', '.join(labels)}): "
                           f"{preview!r}.", begin=m.start(), end=m.end(), tool=tool)
        elif near:
            yield _finding("GK04R", Severity.MEDIUM, node,
                           f"Encoded blob in {where} next to decode/follow/execute language; "
                           f"review what it decodes to before connecting.",
                           begin=m.start(), end=m.end(), tool=tool)


def _obfuscated(node: Node, text: str, where: str, tool: Optional[str],
                strict: list[tuple[int, int]], force: bool = False) -> Iterator[Finding]:
    if text.isascii() and not force:
        low = text.lower()
        if (not _LEET_ADJ.search(low) and not _SPACED_RUN.search(low)
                and not (("&" in low or "\\" in low) and _TEXT_ESCAPE.search(text))):
            return  # plain ASCII with nothing to de-obfuscate: the strict pass covered it
    norm, starts, ends = _normalise(text)
    if norm == text.lower() and not force:
        return
    for label, pat in _FUZZY_PATTERNS:
        for m in pat.finditer(norm):
            if m.end() <= m.start():
                continue
            b, e = starts[m.start()], ends[m.end() - 1]
            if any(sb < e and b < se for sb, se in strict):
                continue
            strict.append((b, e))
            yield _finding("GK04R", Severity.MEDIUM, node,
                           f"Possible obfuscated {label} in {where}: reads as {m.group(0)!r} after "
                           f"escape/unicode/homoglyph/spacing/leetspeak normalisation"
                           f"{_folded_chars(text[b:e])}. Review before connecting.",
                           begin=b, end=e, tool=tool)


RULES.append(Rule("GK04R", "Possible obfuscated injection (review)", "tool_manifest", (Severity.MEDIUM,),
                  "Text that matches an injection pattern only after de-obfuscation (fullwidth, homoglyphs, "
                  "letter-spacing, leetspeak), or an encoded blob beside decode/follow language. The gate may be "
                  "wrong about intent, so it asks for review instead of staying silent.",
                  "Read the flagged text as the model would; if the obfuscation has no innocent explanation, "
                  "treat it as GK04.", lambda doc: ()))


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


def _fold_name(name: str) -> str:
    """NFKC + homoglyph fold a tool name, keeping case and separators (no leetspeak)."""
    out = []
    for ch in name:
        if ch < "\x80":
            out.append(ch)
        elif not _is_invisible(ch):
            out.extend(c for c in unicodedata.normalize("NFKC", ch).translate(_CONFUSABLES)
                       if unicodedata.category(c) != "Mn")
    return "".join(out)


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
_HOME_PATH = re.compile(
    r"^(?:~|~/|~[A-Za-z0-9._-]+/?|\$HOME/?|\$\{HOME\}/?|\$\{userHome\}/?|%USERPROFILE%\\?|%HOMEPATH%\\?"
    r"|/home/?|/Users/?|/root/?|/var/root/?|/home/[^/\\]+/?|/Users/[^/\\]+/?"
    r"|[A-Za-z]:[\\/](?:Users|Documents and Settings)(?:[\\/][^/\\]+)?[\\/]?)$",
    re.I,
)


@rule("GK05", "Over-privileged tool surface", "client_config", (Severity.MEDIUM, Severity.HIGH),
      "Filesystem access rooted at '/' (or a drive root / whole home directory), privileged containers, "
      "host-root or docker.sock mounts.",
      "Scope filesystem servers to the specific project directories they need; drop --privileged and "
      "host-root mounts.")
def check_gk05_config(doc: SourceDoc) -> Iterator[Finding]:
    for entry in doc.servers:
        for launch in _launches(entry):
            yield from _gk05_launch(entry, launch)


def _gk05_launch(entry: Entry, launch: _Launch) -> Iterator[Finding]:
    eco, _rest = _launcher(launch.cmd, launch.args)
    for a in launch.args:
        v = a.value
        if _ROOT_PATH.match(v):
            yield _finding("GK05", Severity.HIGH, a,
                           f"Server '{entry.name}' is granted the filesystem root '{v}'.", server=entry.name)
        elif _HOME_PATH.match(v) and not v.lower().rstrip("/\\").endswith(("/shared", "\\public", "/guest")):
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
            continue
        folded = _fold_name(name.value)
        hit = _dangerous_tool(folded) if folded != name.value else None
        if hit:
            yield _finding("GK05", Severity.HIGH, name,
                           f"Tool '{name.value}' reads as '{folded}' after homoglyph/NFKC folding and exposes "
                           f"arbitrary command/code execution ('{hit}'){_folded_chars(name.value)}.",
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
            hidden = _INVISIBLE_RUN.search(node.value)
            if hidden:
                yield _finding("GK06", Severity.CRITICAL, node,
                               f"Hidden unicode in the launch command of server '{entry.name}' "
                               f"({_describe_invisible(hidden.group(0))}).",
                               begin=hidden.start(), end=hidden.end(), server=entry.name)
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
