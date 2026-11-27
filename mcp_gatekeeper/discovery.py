"""Config discovery and location-preserving parsing.

The stdlib ``json`` module discards source positions, so this module carries a
small JSON parser that keeps raw offsets for every value. It accepts the JSONC
dialect VS Code uses for ``settings.json`` (``//`` and ``/* */`` comments,
trailing commas). YAML tool manifests are parsed with PyYAML's composer, which
also exposes node positions.

Discovery then classifies each parsed file as an MCP client config or a server
tool manifest and extracts the server / tool entries the rules run over.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Optional

import yaml

from .models import Entry, Node, SourceDoc, child_path

MAX_FILE_BYTES = 5 * 1024 * 1024
SCAN_EXTENSIONS = (".json", ".jsonc", ".yaml", ".yml")
PRUNE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
}
# File names that are MCP configs by convention. A parse failure on one of
# these is reported as an error; on any other file found while walking a
# directory it is silently skipped.
WELL_KNOWN_NAMES = {"claude_desktop_config.json", ".mcp.json", "mcp.json", "settings.json"}


class ParseError(Exception):
    def __init__(self, message: str, line: int = 0, column: int = 0):
        super().__init__(message)
        self.message = message
        self.line = line
        self.column = column

    def __str__(self) -> str:
        if self.line:
            return f"{self.message} (line {self.line}, column {self.column})"
        return self.message


# ---------------------------------------------------------------------------
# JSON / JSONC parser with offsets
# ---------------------------------------------------------------------------

_ESCAPES = {'"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t"}
_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_MAX_DEPTH = 200
# Upper bound on nodes produced when expanding YAML anchors/aliases. Aliases
# are re-expanded at every use, so nested aliases ("billion laughs") grow
# exponentially; anything past this cap is rejected rather than walked.
MAX_YAML_NODES = 100_000


class _JsonParser:
    def __init__(self, doc: SourceDoc):
        self.doc = doc
        self.t = doc.text
        self.n = len(self.t)
        self.i = 0

    def error(self, msg: str, at: Optional[int] = None) -> ParseError:
        line, col = self.doc.line_col(min(self.i if at is None else at, max(self.n - 1, 0)))
        return ParseError(msg, line, col)

    def parse(self) -> Node:
        if self.t.startswith("﻿"):
            self.i = 1
        self.ws()
        if self.i >= self.n:
            raise self.error("empty document")
        node = self.value("$", 0)
        self.ws()
        if self.i != self.n:
            raise self.error("unexpected trailing content")
        return node

    def ws(self) -> None:
        t, n = self.t, self.n
        while self.i < n:
            c = t[self.i]
            if c in " \t\r\n":
                self.i += 1
            elif t.startswith("//", self.i):
                nl = t.find("\n", self.i)
                self.i = n if nl == -1 else nl + 1
            elif t.startswith("/*", self.i):
                close = t.find("*/", self.i + 2)
                if close == -1:
                    raise self.error("unterminated block comment")
                self.i = close + 2
            else:
                break

    def value(self, path: str, depth: int) -> Node:
        if depth > _MAX_DEPTH:
            raise self.error("document nested too deeply")
        if self.i >= self.n:
            raise self.error("unexpected end of document")
        c = self.t[self.i]
        if c == "{":
            return self.obj(path, depth)
        if c == "[":
            return self.arr(path, depth)
        if c == '"':
            return self.string(path)
        if c == "-" or c.isdigit():
            m = _NUMBER.match(self.t, self.i)
            if not m:
                raise self.error("invalid number")
            start, self.i = self.i, m.end()
            raw = m.group(0)
            num = float(raw) if any(ch in raw for ch in ".eE") else int(raw)
            return Node("number", num, path, self.doc, start, self.i)
        for word, kind, val in (("true", "bool", True), ("false", "bool", False), ("null", "null", None)):
            if self.t.startswith(word, self.i):
                start = self.i
                self.i += len(word)
                return Node(kind, val, path, self.doc, start, self.i)
        raise self.error(f"unexpected character {c!r}")

    def obj(self, path: str, depth: int) -> Node:
        start = self.i
        self.i += 1
        items: list = []
        while True:
            self.ws()
            if self.i >= self.n:
                raise self.error("unterminated object", start)
            if self.t[self.i] == "}":
                break
            if self.t[self.i] != '"':
                raise self.error("expected string key")
            key_node = self.string(path)
            key = key_node.value
            self.ws()
            if self.i >= self.n or self.t[self.i] != ":":
                raise self.error("expected ':' after key")
            self.i += 1
            self.ws()
            val = self.value(child_path(path, key), depth + 1)
            items.append((key, key_node, val))
            self.ws()
            if self.i < self.n and self.t[self.i] == ",":
                self.i += 1
                continue
            if self.i < self.n and self.t[self.i] == "}":
                break
            raise self.error("expected ',' or '}' in object")
        self.i += 1
        return Node("object", items, path, self.doc, start, self.i)

    def arr(self, path: str, depth: int) -> Node:
        start = self.i
        self.i += 1
        elems: list = []
        while True:
            self.ws()
            if self.i >= self.n:
                raise self.error("unterminated array", start)
            if self.t[self.i] == "]":
                break
            elems.append(self.value(child_path(path, len(elems)), depth + 1))
            self.ws()
            if self.i < self.n and self.t[self.i] == ",":
                self.i += 1
                continue
            if self.i < self.n and self.t[self.i] == "]":
                break
            raise self.error("expected ',' or ']' in array")
        self.i += 1
        return Node("array", elems, path, self.doc, start, self.i)

    def string(self, path: str) -> Node:
        t, n = self.t, self.n
        start = self.i
        self.i += 1
        chars: list[str] = []
        offs: list[int] = []
        while True:
            if self.i >= n:
                raise self.error("unterminated string", start)
            c = t[self.i]
            if c == '"':
                offs.append(self.i)
                self.i += 1
                break
            if c == "\\":
                if self.i + 1 >= n:
                    raise self.error("unterminated escape")
                e = t[self.i + 1]
                if e in _ESCAPES:
                    chars.append(_ESCAPES[e])
                    offs.append(self.i)
                    self.i += 2
                elif e == "u":
                    code = self._hex4(self.i + 2)
                    j = self.i + 6
                    if 0xD800 <= code < 0xDC00 and t.startswith("\\u", j):
                        low = self._hex4(j + 2)
                        if 0xDC00 <= low < 0xE000:
                            code = 0x10000 + ((code - 0xD800) << 10) + (low - 0xDC00)
                            j += 6
                    chars.append(chr(code))
                    offs.append(self.i)
                    self.i = j
                else:
                    raise self.error(f"invalid escape \\{e}")
            elif c == "\n" or (ord(c) < 0x20 and c != "\t"):
                raise self.error("control character in string")
            else:
                chars.append(c)
                offs.append(self.i)
                self.i += 1
        return Node("string", "".join(chars), path, self.doc, start, self.i, offsets=offs)

    def _hex4(self, at: int) -> int:
        h = self.t[at:at + 4]
        if len(h) != 4 or not all(ch in "0123456789abcdefABCDEF" for ch in h):
            raise self.error("invalid \\u escape", at)
        return int(h, 16)


def parse_json(doc: SourceDoc) -> Node:
    return _JsonParser(doc).parse()


# ---------------------------------------------------------------------------
# YAML (PyYAML composer keeps marks)
# ---------------------------------------------------------------------------

def parse_yaml(doc: SourceDoc) -> Node:
    try:
        root = yaml.compose(doc.text, Loader=yaml.SafeLoader)
    except RecursionError:
        raise ParseError("document nested too deeply") from None
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        if mark is not None:
            raise ParseError(str(getattr(exc, "problem", exc)), mark.line + 1, mark.column + 1) from None
        raise ParseError(str(exc)) from None
    if root is None:
        raise ParseError("empty document")
    constructor = yaml.SafeLoader("")
    budget = [MAX_YAML_NODES]

    def conv(yn, path: str, depth: int) -> Node:
        if depth > _MAX_DEPTH:
            raise ParseError("document nested too deeply")
        budget[0] -= 1
        if budget[0] < 0:
            raise ParseError(f"YAML alias expansion too large (more than {MAX_YAML_NODES} nodes)")
        s, e = yn.start_mark.index, yn.end_mark.index
        if isinstance(yn, yaml.MappingNode):
            items = []
            for kn, vn in yn.value:
                key = str(kn.value)
                key_node = Node("string", key, path, doc, kn.start_mark.index, kn.end_mark.index)
                items.append((key, key_node, conv(vn, child_path(path, key), depth + 1)))
            return Node("object", items, path, doc, s, e)
        if isinstance(yn, yaml.SequenceNode):
            return Node("array", [conv(v, child_path(path, i), depth + 1) for i, v in enumerate(yn.value)],
                        path, doc, s, e)
        if yn.tag == "tag:yaml.org,2002:str":
            return Node("string", yn.value, path, doc, s, e)
        val = constructor.construct_object(yn)
        kind = "null" if val is None else "bool" if isinstance(val, bool) else \
            "number" if isinstance(val, (int, float)) else "string"
        if kind == "string":
            val = str(val)
        return Node(kind, val, path, doc, s, e)

    try:
        return conv(root, "$", 0)
    except RecursionError:
        raise ParseError("document nested too deeply") from None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

_SERVER_KEYS = {"command", "url", "type", "transport", "args"}


def _looks_like_server(node: Node) -> bool:
    return node.kind == "object" and any(k in _SERVER_KEYS for k, _kn, _vn in node.items())


def _entries(container: Node) -> list[Entry]:
    return [Entry(k, vn) for k, _kn, vn in container.items() if vn.kind == "object"]


def _tool_entries(arr: Node) -> list[Entry]:
    out = []
    for el in arr.elements():
        if el.kind == "object":
            name = el.get("name")
            out.append(Entry(name.value if name is not None and name.is_str else "", el))
    return out


def classify(doc: SourceDoc) -> bool:
    """Fill ``doc.kind``/``flavor``/``servers``/``tools``. Returns False if unrecognised."""
    root = doc.root
    base = os.path.basename(doc.path)
    if root is None:
        return False
    if root.kind == "object":
        servers = root.get("mcpServers")
        if servers is not None and servers.kind == "object":
            doc.kind = "client_config"
            doc.flavor = {"claude_desktop_config.json": "claude_desktop", ".mcp.json": "mcp_json"}.get(
                base, "mcp_servers")
            doc.servers = _entries(servers)
            return True
        mcp = root.get("mcp")
        if mcp is not None and mcp.kind == "object":
            vs = mcp.get("servers")
            if vs is not None and vs.kind == "object":
                doc.kind, doc.flavor = "client_config", "vscode_settings"
                doc.servers = _entries(vs)
                return True
        vs = root.get("servers")
        if vs is not None and vs.kind == "object":
            entries = _entries(vs)
            if base == "mcp.json" or (entries and all(_looks_like_server(e.node) for e in entries)):
                doc.kind, doc.flavor = "client_config", "vscode_mcp"
                doc.servers = entries
                return True
        tools = root.get("tools")
        if tools is None:
            result = root.get("result")
            if result is not None and result.kind == "object":
                tools = result.get("tools")
        if tools is not None and tools.kind == "array":
            doc.kind, doc.flavor = "tool_manifest", "tool_manifest"
            doc.tools = _tool_entries(tools)
            return True
    if root.kind == "array" and root.value and all(
        el.kind == "object" and el.get("name") is not None
        and (el.get("description") is not None or el.get("inputSchema") is not None)
        for el in root.elements()
    ):
        doc.kind, doc.flavor = "tool_manifest", "tool_manifest"
        doc.tools = _tool_entries(root)
        return True
    return False


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------

@dataclass
class DiscoveryResult:
    docs: list[SourceDoc] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)
    skipped: list[dict] = field(default_factory=list)


def load_file(path: str) -> SourceDoc:
    """Read and parse one file. Raises ParseError / OSError."""
    size = os.path.getsize(path)
    if size > MAX_FILE_BYTES:
        raise ParseError(f"file larger than {MAX_FILE_BYTES} bytes")
    with open(path, "rb") as fh:
        data = fh.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ParseError(f"not valid UTF-8: {exc}") from None
    text = text.replace("\r\n", "\n")
    syntax = "yaml" if path.lower().endswith((".yaml", ".yml")) else "json"
    doc = SourceDoc(path=path, text=text, syntax=syntax)
    doc.root = parse_yaml(doc) if syntax == "yaml" else parse_json(doc)
    return doc


def _iter_dir(root: str):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in PRUNE_DIRS)
        for name in sorted(filenames):
            if name.lower().endswith(SCAN_EXTENSIONS):
                yield os.path.join(dirpath, name), name


def discover(paths: list[str]) -> DiscoveryResult:
    """Resolve CLI paths to parsed, classified documents (deterministic order)."""
    res = DiscoveryResult()
    seen: set[str] = set()

    def handle(path: str, explicit: bool) -> None:
        real = os.path.realpath(path)
        if real in seen:
            return
        seen.add(real)
        name = os.path.basename(path)
        try:
            doc = load_file(path)
        except (ParseError, OSError) as exc:
            if explicit or name in WELL_KNOWN_NAMES:
                res.errors.append({"file": path, "message": str(exc)})
            else:
                res.skipped.append({"file": path, "reason": f"not parseable: {exc}"})
            return
        if classify(doc):
            res.docs.append(doc)
        else:
            res.skipped.append({"file": path, "reason": "no MCP server config or tool manifest found"})

    for p in paths:
        if os.path.isdir(p):
            for fp, _name in _iter_dir(p):
                handle(fp, explicit=False)
        elif os.path.isfile(p):
            handle(p, explicit=True)
        else:
            res.errors.append({"file": p, "message": "path does not exist"})
    return res
