"""Core data types: severities, located document nodes, and findings.

Every value parsed out of a scanned file is wrapped in a :class:`Node` that
remembers exactly where it came from (raw character offsets in the source
text). Rules never invent locations; they ask a node to ``locate`` a span of
its decoded value, and the node maps that span back to the raw source text.
That mapping is what makes each finding's provenance verifiable.
"""

from __future__ import annotations

import bisect
import enum
import re
from dataclasses import dataclass, field
from typing import Any, Iterator, Optional


class Severity(enum.IntEnum):
    INFO = 10
    LOW = 20
    MEDIUM = 30
    HIGH = 40
    CRITICAL = 50

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError:
            names = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {text!r} (expected one of: {names})") from None


SEVERITY_LABELS = [s.label for s in Severity]

_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def child_path(parent: str, key: Any) -> str:
    """Build a JSONPath-style child path.

    Identifier-like keys use dot notation (``$.mcpServers.github``); anything
    else uses bracket notation with a JSON-escaped string
    (``$.mcp.servers["my-server"]``). Integers produce ``[n]``.
    """
    if isinstance(key, int):
        return f"{parent}[{key}]"
    key = str(key)
    if _IDENT.match(key):
        return f"{parent}.{key}"
    escaped = key.replace("\\", "\\\\").replace('"', '\\"')
    return f'{parent}["{escaped}"]'


@dataclass(frozen=True)
class Location:
    line: int  # 1-based
    column: int  # 1-based, counted in code points
    text: str  # exact raw source text at that location


@dataclass(eq=False)
class SourceDoc:
    """A scanned file: its path (as given), raw text and parsed root node."""

    path: str
    text: str
    syntax: str  # "json" or "yaml"
    root: Optional["Node"] = None
    kind: str = ""  # "client_config" or "tool_manifest"
    flavor: str = ""  # e.g. "claude_desktop", "mcp_json", "vscode_settings"
    servers: list["Entry"] = field(default_factory=list)
    tools: list["Entry"] = field(default_factory=list)
    containers: list["Node"] = field(default_factory=list)  # mcpServers / servers / tools nodes
    _line_starts: list[int] = field(default_factory=list, repr=False)

    def __post_init__(self) -> None:
        starts = [0]
        for m in re.finditer("\n", self.text):
            starts.append(m.end())
        self._line_starts = starts

    def line_col(self, offset: int) -> tuple[int, int]:
        idx = bisect.bisect_right(self._line_starts, offset) - 1
        return idx + 1, offset - self._line_starts[idx] + 1

    def line_text(self, line: int) -> str:
        start = self._line_starts[line - 1]
        end = self.text.find("\n", start)
        return self.text[start:] if end == -1 else self.text[start:end]


@dataclass(eq=False)
class Node:
    """A parsed value with its source location.

    ``value`` holds the Python scalar for leaf nodes, a list of
    ``(key, key_node, value_node)`` triples for objects (duplicates kept, in
    source order), or a list of nodes for arrays.

    ``offsets`` is only set for JSON strings: ``offsets[i]`` is the raw offset
    of decoded character ``i`` and ``offsets[len(value)]`` is the offset of the
    closing quote. This lets escaped text (``\\u200b``) map back exactly.
    """

    kind: str  # object | array | string | number | bool | null
    value: Any
    path: str
    doc: SourceDoc
    start: int
    end: int
    offsets: Optional[list[int]] = None

    # -- navigation ---------------------------------------------------------
    def get(self, key: str) -> Optional["Node"]:
        if self.kind != "object":
            return None
        found = None
        for k, _kn, vn in self.value:
            if k == key:
                found = vn  # last one wins, matching client behaviour
        return found

    def items(self) -> Iterator[tuple[str, "Node", "Node"]]:
        if self.kind == "object":
            yield from self.value

    def elements(self) -> list["Node"]:
        return list(self.value) if self.kind == "array" else []

    def walk(self) -> Iterator["Node"]:
        yield self
        if self.kind == "object":
            for _k, _kn, vn in self.value:
                yield from vn.walk()
        elif self.kind == "array":
            for el in self.value:
                yield from el.walk()

    def strings(self) -> Iterator["Node"]:
        for n in self.walk():
            if n.kind == "string":
                yield n

    @property
    def is_str(self) -> bool:
        return self.kind == "string"

    def str_value(self) -> Optional[str]:
        return self.value if self.kind == "string" else None

    def string_list(self) -> list["Node"]:
        """Elements of an array that are strings (others are ignored)."""
        return [el for el in self.elements() if el.is_str]

    # -- provenance ---------------------------------------------------------
    def locate(self, begin: int = 0, end: Optional[int] = None) -> Location:
        """Map decoded span ``[begin, end)`` of this node to raw source text."""
        text = self.doc.text
        if self.kind == "string":
            value = self.value
            if end is None:
                end = len(value)
            if self.offsets is not None:
                raw_s = self.offsets[begin]
                raw_e = self.offsets[end]
                if raw_e <= raw_s:  # empty span: point at the whole string
                    raw_s, raw_e = self.offsets[0], self.offsets[-1]
                line, col = self.doc.line_col(raw_s)
                return Location(line, col, text[raw_s:raw_e])
            # YAML scalar: the decoded text normally appears verbatim.
            region = text[self.start:self.end]
            sub = value[begin:end]
            k = region.find(sub) if sub else -1
            if k >= 0:
                raw_s = self.start + k
                line, col = self.doc.line_col(raw_s)
                return Location(line, col, sub)
            # Double-quoted scalar with escapes: look for the escaped spelling.
            for esc in _yaml_escapes(sub):
                k = region.find(esc)
                if k >= 0:
                    line, col = self.doc.line_col(self.start + k)
                    return Location(line, col, esc)
            # Folded scalar spanning lines: fall back to the first raw line of it.
            first = region.split("\n", 1)[0]
            line, col = self.doc.line_col(self.start)
            return Location(line, col, first)
        raw = text[self.start:self.end].split("\n", 1)[0]
        line, col = self.doc.line_col(self.start)
        return Location(line, col, raw)


@dataclass(eq=False)
class Entry:
    """A named MCP server (config) or tool (manifest)."""

    name: str
    node: Node


@dataclass
class Finding:
    rule: str
    severity: Severity
    title: str
    message: str
    file: str
    json_path: str
    line: int
    column: int
    matched_text: str
    remediation: str = ""
    server: Optional[str] = None
    tool: Optional[str] = None
    sensitive: bool = False  # matched_text is (probably) a live secret
    redacted: bool = False
    incomplete: bool = False  # entry could not be verified: the scan is incomplete (exit 2)

    def sort_key(self) -> tuple:
        return (self.file, self.line, self.column, self.rule, self.json_path)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity.label,
            "title": self.title,
            "message": self.message,
            "file": self.file,
            "json_path": self.json_path,
            "line": self.line,
            "column": self.column,
            "matched_text": self.matched_text,
            "redacted": self.redacted,
            "server": self.server,
            "tool": self.tool,
            "remediation": self.remediation,
        }


def _yaml_escapes(sub: str) -> list[str]:
    """Candidate escaped spellings of ``sub`` inside a YAML double-quoted scalar."""
    if not sub or all(0x20 <= ord(c) < 0x7F for c in sub):
        return []
    out = []
    for upper in (False, True):
        parts = []
        for c in sub:
            o = ord(c)
            if 0x20 <= o < 0x7F:
                parts.append(c)
            else:
                code = f"\\x{o:02x}" if o <= 0xFF else f"\\u{o:04x}" if o <= 0xFFFF else f"\\U{o:08x}"
                parts.append(code[:2] + code[2:].upper() if upper else code)
        out.append("".join(parts))
    return out


def redact(text: str) -> str:
    keep = 4 if len(text) > 8 else 0
    return f"{text[:keep]}...[redacted {len(text)} chars]"
