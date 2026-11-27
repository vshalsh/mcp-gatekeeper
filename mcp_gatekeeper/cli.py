"""Command-line interface: ``mcp-gatekeeper scan|rules|schema``."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Optional, Sequence

from . import __version__, scan
from .models import SEVERITY_LABELS
from .report import EXIT_ERROR, render_json, render_text, use_color
from .rules import RULES
from .schema import REPORT_SCHEMA


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mcp-gatekeeper",
        description="Audit MCP client configs and server tool manifests for security issues "
                    "before you connect. Offline and deterministic.",
    )
    p.add_argument("--version", action="version", version=f"mcp-gatekeeper {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")

    s = sub.add_parser("scan", help="scan files or directories")
    s.add_argument("paths", nargs="+", metavar="PATH",
                   help="config file, tool manifest, or directory to walk")
    s.add_argument("--format", choices=["text", "json"], default="text", help="output format (default: text)")
    s.add_argument("--fail-on", choices=["info", "low", "review", "medium", "high", "critical", "none"],
                   default="high",
                   help="exit 1 when any finding is at or above this severity (default: high); "
                        "'review' also blocks review-class findings (GK04R) and is the recommended "
                        "setting for manifest gating in CI")
    s.add_argument("--color", choices=["auto", "always", "never"], default="auto",
                   help="ANSI colour for text output (default: auto = only on a TTY, honours NO_COLOR)")
    s.add_argument("--redact", action="store_true",
                   help="mask secret values in JSON matched_text (text output always masks them)")

    sub.add_parser("rules", help="list the rule pack")
    sub.add_parser("schema", help="print the JSON Schema for --format json output")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    out = sys.stdout

    if args.command == "rules":
        for r in RULES:
            sev = "/".join(s.label for s in r.severities)
            out.write(f"{r.id}  [{r.applies_to}]  {r.title}  ({sev})\n      {r.summary}\n")
        return 0
    if args.command == "schema":
        json.dump(REPORT_SCHEMA, out, indent=2)
        out.write("\n")
        return 0
    if args.command != "scan":
        parser.print_help(sys.stderr)
        return EXIT_ERROR

    result = scan(args.paths, fail_on=args.fail_on)
    try:
        if args.format == "json":
            render_json(result, out, redact_secrets=args.redact)
        else:
            render_text(result, out, color=use_color(args.color, out))
        out.flush()
    except (BrokenPipeError, OSError) as exc:
        # The report could not be delivered (closed pipe, full disk): that is an
        # incomplete run, not a pass. Silence the interpreter's own flush at exit.
        _discard_stdout()
        try:
            sys.stderr.write(f"mcp-gatekeeper: could not write report: {exc.strerror or exc}\n")
        except OSError:
            pass
        return EXIT_ERROR
    return result.exit_code


def _discard_stdout() -> None:
    try:
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
    except (OSError, ValueError, AttributeError):
        pass


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
