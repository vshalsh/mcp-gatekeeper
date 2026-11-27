"""mcp-gatekeeper: pre-flight security audit for MCP client configs and tool manifests."""

__version__ = "0.1.0"

__all__ = ["__version__", "scan"]


def scan(paths, fail_on="high"):
    """Programmatic entry point: discover, parse and run every rule over ``paths``.

    Returns a :class:`mcp_gatekeeper.report.ScanResult`.
    """
    from .discovery import discover
    from .models import Severity
    from .report import ScanResult
    from .rules import run_rules

    if isinstance(paths, str):
        paths = [paths]
    found = discover(list(paths))
    findings = []
    for doc in found.docs:
        findings.extend(run_rules(doc))
    threshold = None if fail_on in (None, "none") else Severity.parse(fail_on)
    return ScanResult(docs=found.docs, findings=findings, errors=found.errors,
                      skipped=found.skipped, fail_on=threshold)
