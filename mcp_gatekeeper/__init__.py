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
    errors = list(found.errors)
    for doc in found.docs:
        doc_findings = run_rules(doc)
        findings.extend(doc_findings)
        for f in doc_findings:
            if f.incomplete:  # fail closed: an unverifiable entry makes the scan incomplete
                errors.append({"file": f.file, "message": f"could not verify entry at {f.json_path} "
                                                         f"(line {f.line}): unexpected shape ({f.rule})"})
    review = fail_on == "review"
    threshold = None if fail_on in (None, "none") else Severity.MEDIUM if review else Severity.parse(fail_on)
    return ScanResult(docs=found.docs, findings=findings, errors=errors,
                      skipped=found.skipped, fail_on=threshold, fail_on_review=review)
