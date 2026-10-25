"""Turn findings into console, JSON and Markdown reports."""
import json
from collections import Counter
from .models import SEVERITY_ORDER

COLORS = {"CRITICAL": "\033[95m", "HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[94m"}
RESET = "\033[0m"


def sort_findings(findings):
    return sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.check_id, f.resource))


def summary(findings):
    counts = Counter(f.severity for f in findings)
    return {s: counts.get(s, 0) for s in SEVERITY_ORDER}


def to_console(findings, color=True):
    lines = []
    for f in sort_findings(findings):
        tag = f"[{f.severity}]"
        tag = f"{COLORS[f.severity]}{tag}{RESET}" if color else tag
        lines.append(f"{tag} {f.check_id} {f.resource}\n    {f.title}\n    Fix: {f.remediation}")
    s = summary(findings)
    lines.append("\nSummary: " + ", ".join(f"{k}={v}" for k, v in s.items()) + f"  (total {len(findings)})")
    return "\n".join(lines)


def to_json(findings, meta=None):
    return json.dumps({"meta": meta or {}, "summary": summary(findings),
                       "findings": [f.to_dict() for f in sort_findings(findings)]}, indent=2)


def to_markdown(findings, meta=None):
    meta = meta or {}
    out = ["# Cloud Security Misconfiguration Report", ""]
    for k, v in meta.items():
        out.append(f"- **{k}**: {v}")
    out += ["", "## Summary", "", "| Severity | Count |", "|---|---|"]
    out += [f"| {k} | {v} |" for k, v in summary(findings).items()]
    out += ["", "## Findings", ""]
    for f in sort_findings(findings):
        out += [f"### [{f.severity}] {f.check_id} - {f.title}", "",
                f"- **Category:** {f.category}", f"- **Resource:** `{f.resource}`",
                f"- **Why it matters:** {f.description}", f"- **Remediation:** {f.remediation}", ""]
    return "\n".join(out)
