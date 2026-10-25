"""Command-line entry point.  Usage:
    python -m scanner --profile myprofile --region ap-south-1 --format markdown -o reports/report.md
    python -m scanner --input sample_data/vulnerable_account.json
"""
import argparse
import json
import sys
from datetime import datetime, timezone

from . import __version__, report
from .checks import ALL_CHECKS

FAIL_ON = {"critical": {"CRITICAL"}, "high": {"CRITICAL", "HIGH"},
           "medium": {"CRITICAL", "HIGH", "MEDIUM"}, "low": {"CRITICAL", "HIGH", "MEDIUM", "LOW"}}


def run_checks(snapshot):
    findings = []
    for module in ALL_CHECKS:
        findings.extend(module.run(snapshot))
    return findings


def main(argv=None):
    p = argparse.ArgumentParser(prog="scanner", description="AWS security misconfiguration scanner (read-only)")
    src = p.add_mutually_exclusive_group()
    src.add_argument("--input", help="scan a saved JSON snapshot instead of calling AWS")
    src.add_argument("--profile", help="AWS CLI profile name (default credentials if omitted)")
    p.add_argument("--region", default="ap-south-1")
    p.add_argument("--format", choices=["console", "json", "markdown"], default="console")
    p.add_argument("-o", "--output", help="write the report to this file")
    p.add_argument("--save-snapshot", help="also save the collected AWS data to this JSON file")
    p.add_argument("--fail-on", choices=list(FAIL_ON), help="exit code 1 if findings at/above this severity exist")
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    if args.input:
        with open(args.input) as f:
            snapshot = json.load(f)
    else:
        from .collectors import aws
        snapshot = aws.collect(args.profile, args.region)
        if args.save_snapshot:
            aws.save_snapshot(snapshot, args.save_snapshot)

    findings = run_checks(snapshot)
    meta = {"Account": snapshot.get("account_id", "unknown"), "Region": snapshot.get("region", "n/a"),
            "Scanned at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"), "Scanner version": __version__}

    if args.format == "json":
        text = report.to_json(findings, meta)
    elif args.format == "markdown":
        text = report.to_markdown(findings, meta)
    else:
        text = report.to_console(findings, color=not args.output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(text)
        print(f"Report written to {args.output}")
        print("Summary: " + ", ".join(f"{k}={v}" for k, v in report.summary(findings).items()))
    else:
        print(text)

    if args.fail_on and any(f.severity in FAIL_ON[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
