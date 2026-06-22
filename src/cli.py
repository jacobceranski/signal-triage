from __future__ import annotations

import argparse
from collections import Counter

from src.parser import load_events
from src.scoring import PROFILES, get_profile
from src.detections import run_all
from src.report import write_markdown_report, write_json, write_csv


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signal-triage",
        description="SOC-style SSO/VPN authentication log analyzer.",
    )
    parser.add_argument("input", help="Path to auth log input file (.jsonl, .json, or .csv)")
    parser.add_argument(
        "--profile",
        choices=sorted(PROFILES),
        default="balanced",
        help="Detection threshold profile. Default: balanced",
    )
    parser.add_argument("--out", default="report.md", help="Markdown report output path")
    parser.add_argument("--json", default="alerts.json", help="JSON alerts output path")
    parser.add_argument("--csv", default="alerts.csv", help="CSV alerts output path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    profile = get_profile(args.profile)
    events = load_events(args.input)
    alerts = run_all(events, profile)

    write_markdown_report(args.out, alerts, profile_name=profile.name)
    write_json(args.json, alerts)
    write_csv(args.csv, alerts)

    severity_counts = Counter(alert.severity for alert in alerts)
    print("Signal Triage complete")
    print(f"Events loaded: {len(events)}")
    print(f"Alerts generated: {len(alerts)}")
    if alerts:
        print("Severity summary:")
        for severity in ("critical", "high", "medium", "low"):
            print(f"  {severity}: {severity_counts.get(severity, 0)}")
    print(f"Markdown report: {args.out}")
    print(f"JSON alerts: {args.json}")
    print(f"CSV alerts: {args.csv}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
