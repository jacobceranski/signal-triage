from __future__ import annotations

import csv
import json
from collections import Counter
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.detections import Alert


def _alert_dict(alert: Alert) -> dict[str, Any]:
    return asdict(alert)


def write_markdown_report(path: str | Path, alerts: list[Alert], profile_name: str = "balanced") -> None:
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True) if output.parent != Path(".") else None
    severity_counts = Counter(alert.severity for alert in alerts)
    rule_counts = Counter(alert.rule_id for alert in alerts)
    generated = datetime.now(timezone.utc).isoformat(timespec="seconds")

    lines: list[str] = [
        "# Signal Triage Report",
        "",
        f"Generated: {generated}",
        f"Profile: `{profile_name}`",
        "",
        "## Summary",
        "",
        f"- Total alerts: **{len(alerts)}**",
        f"- Critical: {severity_counts.get('critical', 0)}",
        f"- High: {severity_counts.get('high', 0)}",
        f"- Medium: {severity_counts.get('medium', 0)}",
        f"- Low: {severity_counts.get('low', 0)}",
        "",
        "## Alerts by rule",
        "",
    ]
    if rule_counts:
        lines.extend([f"- {rule}: {count}" for rule, count in rule_counts.most_common()])
    else:
        lines.append("- No alerts generated.")

    lines.extend(["", "## Alert details", ""])
    if not alerts:
        lines.append("No suspicious authentication patterns were detected.")
    for index, alert in enumerate(alerts, start=1):
        lines.extend(
            [
                f"### {index}. {alert.title}",
                "",
                f"- Rule: `{alert.rule_id}`",
                f"- Severity: **{alert.severity}**",
                f"- Score: {alert.score}",
                f"- User: `{alert.user}`",
                f"- Source IP: `{alert.source_ip}`",
                f"- Timestamp: {alert.timestamp}",
                f"- Description: {alert.description}",
                f"- Evidence: `{json.dumps(alert.evidence, sort_keys=True)}`",
                "",
            ]
        )

    output.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json(path: str | Path, alerts: list[Alert]) -> None:
    output = Path(path)
    output.write_text(json.dumps([_alert_dict(alert) for alert in alerts], indent=2, sort_keys=True), encoding="utf-8")


def write_csv(path: str | Path, alerts: list[Alert]) -> None:
    output = Path(path)
    fieldnames = ["rule_id", "title", "severity", "score", "user", "source_ip", "timestamp", "description", "evidence"]
    with output.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            row = _alert_dict(alert)
            row["evidence"] = json.dumps(row["evidence"], sort_keys=True)
            writer.writerow(row)
