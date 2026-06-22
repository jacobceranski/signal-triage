from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


@dataclass(frozen=True)
class Event:
    """Normalized authentication event used by detections."""

    timestamp: datetime
    user: str
    source_ip: str
    action: str
    outcome: str
    app: str = "unknown"
    country: Optional[str] = None
    city: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def success(self) -> bool:
        return self.outcome.lower() in {"success", "succeeded", "allow", "allowed", "ok", "true"}

    @property
    def failure(self) -> bool:
        return self.outcome.lower() in {"failure", "failed", "fail", "deny", "denied", "blocked", "false"}


def _first(record: dict[str, Any], *keys: str, default: Any = None) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return default


def _parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        dt = value
    elif isinstance(value, (int, float)):
        # Accept either epoch seconds or epoch milliseconds.
        if value > 10_000_000_000:
            value = value / 1000
        dt = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            dt = datetime.fromisoformat(text)
        except ValueError:
            # Common auth-log fallback formats.
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%m/%d/%Y %H:%M:%S"):
                try:
                    dt = datetime.strptime(text, fmt)
                    break
                except ValueError:
                    continue
            else:
                raise
    else:
        raise ValueError(f"unsupported timestamp value: {value!r}")

    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def normalize_event(record: dict[str, Any]) -> Event:
    """Convert a source log record into an Event.

    The analyzer accepts several common SSO/VPN auth-log field names so sample
    data from Okta, Entra ID/Azure AD, Duo, VPN gateways, and hand-built JSONL
    files can be used without writing a custom parser first.
    """

    timestamp = _parse_timestamp(
        _first(record, "timestamp", "time", "ts", "@timestamp", "event_time", "created_at", "datetime")
    )
    user = str(_first(record, "user", "username", "user_name", "email", "principal", "actor", default="unknown"))
    source_ip = str(
        _first(record, "source_ip", "src_ip", "ip", "client_ip", "remote_ip", "sourceAddress", default="unknown")
    )
    action = str(_first(record, "action", "event", "event_type", "operation", "activity", default="auth"))
    outcome = str(_first(record, "outcome", "result", "status", "decision", "success", default="unknown"))
    app = str(_first(record, "app", "application", "service", "target", "resource", "provider", default="unknown"))
    country = _first(record, "country", "src_country", "geo_country", "country_code")
    city = _first(record, "city", "src_city", "geo_city")

    return Event(
        timestamp=timestamp,
        user=user,
        source_ip=source_ip,
        action=action,
        outcome=outcome,
        app=app,
        country=str(country) if country not in (None, "") else None,
        city=str(city) if city not in (None, "") else None,
        raw=record,
    )


def _load_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no}: invalid JSONL: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"{path}:{line_no}: expected JSON object")
            yield item


def _load_json(path: Path) -> Iterable[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        data = data.get("events", data.get("records", [data]))
    if not isinstance(data, list):
        raise ValueError(f"{path}: expected a JSON object, list, or object with events/records")
    for index, item in enumerate(data, start=1):
        if not isinstance(item, dict):
            raise ValueError(f"{path}: item {index} is not a JSON object")
        yield item


def _load_csv(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8", newline="") as f:
        yield from csv.DictReader(f)


def load_events(path: str | Path) -> list[Event]:
    """Load auth events from JSONL, JSON, or CSV and normalize them."""

    input_path = Path(path)
    if not input_path.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    suffix = input_path.suffix.lower()
    if suffix in {".jsonl", ".ndjson"}:
        records = _load_jsonl(input_path)
    elif suffix == ".json":
        records = _load_json(input_path)
    elif suffix == ".csv":
        records = _load_csv(input_path)
    else:
        raise ValueError(f"Unsupported input file type: {suffix or '<none>'}. Use .jsonl, .json, or .csv")

    events: list[Event] = []
    for index, record in enumerate(records, start=1):
        try:
            events.append(normalize_event(record))
        except Exception as exc:
            raise ValueError(f"Failed to parse event {index} in {input_path}: {exc}") from exc

    return sorted(events, key=lambda event: event.timestamp)
