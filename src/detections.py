from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from src.parser import Event
from src.scoring import ThresholdProfile, severity_from_score


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str
    score: int
    user: str
    source_ip: str
    timestamp: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)


def _add_alert(alerts: list[Alert], rule_id: str, title: str, score: int, event: Event, description: str, evidence: dict[str, Any]) -> None:
    alerts.append(
        Alert(
            rule_id=rule_id,
            title=title,
            severity=severity_from_score(score),
            score=score,
            user=event.user,
            source_ip=event.source_ip,
            timestamp=event.timestamp.isoformat(),
            description=description,
            evidence=evidence,
        )
    )


def detect_brute_force(events: list[Event], profile: ThresholdProfile) -> list[Alert]:
    """Many failed attempts for one user from one IP."""
    alerts: list[Alert] = []
    window = timedelta(minutes=profile.brute_force_minutes)
    failures_by_key: dict[tuple[str, str], deque[Event]] = defaultdict(deque)
    seen_windows: set[tuple[str, str, str]] = set()

    for event in events:
        if not event.failure:
            continue
        key = (event.user, event.source_ip)
        q = failures_by_key[key]
        q.append(event)
        while q and event.timestamp - q[0].timestamp > window:
            q.popleft()
        if len(q) >= profile.brute_force_failures:
            dedupe = (event.user, event.source_ip, q[0].timestamp.isoformat())
            if dedupe in seen_windows:
                continue
            seen_windows.add(dedupe)
            _add_alert(
                alerts,
                "AUTH-BRUTE-FORCE",
                "Repeated authentication failures",
                profile.score_brute_force,
                event,
                f"{len(q)} failed logins for {event.user} from {event.source_ip} within {profile.brute_force_minutes} minutes.",
                {"failure_count": len(q), "window_minutes": profile.brute_force_minutes, "first_failure": q[0].timestamp.isoformat()},
            )
    return alerts


def detect_password_spraying(events: list[Event], profile: ThresholdProfile) -> list[Alert]:
    """One IP attempting many users in a short window."""
    alerts: list[Alert] = []
    window = timedelta(minutes=profile.spray_minutes)
    failures_by_ip: dict[str, deque[Event]] = defaultdict(deque)
    seen_windows: set[tuple[str, str]] = set()

    for event in events:
        if not event.failure:
            continue
        q = failures_by_ip[event.source_ip]
        q.append(event)
        while q and event.timestamp - q[0].timestamp > window:
            q.popleft()
        users = sorted({item.user for item in q})
        if len(users) >= profile.spray_users:
            dedupe = (event.source_ip, q[0].timestamp.isoformat())
            if dedupe in seen_windows:
                continue
            seen_windows.add(dedupe)
            _add_alert(
                alerts,
                "AUTH-PASSWORD-SPRAY",
                "Possible password spraying",
                profile.score_password_spray,
                event,
                f"{event.source_ip} failed authentication against {len(users)} users within {profile.spray_minutes} minutes.",
                {"user_count": len(users), "users": users, "failure_count": len(q), "window_minutes": profile.spray_minutes},
            )
    return alerts


def detect_success_after_failures(events: list[Event], profile: ThresholdProfile) -> list[Alert]:
    """Many failed attempts followed by a success for the same user/IP."""
    alerts: list[Alert] = []
    window = timedelta(minutes=profile.brute_force_minutes)
    failures_by_key: dict[tuple[str, str], deque[Event]] = defaultdict(deque)

    for event in events:
        key = (event.user, event.source_ip)
        q = failures_by_key[key]
        while q and event.timestamp - q[0].timestamp > window:
            q.popleft()
        if event.success and len(q) >= profile.brute_force_failures:
            _add_alert(
                alerts,
                "AUTH-SUCCESS-AFTER-FAILURES",
                "Successful login after repeated failures",
                profile.score_success_after_failures,
                event,
                f"Successful login for {event.user} from {event.source_ip} followed {len(q)} recent failures.",
                {"prior_failure_count": len(q), "window_minutes": profile.brute_force_minutes, "first_failure": q[0].timestamp.isoformat()},
            )
            q.clear()
        elif event.failure:
            q.append(event)
    return alerts


def detect_new_ip_for_user(events: list[Event], profile: ThresholdProfile) -> list[Alert]:
    """First time a user is seen successfully logging in from an IP in the dataset."""
    alerts: list[Alert] = []
    seen_ips_by_user: dict[str, set[str]] = defaultdict(set)

    for event in events:
        if not event.success:
            continue
        seen_ips = seen_ips_by_user[event.user]
        if seen_ips and event.source_ip not in seen_ips:
            _add_alert(
                alerts,
                "AUTH-NEW-IP-FOR-USER",
                "New source IP for user",
                profile.score_new_ip,
                event,
                f"{event.user} successfully logged in from a new source IP: {event.source_ip}.",
                {"previous_ips": sorted(seen_ips), "new_ip": event.source_ip, "app": event.app},
            )
        seen_ips.add(event.source_ip)
    return alerts


def detect_suspicious_geo(events: list[Event], profile: ThresholdProfile) -> list[Alert]:
    alerts: list[Alert] = []
    for event in events:
        country = (event.country or "").upper()
        if event.success and country in profile.suspicious_countries:
            _add_alert(
                alerts,
                "AUTH-SUSPICIOUS-GEO",
                "Successful login from suspicious geography",
                profile.score_suspicious_geo,
                event,
                f"Successful login for {event.user} from country {country}.",
                {"country": country, "city": event.city, "app": event.app},
            )
    return alerts


def detect_impossible_travel(events: list[Event], profile: ThresholdProfile) -> list[Alert]:
    alerts: list[Alert] = []
    last_success_by_user: dict[str, Event] = {}
    min_delta = timedelta(minutes=profile.impossible_travel_minutes)

    for event in events:
        if not event.success:
            continue
        previous = last_success_by_user.get(event.user)
        if previous and previous.country and event.country and previous.country != event.country:
            delta = event.timestamp - previous.timestamp
            if timedelta(0) <= delta <= min_delta:
                _add_alert(
                    alerts,
                    "AUTH-IMPOSSIBLE-TRAVEL",
                    "Potential impossible travel",
                    profile.score_impossible_travel,
                    event,
                    f"{event.user} logged in from {previous.country} and then {event.country} within {int(delta.total_seconds() // 60)} minutes.",
                    {
                        "previous_timestamp": previous.timestamp.isoformat(),
                        "previous_country": previous.country,
                        "previous_source_ip": previous.source_ip,
                        "current_country": event.country,
                        "elapsed_minutes": int(delta.total_seconds() // 60),
                    },
                )
        last_success_by_user[event.user] = event
    return alerts


def run_all(events: list[Event], profile: ThresholdProfile) -> list[Alert]:
    alerts: list[Alert] = []
    alerts.extend(detect_brute_force(events, profile))
    alerts.extend(detect_password_spraying(events, profile))
    alerts.extend(detect_success_after_failures(events, profile))
    alerts.extend(detect_new_ip_for_user(events, profile))
    alerts.extend(detect_suspicious_geo(events, profile))
    alerts.extend(detect_impossible_travel(events, profile))
    return sorted(alerts, key=lambda alert: (-alert.score, alert.timestamp, alert.rule_id, alert.user))
