from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class ThresholdProfile:
    name: str
    brute_force_failures: int
    brute_force_minutes: int
    spray_users: int
    spray_minutes: int
    suspicious_countries: set[str]
    impossible_travel_minutes: int
    score_brute_force: int
    score_password_spray: int
    score_success_after_failures: int
    score_new_ip: int
    score_suspicious_geo: int
    score_impossible_travel: int


PROFILES: dict[str, ThresholdProfile] = {
    "strict": ThresholdProfile(
        name="strict",
        brute_force_failures=4,
        brute_force_minutes=15,
        spray_users=4,
        spray_minutes=20,
        suspicious_countries={"RU", "CN", "KP", "IR"},
        impossible_travel_minutes=120,
        score_brute_force=75,
        score_password_spray=80,
        score_success_after_failures=75,
        score_new_ip=35,
        score_suspicious_geo=55,
        score_impossible_travel=90,
    ),
    "balanced": ThresholdProfile(
        name="balanced",
        brute_force_failures=5,
        brute_force_minutes=20,
        spray_users=5,
        spray_minutes=30,
        suspicious_countries={"RU", "CN", "KP", "IR"},
        impossible_travel_minutes=90,
        score_brute_force=70,
        score_password_spray=80,
        score_success_after_failures=75,
        score_new_ip=30,
        score_suspicious_geo=50,
        score_impossible_travel=85,
    ),
    "loose": ThresholdProfile(
        name="loose",
        brute_force_failures=8,
        brute_force_minutes=30,
        spray_users=8,
        spray_minutes=45,
        suspicious_countries={"RU", "CN", "KP", "IR"},
        impossible_travel_minutes=60,
        score_brute_force=65,
        score_password_spray=70,
        score_success_after_failures=65,
        score_new_ip=25,
        score_suspicious_geo=45,
        score_impossible_travel=80,
    ),
}


def get_profile(name: str) -> ThresholdProfile:
    try:
        return PROFILES[name.lower()]
    except KeyError as exc:
        valid = ", ".join(sorted(PROFILES))
        raise ValueError(f"Unknown profile '{name}'. Valid profiles: {valid}") from exc


def severity_from_score(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "medium"
    return "low"
