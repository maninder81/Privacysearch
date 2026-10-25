"""Risk weighting per exposure and the profile-level Coverage Score."""

from __future__ import annotations

WEIGHTS = {
    "government_id": 40, "financial": 35, "password": 35, "security_qa": 25, "home_address": 25,
    "phone": 15, "dob": 12, "relatives": 10, "email": 8, "location": 6, "ip": 5, "age": 5, "photo": 5,
    "username": 4, "name": 3, "employer": 3, "other": 2,
}
SOURCE_MULTIPLIER = {"broker": 1.0, "breach": 1.0, "paste": 1.2, "web": 0.8}
OPEN_STATUSES = {"active", "removal_requested", "reappeared", "action_required"}
RESOLVED_STATUSES = {"removed", "mitigated", "dismissed"}


def exposure_risk(data_types: list[str], confidence: float, source_type: str) -> int:
    base = sum(WEIGHTS.get(t, WEIGHTS["other"]) for t in set(data_types))
    return max(1, min(100, round(base * confidence * SOURCE_MULTIPLIER.get(source_type, 1.0))))


def severity(risk: int) -> str:
    if risk >= 60:
        return "critical"
    if risk >= 35:
        return "high"
    if risk >= 15:
        return "medium"
    return "low"


def coverage(exposures: list[dict]) -> dict:
    """Coverage Score: share of discovered risk that has been removed or remediated (0-100).

    Exposure level is the total risk still open, banded so it reads at a glance.
    """
    open_risk = sum(e["risk"] for e in exposures if e["status"] in OPEN_STATUSES)
    resolved_risk = sum(e["risk"] for e in exposures if e["status"] in RESOLVED_STATUSES)
    total = open_risk + resolved_risk
    score = 100 if total == 0 else round(100 * resolved_risk / total)
    if open_risk == 0:
        level = "none"
    elif open_risk < 50:
        level = "low"
    elif open_risk < 150:
        level = "moderate"
    elif open_risk < 300:
        level = "high"
    else:
        level = "severe"
    by_type: dict[str, int] = {}
    for e in exposures:
        if e["status"] in OPEN_STATUSES:
            for t in e["data_types"]:
                by_type[t] = by_type.get(t, 0) + 1
    return {
        "coverage_score": score,
        "exposure_level": level,
        "open_risk": open_risk,
        "resolved_risk": resolved_risk,
        "open_exposures": sum(1 for e in exposures if e["status"] in OPEN_STATUSES),
        "resolved_exposures": sum(1 for e in exposures if e["status"] in RESOLVED_STATUSES),
        "open_by_data_type": dict(sorted(by_type.items(), key=lambda kv: -WEIGHTS.get(kv[0], 2))),
    }
