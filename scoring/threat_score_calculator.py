"""Aggregate rule alerts or failed-login summaries into per-IP threat scores."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable


SEVERITY_BASE = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}


def get_severity(score: int | float) -> str:
    """Map a 0–100 score to the project's severity bands."""
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


@dataclass
class ThreatScore:
    source_ip: str
    score: int
    severity: str
    alerts: int


def calculate_threat_scores(alerts: Iterable[Any]) -> list[ThreatScore]:
    """Return descending per-IP scores.

    Rule alerts use their declared severity plus bounded alert/count bonuses.
    Legacy FailedLogin summaries, which have no severity field, use a simple
    count-based score (20 points per event) for compatibility with that API.
    """
    grouped: dict[str, list[Any]] = {}
    for alert in alerts:
        source_ip = str(getattr(alert, "source_ip", "") or "")
        if not source_ip:
            continue
        grouped.setdefault(source_ip, []).append(alert)

    results: list[ThreatScore] = []
    for source_ip, items in grouped.items():
        declared = [
            str(getattr(item, "severity", "") or "").upper()
            for item in items
            if getattr(item, "severity", None)
        ]
        counts = [max(0, int(getattr(item, "count", 1) or 1)) for item in items]
        total_count = sum(counts)

        if not declared:
            score = min(100, total_count * 20)
        else:
            base = max(SEVERITY_BASE.get(level, 20) for level in declared)
            alert_bonus = min(len(items) * 5, 20)
            volume_bonus = min(total_count // 10, 15)
            score = min(100, base + alert_bonus + volume_bonus)

        results.append(
            ThreatScore(
                source_ip=source_ip,
                score=score,
                severity=get_severity(score),
                alerts=len(items),
            )
        )

    return sorted(results, key=lambda item: (-item.score, item.source_ip))
