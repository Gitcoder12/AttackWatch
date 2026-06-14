from dataclasses import dataclass
from typing import List

from detection.fail_login_detector import FailedLogin


@dataclass
class ThreatScore:
    source_ip: str
    score: int
    severity: str


def get_severity(score: int) -> str:
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 30:
        return "MEDIUM"
    return "LOW"


def calculate_threat_scores(failed_logins: List[FailedLogin]) -> List[ThreatScore]:
    results = []

    for login in failed_logins:
        score = min(login.count * 20, 100)

        results.append(
            ThreatScore(
                source_ip=login.source_ip,
                score=score,
                severity=get_severity(score),
            )
        )

    return results
