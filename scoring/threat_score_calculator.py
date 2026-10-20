from dataclasses import dataclass
from typing import List
from detection.engine import Alert


SEVERITY_BASE = {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20}


@dataclass
class ThreatScore:
    source_ip: str
    score: int
    severity: str
    alerts: int


def calculate_threat_scores(alerts: List[Alert]) -> List[ThreatScore]:
    by_ip = {}
    for a in alerts:
        if a.source_ip not in by_ip:
            by_ip[a.source_ip] = []
        by_ip[a.source_ip].append(a)

    results = []
    for ip, ip_alerts in by_ip.items():
        base = max(SEVERITY_BASE.get(a.severity.upper(), 20) for a in ip_alerts)
        bonus = min(len(ip_alerts) * 5, 20)
        count_bonus = min(sum(a.count for a in ip_alerts) // 10, 15)
        score = min(100, base + bonus + count_bonus)
        severity = "CRITICAL" if score >= 80 else "HIGH" if score >= 60 else "MEDIUM" if score >= 30 else "LOW"
        results.append(ThreatScore(source_ip=ip, score=score, severity=severity, alerts=len(ip_alerts)))

    results.sort(key=lambda x: x.score, reverse=True)
    return results
