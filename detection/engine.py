"""Rule-based detection engine."""

from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Any
from models.log_entry import LogEntry


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    source_ip: str
    severity: str
    detail: str
    count: int
    ports: List[int] = None

    def __post_init__(self):
        if self.ports is None:
            self.ports = []


def detect(entries: List[LogEntry], rules: List[Dict[str, Any]]) -> List[Alert]:
    alerts: List[Alert] = []

    # Group by source IP
    by_ip: Dict[str, List[LogEntry]] = defaultdict(list)
    for e in entries:
        by_ip[e.source_ip].append(e)

    for rule in rules:
        rid = rule.get("id", "?")
        name = rule.get("name", "Unknown")
        severity = rule.get("severity", "MEDIUM")
        port = rule.get("port")
        threshold = rule.get("threshold", 10)
        threshold_ports = rule.get("threshold_ports")

        for ip, logs in by_ip.items():
            # Port-specific threshold (brute force style)
            if port is not None and threshold_ports is None:
                matching = [l for l in logs if l.port == port]
                total = sum(l.count for l in matching)
                # Also count by event keywords
                if any(k in (matching[0].event_type if matching else "") for k in ("fail", "brute", "login")):
                    total = max(total, sum(l.count for l in matching))
                if total >= threshold:
                    alerts.append(Alert(
                        rule_id=rid, rule_name=name, source_ip=ip,
                        severity=severity, detail=f"{total} events on port {port}",
                        count=total, ports=[port],
                    ))

            # Port scan: many distinct ports
            if threshold_ports is not None:
                ports = {l.port for l in logs}
                if len(ports) >= threshold_ports:
                    alerts.append(Alert(
                        rule_id=rid, rule_name=name, source_ip=ip,
                        severity=severity,
                        detail=f"{len(ports)} distinct ports contacted",
                        count=len(ports), ports=sorted(ports)[:20],
                    ))

            # Keyword / event-type based (SQL injection etc.)
            patterns = rule.get("patterns")
            if patterns:
                for l in logs:
                    if any(p.lower() in l.event_type for p in patterns) or \
                       any(p.lower() in (l.severity or "") for p in patterns):
                        alerts.append(Alert(
                            rule_id=rid, rule_name=name, source_ip=ip,
                            severity=severity, detail=f"Pattern match: {l.event_type}",
                            count=l.count, ports=[l.port],
                        ))
                        break

            # Generic high-count events
            if port is None and threshold_ports is None and not patterns:
                total = sum(l.count for l in logs)
                if total >= threshold:
                    alerts.append(Alert(
                        rule_id=rid, rule_name=name, source_ip=ip,
                        severity=severity, detail=f"{total} total events",
                        count=total,
                    ))

    # Also surface pre-labeled sample events
    for e in entries:
        if e.severity and e.count >= 5:
            already = any(a.source_ip == e.source_ip and a.rule_name.lower() in e.event_type for a in alerts)
            if not already:
                alerts.append(Alert(
                    rule_id="SAMPLE", rule_name=e.event_type.replace("_", " ").title(),
                    source_ip=e.source_ip, severity=e.severity.upper(),
                    detail=f"count={e.count} port={e.port}", count=e.count, ports=[e.port],
                ))

    # Deduplicate by (source_ip, rule_name)
    seen = set()
    unique = []
    for a in alerts:
        key = (a.source_ip, a.rule_name)
        if key not in seen:
            seen.add(key)
            unique.append(a)
    return unique
