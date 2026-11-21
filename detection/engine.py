"""Indexed rule-based detection engine.

Builds per-source aggregates once, then evaluates each rule against those
aggregates. Pattern rules still inspect event text because patterns are
user-defined substrings and cannot safely be reduced to a fixed token index.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from models.log_entry import LogEntry


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    source_ip: str
    severity: str
    detail: str
    count: int
    ports: list[int] = field(default_factory=list)


@dataclass(slots=True)
class _SourceIndex:
    entries: list[LogEntry] = field(default_factory=list)
    total_count: int = 0
    counts_by_port: dict[int, int] = field(default_factory=dict)
    distinct_ports: set[int] = field(default_factory=set)
    normalized_events: list[tuple[LogEntry, str, str]] = field(default_factory=list)


def _build_index(entries: list[LogEntry]) -> dict[str, _SourceIndex]:
    """O(N) preprocessing with O(N + distinct source/port pairs) memory."""
    index: dict[str, _SourceIndex] = {}
    for entry in entries:
        source = index.get(entry.source_ip)
        if source is None:
            source = index[entry.source_ip] = _SourceIndex()
        source.entries.append(entry)
        source.total_count += entry.count
        source.counts_by_port[entry.port] = (
            source.counts_by_port.get(entry.port, 0) + entry.count
        )
        source.distinct_ports.add(entry.port)
        source.normalized_events.append((
            entry,
            (entry.event_type or "").casefold(),
            (entry.severity or "").casefold(),
        ))
    return index


def detect(entries: list[LogEntry], rules: list[dict[str, Any]]) -> list[Alert]:
    """Detect rule matches without repeatedly filtering every source's logs.

    Complexity:
      - preprocessing: O(N)
      - port/count rules: O(R * S), where S is distinct source IPs
      - pattern rules: O(P * N), where P is pattern-bearing rules
      - output de-duplication: expected O(A), not O(A²)

    N = log entries, R = rules, S = source IPs, P = pattern rules,
    A = emitted alerts.
    """
    by_ip = _build_index(entries)
    alerts: list[Alert] = []
    seen_alerts: set[tuple[str, str]] = set()

    def emit(alert: Alert) -> None:
        key = (alert.source_ip, alert.rule_name)
        if key not in seen_alerts:
            seen_alerts.add(key)
            alerts.append(alert)

    for rule in rules:
        rid = rule.get("id", "?")
        name = rule.get("name", "Unknown")
        severity = rule.get("severity", "MEDIUM")
        port = rule.get("port")
        threshold = rule.get("threshold", 10)
        threshold_ports = rule.get("threshold_ports")
        patterns = rule.get("patterns")

        for ip, source in by_ip.items():
            if port is not None and threshold_ports is None:
                total = source.counts_by_port.get(port, 0)
                if total >= threshold:
                    emit(Alert(
                        rule_id=rid,
                        rule_name=name,
                        source_ip=ip,
                        severity=severity,
                        detail=f"{total} events on port {port}",
                        count=total,
                        ports=[port],
                    ))

            if threshold_ports is not None:
                port_count = len(source.distinct_ports)
                if port_count >= threshold_ports:
                    emit(Alert(
                        rule_id=rid,
                        rule_name=name,
                        source_ip=ip,
                        severity=severity,
                        detail=f"{port_count} distinct ports contacted",
                        count=port_count,
                        ports=sorted(source.distinct_ports)[:20],
                    ))

            if patterns:
                normalized_patterns = tuple(
                    pattern.casefold() for pattern in patterns
                    if isinstance(pattern, str) and pattern
                )
                for entry, event_type, event_severity in source.normalized_events:
                    if any(
                        pattern in event_type or pattern in event_severity
                        for pattern in normalized_patterns
                    ):
                        emit(Alert(
                            rule_id=rid,
                            rule_name=name,
                            source_ip=ip,
                            severity=severity,
                            detail=f"Pattern match: {entry.event_type}",
                            count=entry.count,
                            ports=[entry.port],
                        ))
                        break

            if port is None and threshold_ports is None and not patterns:
                if source.total_count >= threshold:
                    emit(Alert(
                        rule_id=rid,
                        rule_name=name,
                        source_ip=ip,
                        severity=severity,
                        detail=f"{source.total_count} total events",
                        count=source.total_count,
                    ))

    # Preserve the legacy sample-event fallback while de-duplicating in O(1).
    for entry in entries:
        if entry.severity and entry.count >= 5:
            already = any(
                source_ip == entry.source_ip and rule_name.casefold() in entry.event_type.casefold()
                for source_ip, rule_name in seen_alerts
            )
            if not already:
                emit(Alert(
                    rule_id="SAMPLE",
                    rule_name=entry.event_type.replace("_", " ").title(),
                    source_ip=entry.source_ip,
                    severity=entry.severity.upper(),
                    detail=f"count={entry.count} port={entry.port}",
                    count=entry.count,
                    ports=[entry.port],
                ))

    return alerts
