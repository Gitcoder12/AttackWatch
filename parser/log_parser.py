"""Parse JSON log records into LogEntry objects. Tolerant of field-name variants."""

from typing import List, Optional, Any, Dict
from models.log_entry import LogEntry


def _get(d: Dict, *keys, default=None):
    for k in keys:
        if k in d:
            return d[k]
    return default


def parse_log(raw: Dict[str, Any]) -> Optional[LogEntry]:
    try:
        source_ip = _get(raw, "source_ip", "src_ip", "src")
        dest_ip = _get(raw, "destination_ip", "dst_ip", "dst", default="0.0.0.0")
        event = _get(raw, "event_type", "event", "type", default="unknown")
        status = int(_get(raw, "status", default=0) or 0)
        port = int(_get(raw, "port", default=0) or 0)
        protocol = str(_get(raw, "protocol", default="TCP") or "TCP").upper()
        ts = str(_get(raw, "timestamp", "time", default=""))
        count = int(_get(raw, "count", default=1) or 1)
        severity = _get(raw, "severity")

        if not source_ip:
            return None

        return LogEntry(
            timestamp=ts,
            source_ip=str(source_ip),
            destination_ip=str(dest_ip),
            event_type=str(event).lower().replace(" ", "_"),
            status=status,
            port=port,
            protocol=protocol,
            count=count,
            severity=severity,
        )
    except (ValueError, TypeError):
        return None


def parse_logs(logs: list) -> List[LogEntry]:
    return [e for e in (parse_log(x) for x in logs) if e is not None]
