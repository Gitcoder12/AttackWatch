from typing import List, Optional

from models.log_entry import LogEntry


REQUIRED_FIELDS = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "event_type",
    "status",
    "port",
    "protocol",
}


def parse_logs(logs: list) -> List[Optional[LogEntry]]:
    parsed_logs = []

    for log in logs:
        if not REQUIRED_FIELDS.issubset(log.keys()):
            parsed_logs.append(None)
            continue

        try:
            parsed_logs.append(
                LogEntry(
                    timestamp=log["timestamp"],
                    source_ip=log["source_ip"],
                    destination_ip=log["destination_ip"],
                    event_type=log["event_type"],
                    status=int(log["status"]),
                    port=int(log["port"]),
                    protocol=log["protocol"],
                )
            )
        except (ValueError, TypeError):
            parsed_logs.append(None)

    return parsed_logs
