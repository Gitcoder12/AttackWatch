from dataclasses import dataclass


@dataclass
class LogEntry:
    timestamp: str
    source_ip: str
    destination_ip: str
    event_type: str
    status: int
    port: int
    protocol: str
