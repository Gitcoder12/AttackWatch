from dataclasses import dataclass
from typing import Optional


@dataclass
class LogEntry:
    timestamp: str
    source_ip: str
    destination_ip: str
    event_type: str
    status: int
    port: int
    protocol: str
    count: int = 1
    severity: Optional[str] = None
