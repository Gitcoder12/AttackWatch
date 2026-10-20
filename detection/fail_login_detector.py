from typing import List, Optional

from models.log_entry import LogEntry


class FailedLogin:
    def __init__(self, source_ip: str, count: int):
        self.source_ip = source_ip
        self.count = count


def detect_failed_logins(log_entries: List[Optional[LogEntry]]) -> List[FailedLogin]:
    failed_logins = {}
    for entry in log_entries:
        if entry and entry.event_type == 'login_failure':
            if entry.source_ip in failed_logins:
                failed_logins[entry.source_ip].count += 1
            else:
                failed_logins[entry.source_ip] = FailedLogin(entry.source_ip, 1)
    return list(failed_logins.values())
