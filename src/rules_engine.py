import logging
from dataclasses import dataclass
from typing import List, Dict, Any
from collections import defaultdict

logger = logging.getLogger("AttackWatch.RulesEngine")

@dataclass
class ThreatAlert:
    technique_id: str
    tactic: str
    description: str
    severity: str
    source_ip: str

class ThreatHunter:
    """Scans parsed logs for MITRE ATT&CK patterns."""
    
    def __init__(self):
        self.failed_logins = defaultdict(int)
        
    def analyze_log(self, log_entry: Dict[str, Any]) -> List[ThreatAlert]:
        alerts = []
        ip = log_entry.get("source_ip", "unknown")
        event_type = log_entry.get("event_type", "")
        status = log_entry.get("status", "")
        
        # Tactic 1: Brute Force (T1110)
        if event_type == "login" and status == "failed":
            self.failed_logins[ip] += 1
            if self.failed_logins[ip] >= 5:
                alerts.append(ThreatAlert(
                    technique_id="T1110",
                    tactic="Credential Access",
                    description=f"Multiple failed logins from {ip}",
                    severity="HIGH",
                    source_ip=ip
                ))
                # Reset to prevent spamming alerts
                self.failed_logins[ip] = 0 
                
        # Tactic 2: Automated Scanning (T1595)
        if event_type == "network_scan" or log_entry.get("port") == 22 and status == "rejected":
            alerts.append(ThreatAlert(
                technique_id="T1595",
                tactic="Reconnaissance",
                description=f"Suspicious network probing from {ip}",
                severity="MEDIUM",
                source_ip=ip
            ))
            
        return alerts
