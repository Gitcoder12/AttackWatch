from typing import List, Optional
import sys
from datetime import datetime

# Import your classes from other modules
from ..parser.log_parser import parse_logs
from ..detection.fail_login_detector import detect_failed_logins
from ..scoring.threat_score_calculator import calculate_threat_scores

def main(log_file_path: str):
    with open(log_file_path, 'r') as file:
        logs = json.load(file)
    
    log_entries = parse_logs(logs)
    failed_logins = detect_failed_logins(log_entries)
    threat_scores = calculate_threat_scores(failed_logins)

    print(f"Failed Logins:")
    for login in failed_logins:
        print(f"  Source IP: {login.source_ip}, Count: {login.count}")

    print("\nThreat Scores:")
    for score in threat_scores:
        print(f"  Source IP: {score.source_ip}, Score: {score.score}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python cli_dashboard.py path/to/logfile.json")
        sys.exit(1)
    
    log_file_path = sys.argv[1]
    main(log_file_path)
