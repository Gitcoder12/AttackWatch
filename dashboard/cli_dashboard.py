"""AttackWatch CLI – parse, detect, score, GeoIP, optional webhook."""

from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

from parser.log_parser import parse_logs
from detection.engine import detect
from scoring.threat_score_calculator import calculate_threat_scores

try:
    from geoip import lookup as geo_lookup
except ImportError:
    geo_lookup = None

try:
    from alerter import send_webhook
except ImportError:
    send_webhook = None


SEVERITY_COLOR = {
    "CRITICAL": "\033[91m",
    "HIGH": "\033[93m",
    "MEDIUM": "\033[94m",
    "LOW": "\033[92m",
}
RESET = "\033[0m"
BOLD = "\033[1m"


def load_json(path: Path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def print_report(alerts, scores, geo: bool = False):
    print(f"\n{BOLD}{'=' * 68}")
    print("  AttackWatch  v0.3  —  Threat Report")
    print(f"{'=' * 68}{RESET}")

    if not alerts:
        print("\n  ✓ No threats detected.\n")
        return

    print(f"\n  {BOLD}Alerts ({len(alerts)}){RESET}\n")
    for a in alerts:
        color = SEVERITY_COLOR.get(a.severity.upper(), "")
        print(f"  {color}{BOLD}[{a.severity}]{RESET} {a.rule_name}")
        print(f"           IP      : {a.source_ip}")
        if geo and geo_lookup:
            info = geo_lookup(a.source_ip)
            if info:
                print(f"           Location: {info.get('city','?')}, {info.get('country','?')}")
                print(f"           ISP     : {info.get('isp','?')}")
        print(f"           Detail  : {a.detail}  (count={a.count})")
        if a.ports:
            print(f"           Ports   : {a.ports}")
        print()

    print(f"{'-' * 68}")
    print(f"\n  {BOLD}Threat Scores ({len(scores)}){RESET}\n")
    for s in scores:
        color = SEVERITY_COLOR.get(s.severity, "")
        filled = s.score // 5
        bar = "█" * filled + "░" * (20 - filled)
        print(f"  {color}{s.score:3d}{RESET}  [{bar}]  {s.source_ip:<18} {s.severity:<8} ({s.alerts} alert(s))")
    print(f"\n{'=' * 68}\n")


def main():
    p = argparse.ArgumentParser(description="AttackWatch – network log threat detection")
    p.add_argument("log_file", nargs="?", default="sample_logs.json", help="JSON log file")
    p.add_argument("rules_file", nargs="?", default="rules.json", help="Rules JSON file")
    p.add_argument("--geo", action="store_true", help="Lookup GeoIP for alert source IPs")
    p.add_argument("--webhook", type=str, default=None, help="Discord/Slack webhook URL")
    p.add_argument("--json-out", type=str, default=None, help="Write full report as JSON")
    args = p.parse_args()

    log_file = Path(args.log_file)
    rules_file = Path(args.rules_file)

    if not log_file.exists():
        print(f"Error: log file not found: {log_file}")
        sys.exit(1)

    logs = load_json(log_file)
    if isinstance(logs, dict) and "logs" in logs:
        logs = logs["logs"]

    entries = parse_logs(logs)
    print(f"Parsed {len(entries)} log entries from {log_file.name}")

    rules = []
    if rules_file.exists():
        data = load_json(rules_file)
        rules = data.get("rules", data) if isinstance(data, dict) else data
        print(f"Loaded {len(rules)} detection rules")

    alerts = detect(entries, rules)
    scores = calculate_threat_scores(alerts)
    print_report(alerts, scores, geo=args.geo)

    if args.webhook and send_webhook:
        ok = send_webhook(args.webhook, alerts)
        print(f"Webhook: {'sent' if ok else 'failed'}")

    if args.json_out:
        report = {
            "alerts": [
                {"rule": a.rule_name, "ip": a.source_ip, "severity": a.severity,
                 "detail": a.detail, "count": a.count, "ports": a.ports}
                for a in alerts
            ],
            "scores": [
                {"ip": s.source_ip, "score": s.score, "severity": s.severity, "alerts": s.alerts}
                for s in scores
            ],
        }
        Path(args.json_out).write_text(json.dumps(report, indent=2))
        print(f"Report written → {args.json_out}")


if __name__ == "__main__":
    main()
