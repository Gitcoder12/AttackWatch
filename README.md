# AttackWatch

**Network log threat detection.**  
Parse logs → apply detection rules → score source IPs → print a clear report (with optional GeoIP + webhook).

## Quick start

```bash
git clone https://github.com/Gitcoder12/AttackWatch.git
cd AttackWatch
python main.py
```

## CLI options

```bash
# Default sample data
python main.py

# Custom logs + rules
python main.py my_logs.json rules.json

# With GeoIP lookup for alert IPs
python main.py --geo

# Send alerts to Discord/Slack
python main.py --webhook "https://discord.com/api/webhooks/..."

# Export full report as JSON
python main.py --json-out report.json

# Combine
python main.py sample_logs.json rules.json --geo --json-out out.json
```

## What it detects

| Rule | Trigger |
|------|---------|
| SSH Brute Force | Many failures on port 22 |
| RDP Brute Force | Repeated failures on 3389 |
| Port Scan | One IP hitting many distinct ports |
| SQL Injection | Pattern match in event data |
| DNS Tunneling | High-volume DNS queries |

## Architecture

```
main.py
  └── dashboard/cli_dashboard.py
        ├── parser/log_parser.py      # JSON → LogEntry (flexible keys)
        ├── detection/engine.py       # Rules → Alerts
        ├── scoring/threat_score_calculator.py
        ├── geoip.py                  # Optional IP location
        └── alerter.py                # Optional webhook
```

## Log format (flexible)

Accepts either naming style:

```json
{
  "timestamp": "2025-06-01T10:23:11Z",
  "src_ip": "203.0.113.42",
  "dst_ip": "10.0.0.1",
  "port": 22,
  "protocol": "TCP",
  "event": "ssh_login_failure",
  "count": 87
}
```

Also works with `source_ip`, `destination_ip`, `event_type`.

## Threat score

```
base(severity) + 5×alert_count + volume_bonus  →  max 100
CRITICAL ≥ 80 | HIGH ≥ 60 | MEDIUM ≥ 30 | LOW < 30
```

## License

MIT

**Author**: Dharavath Satvik ([@Gitcoder12](https://github.com/Gitcoder12))
