# AttackWatch

**A rule-based network-log analysis CLI that detects suspicious activity and scores source IPs.**

[![License](https://img.shields.io/badge/license-see%20LICENSE-lightgrey)](LICENSE)

AttackWatch parses structured JSON logs, applies configurable detection rules, groups alerts by source IP, calculates risk scores, and writes a JSON report. Optional GeoIP enrichment and webhook delivery can be enabled from the command line.

## Features

- Parse common JSON log field names into normalized log records.
- Detect configured patterns such as repeated SSH/RDP events, SQL-injection indicators, and port scans.
- Aggregate alerts by source IP and calculate a 0–100 threat score.
- Optionally enrich source IPs with country/city metadata.
- Optionally send alerts to a Discord-compatible webhook.
- Save alerts and per-IP scores to a JSON report.

## Tech Stack

Python · JSON · Python Standard Library

## Quick Start

```bash
git clone https://github.com/Gitcoder12/AttackWatch.git
cd AttackWatch
python main.py
```

The default run reads `sample_logs.json` and `rules.json`, then writes `report.json`.

## CLI

```bash
# Use custom log and rule files
python main.py my_logs.json my_rules.json

# Add optional GeoIP enrichment
python main.py --geo

# Send alerts to a webhook
python main.py --webhook "https://example.com/webhook"

# Choose the report output path
python main.py sample_logs.json rules.json --json-out output/report.json
```

The webhook can also be supplied through the `ATTACKWATCH_WEBHOOK` environment variable.

## Log Format

The parser accepts common aliases for source IP, destination IP, and event type. A minimal example:

```json
{
  "timestamp": "2026-11-12T10:23:11Z",
  "src_ip": "203.0.113.42",
  "dst_ip": "10.0.0.1",
  "port": 22,
  "protocol": "TCP",
  "event": "ssh_login_failure",
  "count": 20
}
```

Detection thresholds and severities are defined in `rules.json`.

## Run Tests

The test suite uses Python's built-in `unittest` framework:

```bash
python -m unittest discover -s tests -v
```

## Project Structure

```text
AttackWatch/
├── main.py             # CLI pipeline and report generation
├── parser/             # JSON log normalization
├── detection/          # Rule evaluation
├── scoring/            # Per-IP threat scoring
├── models/             # Log-entry data model
├── geoip.py            # Optional GeoIP lookup
├── alerter.py          # Optional webhook delivery
├── rules.json          # Detection rules
├── sample_logs.json    # Demonstration input
└── tests/              # Unit and integration tests
```

## Scope and Limitations

AttackWatch is a rule-based prototype, not a full network sensor or incident-response platform. It analyzes records supplied by the user; it does not capture packets or block traffic. Rule coverage depends on the configured event fields and sample data.

When `--geo` is enabled, source IP addresses are queried through the external ip-api.com service. When a webhook is configured, alert details are sent to that endpoint. Use these options only with data and services you are authorized to share. GeoIP results can be approximate and should not be used to identify a person.

## License

See [LICENSE](LICENSE).
