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


---

## AI-maintained project notes (secondary — 2026-11-13)

This section supplements the maintainer-authored README above. The original text has been restored verbatim from Git-history baseline `b70cfd01130f1f4e34bbf38534aa8e1d14434cbd`; this addendum does not replace or certify the original claims.

- The current source tree, runtime data and tests are the implementation source of truth. A roadmap item, draft PR or AI-generated description is not a shipped feature by itself.
- Preserve real and maintainer-provided data. Never silently substitute generated or placeholder data. Clearly label and isolate synthetic fixtures.
- Mark unverified sources, identifiers, metrics, benchmark results and external claims as unknown/unverified rather than guessing.
- Verify setup, execution, tests and public claims against the exact current commit before using this repository in a job, research or academic application.
- See [MODEL_AUDIT_ROUTER.md](MODEL_AUDIT_ROUTER.md) for independent model review instructions and the merge gate.

---

## Engineering Audit & Handover — 2026-11-17

**Review scope:** default branch `main`; static inspection of `main.py` and `alerter.py`. Runtime tests were not executed.

### Confirmed findings
- The pipeline accepts JSON logs and rules, parses them, applies detection rules, scores alerts, and writes a JSON report. The actual detection quality depends on the configured rules and parser; it is not an independently validated intrusion-detection model.
- The optional webhook sender posts alert details to the supplied URL with a 10-second timeout. Treat webhook URLs as secrets and avoid including sensitive log contents in external notifications.
- The report and webhook behavior were inspected, but no test run or real-world detection evaluation was performed in this audit.

### Next actions
1. Add schema validation and adversarial fixtures for malformed, oversized, and unexpected log records/rules.
2. Add tests for every detection rule, scoring boundaries, webhook success/failure, and report output.
3. Document false-positive/false-negative limitations and keep sample log results separate from measured security effectiveness.

**Verification status:** static source inspection only; CLI execution, test suite, GeoIP integration, and detection precision/recall remain unverified.

---

## Examples Used
- Detecting repeated SSH login failures
- Identifying a port-scan pattern in network logs
- Flagging SQL-injection-like events


---

## Comparison with Existing Open-Source Projects

AttackWatch is a lightweight network-log analysis CLI that parses events, applies configurable detection rules, scores alerts and optionally sends notifications. The following projects are established defensive-security references with different levels of scope.

| Project | Established focus | Relationship to AttackWatch |
|---|---|---|
| [Wazuh](https://github.com/wazuh/wazuh) | Security monitoring, endpoint detection, log analysis and alerting platform | Much broader security platform with agents, rules and centralized operations; AttackWatch is a small local log-to-report workflow. |
| [Zeek](https://github.com/zeek/zeek) | Network security monitoring and rich network-event analysis | A mature network-analysis framework; AttackWatch currently evaluates supplied log records rather than operating as a full network sensor. |
| [Sigma](https://github.com/SigmaHQ/sigma) | Generic, shareable detection-rule format for SIEM systems | A useful rule portability reference; AttackWatch's documented custom JSON rules are narrower and should not claim Sigma compatibility unless implemented. |

### Where AttackWatch is different
- **Small CLI workflow:** the README describes a direct local pipeline from JSON logs to alerts and a report, without requiring a central SIEM deployment.
- **Readable rule triggers:** example detections such as brute-force patterns and port-scan indicators are exposed in a compact format.
- **Optional integrations:** GeoIP enrichment and webhook notification are optional rather than mandatory services.

### Where established projects are stronger
Wazuh and Zeek provide much broader telemetry, rule ecosystems, operational integrations and mature security workflows. Sigma has a standardized cross-tool detection ecosystem. AttackWatch is not a replacement for an EDR, SIEM, NDR or independently validated intrusion-detection system.

### Evidence and security limitations
Detection quality depends on input coverage, rule definitions and thresholds. Add precision/recall evaluation against labelled logs, parser/schema validation and adversarial tests. Treat webhook URLs as secrets and avoid sending sensitive log contents to third parties. This comparison is a scope note, not a detection-performance claim.
