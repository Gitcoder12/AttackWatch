# AttackWatch — README Explanation Draft

## In plain language

A command-line tool that reads structured network logs, looks for suspicious patterns and produces alerts grouped by source IP.

## Example

A system log file contains many events. AttackWatch groups related events, checks them against rules and writes a report that helps an analyst decide what to inspect.

## Technical explanation

Python CLI normalises JSON log records, applies configurable detection rules for repeated SSH/RDP events, SQL-injection indicators and port scans, aggregates alerts by source IP and calculates a project-specific risk score. GeoIP and webhook delivery are optional. This is a defensive log-analysis aid, not a replacement for a SIEM or incident response process.

Document supported JSON fields, normalisation, rule definitions, aggregation, score formula, optional enrichment and webhook behavior. Include one benign and one alert-producing example.

## Limitations

A rule can miss attacks and can alert on normal activity. GeoIP is approximate. Outputs need analyst review and must not be treated as proof of compromise.

## Contributing

See FEATURE_UPGRADE_PLAN.md, CONTRIBUTING.md and ACTIVITY_LOG.md.
