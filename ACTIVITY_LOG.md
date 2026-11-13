# AttackWatch — Activity Log

**Snapshot:** 2026-11-13

## Verified history

No portfolio source-edit PR or issue was recorded in this pass. README describes the JSON-log CLI and its optional GeoIP/webhook integrations.

## Current scope

Python CLI normalises JSON log records, applies configurable detection rules for repeated SSH/RDP events, SQL-injection indicators and port scans, aggregates alerts by source IP and calculates a project-specific risk score. GeoIP and webhook delivery are optional. This is a defensive log-analysis aid, not a replacement for a SIEM or incident response process.

## Append-only record

| Date | Contributor / agent | Issue / PR | Rule/files | Dataset and command | Result | Evidence / limitations |
|---|---|---|---|---|---|---|
| YYYY-MM-DD | name | link | exact rule/path | fixture, version, command | pass / fail / not run | evidence and caveats |

Record false positives, false negatives, rule changes, dataset provenance and test environment. Do not claim detection of every attack or production SOC readiness.
