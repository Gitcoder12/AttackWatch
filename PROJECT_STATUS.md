# Project Status — AttackWatch

**Snapshot date:** 2026-11-16  
**Status type:** Initial documentation and repository-tree assessment  
**Default branch:** main  
**Review completeness:** Partial — not a code audit or release certification

## Project purpose
Python network-log threat-detection CLI that parses records, applies detection rules, scores alerts and optionally performs GeoIP lookup/webhook notification.

## Current maturity (README-declared or visible scaffolding; not independently verified)
Root includes CLI, parser, detection, scoring, dashboard, tests, sample/rule JSON files and GitHub workflow/governance directories.

## Observed repository structure
alerter.py, main.py, parser/, detection/, scoring/, dashboard/, models/, tests/, rules.json, sample_logs.json, report.json and .github/.

## Known issues and risks to investigate
Detection correctness and alert thresholds not tested in this status pass. sample_logs.json/report.json should be clearly marked as synthetic/demo if they are fixtures; ensure no real IP/person data is unintentionally included. GeoIP and webhook paths need privacy and failure handling. Verify SQLi/DNS tunneling rules do not overclaim coverage.

## Recommended next actions
Run full tests/lint/type checks; inspect rule semantics and false-positive behavior; validate flexible log schema and malformed events; add representative benign/attack fixtures; confirm GeoIP/webhook are opt-in and sensitive URLs/IPs are redacted from logs.

## Verification record
| Check | Result |
|---|---|
| Default-branch top-level tree | Inspected |
| README | Inspected |
| Deep source review | Not performed |
| Tests / build / runtime | Not run |
| Security / dependency audit | Not run |
| Live deployment / API checks | Not run |
| Independent review | Not performed |

## Change log
- 2026-11-16: Added this initial status snapshot on a review branch. No application code or existing data changed.

> Update this file only after the corresponding inspection or verification has actually been performed. Distinguish observed facts, README claims, hypotheses and unrun checks.