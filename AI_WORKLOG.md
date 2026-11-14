# AI Worklog — AttackWatch

**Audit date:** 2026-11-14  
**Repository:** https://github.com/Gitcoder12/AttackWatch  
**Default branch:** `main`  
**Review branch:** `docs/portfolio-operating-kit-2026-11-13`  
**Related draft PR:** https://github.com/Gitcoder12/AttackWatch/pull/2

## Purpose and maturity

Runnable Python CLI for parsing JSON network logs, applying configurable rules, aggregating alerts by source IP, calculating heuristic scores, and optionally enriching or delivering alerts through GeoIP and webhooks.

## Verified implementation

- Entry point: `main.py`.
- Parser: `parser/log_parser.py`.
- Detection: `detection/engine.py`.
- Scoring: `scoring/threat_score_calculator.py`.
- Optional integrations: `geoip.py`, `alerter.py`.
- Four focused test modules and a GitHub Actions test workflow are present.

## Findings

- **P1 — Detection semantics:** `detection/engine.py` sums every event on a configured port. The event-keyword conditional does not restrict that total, so a rule intended for failed SSH/RDP logins may count unrelated traffic on the same port. Confirm each rule's intended semantics against `rules.json` before changing it.
- **P2 — Silent record loss:** `parser/log_parser.py` returns `None` for malformed or source-IP-less records, and `parse_logs` filters them out without exposing a rejected-record count in the report.
- **P2 — Alert detail loss:** final deduplication uses only `(source_ip, rule_name)`, which can collapse distinct matching evidence into one alert.
- **P2 — Evaluation gap:** tests exist, but a labelled benign/positive corpus and measured false-positive/false-negative results were not verified.

## Verification

- **CI:** GitHub Actions run associated with the current draft PR #2 head completed successfully.
- **Local tests:** NOT RUN in this automation environment.
- **Not run:** precision/recall evaluation, malformed-record accounting, large-file profiling, live GeoIP and webhook integration tests, dependency/security scan.

## Next actions

1. Inspect `rules.json` and define exact positive/negative semantics per rule.
2. Add labelled fixtures and regression tests for each rule.
3. Report rejected input counts and reasons rather than silently discarding records.
4. Preserve multiple evidence details when aggregating alerts.
5. Review webhook URL handling, payload privacy, retries and timeout behavior.

## Status

Assessed: yes. Changed: AI worklog only. Tests run locally: no. CI: passed on PR #2 head. Independent external-model review: NOT PERFORMED. Merged: no.
