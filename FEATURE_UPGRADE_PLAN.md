# AttackWatch — Feature Upgrade Plan

## Objective

A command-line tool that reads structured network logs, looks for suspicious patterns and produces alerts grouped by source IP.

## P0 — input integrity and explainability

- [ ] Validate log schema and normalise timestamps, IPs, ports and event types with safe malformed-record handling.
- [ ] Document each detection rule, severity, confidence and known false-positive patterns.

## P1 — detection quality

- [ ] Add labelled benign/malicious fixtures and regression tests for each detection rule.
- [ ] Make scoring contributions inspectable and support JSON/CSV outputs with stable schema.

## P2 — scale and evaluation

- [ ] Measure precision/recall and alert volume on documented public or synthetic datasets.
- [ ] Add streaming/large-file profiling and bounded webhook retry/rate behavior.

## Contributor work packages

1. Parser/schema validation.
2. One detection rule with labelled positive and negative fixtures.
3. Explainable scoring and report schema.
4. Dataset-based evaluation and performance profile.

## Definition of done

- [ ] Malformed logs fail safely and are counted.
- [ ] Every rule has tests and documentation.
- [ ] Risk scores expose their contributing indicators.
- [ ] Benchmarks state dataset, labels and evaluation method.
