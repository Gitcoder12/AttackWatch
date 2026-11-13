# Agent Instructions — AttackWatch

Read README.md, CONTRIBUTING.md and FEATURE_UPGRADE_PLAN.md first.

- Keep work strictly defensive and focused on supplied logs and detection quality.
- Never add exploit execution, persistence, credential theft or offensive scanning features.
- Treat log content as untrusted input; validate and sanitise before parsing or rendering.
- Add benign and alert-producing test fixtures for every rule.
- Preserve privacy; do not upload raw logs to external services by default.
- Report false positives, false negatives and checks that were not run.
- Work on a feature branch and open a PR; never merge/deploy autonomously.
