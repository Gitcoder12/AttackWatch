"""AttackWatch command-line pipeline for rule-based log analysis."""

from __future__ import annotations

import argparse
import json
import logging
import os
from dataclasses import asdict
from pathlib import Path
from typing import Any

from alerter import send_webhook
from detection.engine import detect
from geoip import lookup as geoip_lookup
from parser.log_parser import parse_logs
from scoring.threat_score_calculator import calculate_threat_scores

ROOT = Path(__file__).resolve().parent
LOGGER = logging.getLogger("AttackWatch")


def load_json(path: str | Path) -> Any:
    """Load JSON from an absolute path or a path relative to the repository root."""
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = ROOT / candidate
    with candidate.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def run_pipeline(
    logs_path: str | Path = "sample_logs.json",
    rules_path: str | Path = "rules.json",
    output_path: str | Path = "report.json",
    *,
    enable_geoip: bool = False,
    webhook_url: str | None = None,
) -> dict[str, Any]:
    """Parse logs, apply rules, score threats, and write a JSON report."""
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    raw_document = load_json(logs_path)
    if isinstance(raw_document, dict):
        raw_logs = raw_document.get("logs", [])
    elif isinstance(raw_document, list):
        raw_logs = raw_document
    else:
        raise ValueError("Log input must be a JSON object containing 'logs' or a JSON array.")

    rules_document = load_json(rules_path)
    rules = rules_document.get("rules", []) if isinstance(rules_document, dict) else rules_document
    if not isinstance(rules, list):
        raise ValueError("Rules input must be a JSON array or an object with a 'rules' array.")

    entries = parse_logs(raw_logs)
    alerts = detect(entries, rules)
    scores = calculate_threat_scores(alerts)

    score_rows = []
    for score in scores:
        row = asdict(score)
        if enable_geoip:
            row["location"] = geoip_lookup(score.source_ip)
        score_rows.append(row)

    report = {
        "summary": {
            "input_records": len(raw_logs),
            "parsed_records": len(entries),
            "alerts": len(alerts),
            "scored_sources": len(scores),
        },
        "alerts": [asdict(alert) for alert in alerts],
        "scores": score_rows,
    }

    if webhook_url:
        report["webhook_sent"] = send_webhook(webhook_url, alerts)

    destination = Path(output_path)
    if not destination.is_absolute():
        destination = ROOT / destination
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2), encoding="utf-8")

    LOGGER.info(
        "Pipeline complete: %d records parsed, %d alerts, %d scored sources.",
        len(entries),
        len(alerts),
        len(scores),
    )
    LOGGER.info("Report written to %s", destination)
    return report


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(description="Analyze JSON network logs with AttackWatch rules.")
    parser.add_argument("logs", nargs="?", default="sample_logs.json", help="Input log JSON file.")
    parser.add_argument("rules", nargs="?", default="rules.json", help="Detection rules JSON file.")
    parser.add_argument(
        "--geo",
        action="store_true",
        help="Enrich scored source IPs with optional GeoIP lookups.",
    )
    parser.add_argument(
        "--webhook",
        default=os.getenv("ATTACKWATCH_WEBHOOK"),
        help="Optional Discord-compatible webhook URL (or ATTACKWATCH_WEBHOOK env var).",
    )
    parser.add_argument(
        "--json-out",
        default="report.json",
        help="Path for the JSON report (default: report.json).",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    args = build_parser().parse_args(argv)
    try:
        run_pipeline(
            args.logs,
            args.rules,
            args.json_out,
            enable_geoip=args.geo,
            webhook_url=args.webhook,
        )
    except (OSError, json.JSONDecodeError, ValueError) as exc:
        LOGGER.error("Could not complete analysis: %s", exc)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
