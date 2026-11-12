"""Integration tests for the AttackWatch JSON pipeline."""

import json
import tempfile
import unittest
from pathlib import Path

from main import run_pipeline


class PipelineTests(unittest.TestCase):
    def test_pipeline_writes_alerts_and_scores(self):
        logs = {
            "logs": [
                {
                    "timestamp": "2026-11-12T10:00:00Z",
                    "source_ip": "203.0.113.20",
                    "destination_ip": "198.51.100.10",
                    "event_type": "ssh_login_failure",
                    "status": 403,
                    "port": 22,
                    "protocol": "TCP",
                    "count": 8,
                }
            ]
        }
        rules = {
            "rules": [
                {
                    "id": "SSH-01",
                    "name": "SSH Login Failures",
                    "port": 22,
                    "threshold": 5,
                    "severity": "HIGH",
                }
            ]
        }

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            logs_path = root / "logs.json"
            rules_path = root / "rules.json"
            output_path = root / "report.json"
            logs_path.write_text(json.dumps(logs), encoding="utf-8")
            rules_path.write_text(json.dumps(rules), encoding="utf-8")

            report = run_pipeline(logs_path, rules_path, output_path)

            self.assertEqual(
                report["summary"],
                {
                    "input_records": 1,
                    "parsed_records": 1,
                    "alerts": 1,
                    "scored_sources": 1,
                },
            )
            self.assertEqual(report["alerts"][0]["source_ip"], "203.0.113.20")
            self.assertEqual(report["scores"][0]["severity"], "HIGH")
            self.assertEqual(
                json.loads(output_path.read_text(encoding="utf-8")),
                report,
            )


if __name__ == "__main__":
    unittest.main()
