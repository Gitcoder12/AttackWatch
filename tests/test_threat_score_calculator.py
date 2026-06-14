import unittest

from detection.fail_login_detector import FailedLogin
from scoring.threat_score_calculator import calculate_threat_scores, get_severity


class TestThreatScoreCalculator(unittest.TestCase):

    def test_get_severity_thresholds(self):
        self.assertEqual(get_severity(80), "CRITICAL")
        self.assertEqual(get_severity(60), "HIGH")
        self.assertEqual(get_severity(30), "MEDIUM")
        self.assertEqual(get_severity(10), "LOW")

    def test_calculate_threat_scores(self):
        failed_logins = [
            FailedLogin(source_ip="192.168.1.1", count=3),
            FailedLogin(source_ip="10.0.0.5", count=10),
        ]

        scores = calculate_threat_scores(failed_logins)

        self.assertEqual(scores[0].source_ip, "192.168.1.1")
        self.assertEqual(scores[0].score, 60)
        self.assertEqual(scores[0].severity, "HIGH")

        self.assertEqual(scores[1].source_ip, "10.0.0.5")
        self.assertEqual(scores[1].score, 100)
        self.assertEqual(scores[1].severity, "CRITICAL")


if __name__ == "__main__":
    unittest.main()
