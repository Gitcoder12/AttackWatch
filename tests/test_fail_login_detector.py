import unittest

from detection.fail_login_detector import detect_failed_logins
from parser.log_parser import parse_logs


class TestFailLoginDetector(unittest.TestCase):

    def test_detect_failed_logins(self):
        log_entries = [
            {
                "timestamp": "2023-04-01T12:00:00Z",
                "source_ip": "192.168.1.1",
                "destination_ip": "192.168.1.2",
                "event_type": "login_failure",
                "status": 403,
                "port": 80,
                "protocol": "TCP",
            },
            {
                "timestamp": "2023-04-01T12:01:00Z",
                "source_ip": "192.168.1.1",
                "destination_ip": "192.168.1.2",
                "event_type": "login_failure",
                "status": 403,
                "port": 80,
                "protocol": "TCP",
            },
            {
                "timestamp": "2023-04-01T12:02:00Z",
                "source_ip": "192.168.1.1",
                "destination_ip": "192.168.1.2",
                "event_type": "login_failure",
                "status": 403,
                "port": 80,
                "protocol": "TCP",
            },
        ]

        parsed_entries = [
            parse_logs([entry])[0]
            for entry in log_entries
        ]

        failed_logins = detect_failed_logins(parsed_entries)

        self.assertEqual(len(failed_logins), 1)
        self.assertEqual(
            failed_logins[0].source_ip,
            "192.168.1.1"
        )
        self.assertEqual(
            failed_logins[0].count,
            3
        )


if __name__ == "__main__":
    unittest.main()
