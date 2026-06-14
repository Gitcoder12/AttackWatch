import unittest

from parser.log_parser import parse_logs


class TestLogParser(unittest.TestCase):

    def test_parse_logs(self):
        logs = [
            {
                "timestamp": "2023-04-01T12:00:00Z",
                "source_ip": "192.168.1.1",
                "destination_ip": "192.168.1.2",
                "event_type": "login_failure",
                "status": 403,
                "port": 80,
                "protocol": "TCP",
            }
        ]

        result = parse_logs(logs)

        self.assertEqual(len(result), 1)
        self.assertIsNotNone(result[0])
        self.assertEqual(
            result[0].source_ip,
            "192.168.1.1"
        )


if __name__ == "__main__":
    unittest.main()
