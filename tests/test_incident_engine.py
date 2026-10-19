import sqlite3
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src" / "incidents"))

import incident_engine
sys.path.insert(0, str(PROJECT_ROOT / "src" / "correlation"))
from correlation_engine import CorrelationEngine


class IncidentEngineTests(unittest.TestCase):
    def setUp(self):
        self.connection = sqlite3.connect(":memory:")
        incident_engine.init_db(self.connection)
        self.original_timeout = incident_engine.INCIDENT_TIMEOUT_SECONDS
        incident_engine.INCIDENT_TIMEOUT_SECONDS = 300

    def tearDown(self):
        incident_engine.INCIDENT_TIMEOUT_SECONDS = self.original_timeout
        self.connection.close()

    def test_events_from_same_source_are_grouped(self):
        first_id = incident_engine.record_event(
            self.connection, "10.0.0.1", "10.0.0.2", 443,
            "DDoS", "ml_verdict", "ATTACK", 0.7,
            "2026-09-19T10:00:00+00:00", 1,
        )
        second_id = incident_engine.record_event(
            self.connection, "10.0.0.1", "10.0.0.3", 80,
            "DDoS", "ml_verdict", "CRITICAL", 0.9,
            "2026-09-19T10:02:00+00:00", 2,
        )

        self.assertEqual(first_id, second_id)
        incident = self.connection.execute(
            "SELECT severity, events_count, max_risk_score FROM incidents WHERE id=?",
            (first_id,),
        ).fetchone()
        self.assertEqual(incident, ("CRITICAL", 2, 0.9))

    def test_silence_creates_new_incident_and_resolves_old_one(self):
        first_id = incident_engine.record_event(
            self.connection, "10.0.0.4", "10.0.0.5", 22,
            "Port Scan", "ml_verdict", "SUSPICIOUS", 0.3,
            "2026-09-19T10:00:00+00:00",
        )
        second_id = incident_engine.record_event(
            self.connection, "10.0.0.4", "10.0.0.6", 22,
            "Port Scan", "ml_verdict", "SUSPICIOUS", 0.3,
            "2026-09-19T10:06:00+00:00",
        )

        self.assertNotEqual(first_id, second_id)
        old_status = self.connection.execute(
            "SELECT status FROM incidents WHERE id=?", (first_id,)
        ).fetchone()[0]
        self.assertEqual(old_status, "RESOLVED")

    def test_normal_and_unknown_do_not_create_incidents(self):
        result = incident_engine.record_event(
            self.connection, "10.0.0.7", "10.0.0.8", 53,
            "Normal Traffic", "ml_verdict", "NORMAL", 0.0,
            "2026-09-19T10:00:00+00:00",
        )
        self.assertIsNone(result)
        count = self.connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        self.assertEqual(count, 0)

    def test_scan_signal_requires_many_distinct_ports(self):
        engine = CorrelationEngine(window_seconds=60)
        for port in range(10):
            engine.add_flow_verdict(
                "10.0.0.9", "10.0.0.10", port, "Normal Traffic",
                0.9, "3/3", False, 0.1, port, None,
            )
        _, signals = engine.evaluate_signals("10.0.0.9", scan_port_threshold=10)
        self.assertTrue(any(signal.startswith("POSSIBLE_SCAN") for signal in signals))

    def test_flood_signal_uses_rate_thresholds(self):
        engine = CorrelationEngine(window_seconds=60)
        engine.add_flow_verdict(
            "10.0.0.11", "10.0.0.12", 80, "Normal Traffic",
            0.9, "3/3", False, 0.1, 1, None,
            packets=2000, bytes_total=2000000,
            packets_per_sec=2000, bytes_per_sec=2000000,
        )
        _, signals = engine.evaluate_signals(
            "10.0.0.11", flood_packets_per_sec_threshold=1000,
            flood_bytes_per_sec_threshold=1000000,
        )
        self.assertTrue(any(signal.startswith("POSSIBLE_FLOOD") for signal in signals))


if __name__ == "__main__":
    unittest.main()
