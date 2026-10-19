import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "llm"))

import report_generator


class ReportGeneratorTests(unittest.TestCase):
    def test_prompt_limits_events_from_configuration(self):
        incident = {
            "id": "INC-TEST",
            "source_ip": "10.0.0.1",
            "destination_ips": ["10.0.0.2"],
            "attack_types": ["Port Scan"],
            "severity": "ATTACK",
            "max_risk_score": 0.8,
            "status": "OPEN",
            "events_count": 3,
            "first_seen": "2026-09-19T10:00:00+00:00",
            "last_seen": "2026-09-19T10:02:00+00:00",
            "events": [
                {
                    "timestamp": f"2026-09-19T10:0{i}:00+00:00",
                    "event_type": "ml_verdict",
                    "src_ip": "10.0.0.1",
                    "dest_ip": "10.0.0.2",
                    "dest_port": 22,
                    "detail": "Port Scan",
                    "status": "ATTACK",
                    "risk_score": 0.8,
                }
                for i in range(3)
            ],
        }
        prompt = report_generator.build_prompt(incident)
        self.assertIn("INC-TEST", prompt)
        self.assertIn("Port Scan", prompt)

    def test_disabled_llm_does_not_call_ollama(self):
        original_loader = report_generator._load_llm_config
        report_generator._load_llm_config = lambda: {"enabled": False}
        try:
            result = report_generator.generate_incident_report({})
        finally:
            report_generator._load_llm_config = original_loader
        self.assertFalse(result["success"])
        self.assertIn("desactivee", result["error"])


if __name__ == "__main__":
    unittest.main()
