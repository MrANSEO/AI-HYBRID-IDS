import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "app"))

import api
from fastapi import HTTPException


class ApiConfigTests(unittest.TestCase):
    def setUp(self):
        self.config = {
            "correlation": {"window_seconds": 60},
            "decision_engine": {
                "weight_suricata": 0.40,
                "weight_ml_confidence": 0.25,
                "weight_model_agreement": 0.10,
                "weight_anomaly": 0.10,
                "weight_correlation": 0.15,
                "threshold_critical": 0.75,
                "threshold_attack": 0.45,
                "threshold_suspicious": 0.20,
            },
            "incident_engine": {"timeout_seconds": 300},
            "llm": {
                "enabled": True,
                "model": "qwen2.5:3b",
                "timeout_seconds": 320,
                "max_events_in_prompt": 10,
            },
            "logs": {"retention_days": 30},
        }

    def test_valid_configuration_is_accepted(self):
        self.assertIsNone(api.validate_config(self.config))

    def test_invalid_weight_sum_is_rejected(self):
        self.config["decision_engine"]["weight_correlation"] = 0.30
        with self.assertRaises(HTTPException) as error:
            api.validate_config(self.config)
        self.assertEqual(error.exception.status_code, 422)

    def test_incident_context_contains_observed_iocs_and_mitre_basis(self):
        incident = {
            "source_ip": "10.0.0.1",
            "destination_ips": ["10.0.0.2"],
            "attack_types": ["Port Scan"],
        }
        enriched = api.enrich_incident_context(incident, [{"dest_port": 22}])
        self.assertEqual(enriched["iocs"]["destination_ports"], [22])
        self.assertEqual(enriched["mitre_techniques"][0]["id"], "T1046")


if __name__ == "__main__":
    unittest.main()
