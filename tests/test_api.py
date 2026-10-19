"""
test_api.py
AI-HYBRID-IDS - Tests automatises (section 56)

Teste les endpoints HTTP de api.py via le TestClient FastAPI. Complete
test_api_config.py (deja existant), qui teste validate_config() et
enrich_incident_context() comme fonctions isolees mais ne fait jamais
d'appel HTTP reel a travers l'application.

ISOLATION DES DONNEES (meme principe que test_detection.py): les chemins
internes du module api.py (PROJECT_ROOT, DETECTIONS_CSV_PATH,
INCIDENTS_DB_PATH, RESULTS_METRICS_DIR, CONFIG_PATH, PID_FILE_PATH) sont
substitues vers des fichiers temporaires en setUp et restaures en tearDown.
Aucun test ici ne lit ni ne modifie les vraies donnees du projet.

HORS PERIMETRE (volontairement, pour la securite de la machine qui fait
tourner les tests): POST /api/start et POST /api/stop ne sont PAS testes
ici. Ces endpoints lancent reellement live_detection.py via 'sudo -n' -
les tester en conditions reelles demarrerait un vrai processus de capture
reseau sur la machine, ce qui n'a rien a faire dans une suite de tests
automatises. Ils restent couverts manuellement (deja valides plus tot
dans le projet via start_ids.sh).
"""

import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "app"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "incidents"))

import api
import incident_engine
from fastapi.testclient import TestClient


def fake_lookup_ips(ip_list):
    """
    Remplace geoip_lookup.lookup_ips() pendant les tests: aucun appel
    reseau reel vers ip-api.com (tests rapides, deterministes, et
    fonctionnels sans connexion internet ni risque de rate-limit).
    """
    return {
        ip: {
            "public": not ip.startswith("192.168."),
            "status": "resolved" if not ip.startswith("192.168.") else "private",
            "country": "United States" if not ip.startswith("192.168.") else None,
            "city": "Testville" if not ip.startswith("192.168.") else None,
            "lat": 10.0 if not ip.startswith("192.168.") else None,
            "lon": 20.0 if not ip.startswith("192.168.") else None,
            "isp": "Test ISP" if not ip.startswith("192.168.") else None,
        }
        for ip in ip_list
    }


class ApiEndpointTestsBase(unittest.TestCase):
    """Isolation commune: chemins temporaires, restaures a chaque test."""

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        tmp_path = Path(self.tmp_dir.name)
        (tmp_path / "config").mkdir(parents=True, exist_ok=True)
        (tmp_path / "logs").mkdir(parents=True, exist_ok=True)
        (tmp_path / "results" / "metrics").mkdir(parents=True, exist_ok=True)
        (tmp_path / "data" / "incidents").mkdir(parents=True, exist_ok=True)
        (tmp_path / "models" / "registry").mkdir(parents=True, exist_ok=True)

        self._real = {
            "PROJECT_ROOT": api.PROJECT_ROOT,
            "DETECTIONS_CSV_PATH": api.DETECTIONS_CSV_PATH,
            "INCIDENTS_DB_PATH": api.INCIDENTS_DB_PATH,
            "RESULTS_METRICS_DIR": api.RESULTS_METRICS_DIR,
            "CONFIG_PATH": api.CONFIG_PATH,
            "PID_FILE_PATH": api.PID_FILE_PATH,
            "lookup_ips": api.lookup_ips,
        }

        self.tmp_path = tmp_path
        api.PROJECT_ROOT = str(tmp_path)
        api.DETECTIONS_CSV_PATH = str(tmp_path / "logs" / "detections.csv")
        api.INCIDENTS_DB_PATH = str(tmp_path / "data" / "incidents" / "incidents.db")
        api.RESULTS_METRICS_DIR = str(tmp_path / "results" / "metrics")
        api.CONFIG_PATH = str(tmp_path / "config" / "config.yaml")
        api.PID_FILE_PATH = str(tmp_path / "logs" / "live_detection.pid")
        api.lookup_ips = fake_lookup_ips

        self.client = TestClient(api.app)

    def tearDown(self):
        for key, value in self._real.items():
            setattr(api, key, value)
        self.tmp_dir.cleanup()

    def _init_incidents_db(self):
        conn = sqlite3.connect(api.INCIDENTS_DB_PATH)
        incident_engine.init_db(conn)
        return conn


class HealthAndStatusTests(ApiEndpointTestsBase):
    def test_health_returns_ok(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "ok")

    def test_status_with_no_pid_file_reports_not_running(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertFalse(body["detection_engine_running"])
        self.assertIsNone(body["detection_engine_pid"])


class FlowsEndpointTests(ApiEndpointTestsBase):
    def test_no_csv_returns_empty_list_not_an_error(self):
        response = self.client.get("/api/flows")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["flows"], [])

    def test_nan_values_are_sanitized_to_null_in_json(self):
        # Reproduit le cas reel documente dans sanitize_nan(): un flow ICMP
        # n'a pas de dest_port -> pandas lit NaN sur cette colonne.
        csv_content = "timestamp,src_ip,dest_port,risk_score\n2026-09-01T10:00:00,1.2.3.4,,0.1\n"
        Path(api.DETECTIONS_CSV_PATH).write_text(csv_content)

        response = self.client.get("/api/flows")
        self.assertEqual(response.status_code, 200)
        row = response.json()["flows"][0]
        self.assertIsNone(row["dest_port"])  # jamais NaN (invalide en JSON strict)

    def test_limit_parameter_is_respected(self):
        rows = "\n".join(f"2026-09-01T10:00:0{i},1.2.3.{i}" for i in range(5))
        Path(api.DETECTIONS_CSV_PATH).write_text("timestamp,src_ip\n" + rows + "\n")
        response = self.client.get("/api/flows", params={"limit": 2})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 2)


class IncidentsEndpointTests(ApiEndpointTestsBase):
    def test_incidents_endpoint_returns_503_without_db(self):
        response = self.client.get("/api/incidents")
        self.assertEqual(response.status_code, 503)

    def test_incident_lifecycle_end_to_end(self):
        conn = self._init_incidents_db()
        incident_id = incident_engine.record_event(
            conn, source_ip="10.0.0.5", dest_ip="10.0.0.6", dest_port=445,
            detail="Port Scan", event_type="ml_verdict", status="ATTACK",
            risk_score=0.9, timestamp="2026-09-01T10:00:00+00:00",
        )
        conn.close()

        list_response = self.client.get("/api/incidents")
        self.assertEqual(list_response.status_code, 200)
        self.assertEqual(list_response.json()["count"], 1)

        detail_response = self.client.get(f"/api/incidents/{incident_id}")
        self.assertEqual(detail_response.status_code, 200)
        body = detail_response.json()
        self.assertEqual(body["source_ip"], "10.0.0.5")
        self.assertEqual(len(body["events"]), 1)
        # Enrichissement MITRE (deja teste en unite dans test_api_config.py,
        # verifie ici seulement qu'il est bien applique par l'endpoint).
        self.assertEqual(body["mitre_techniques"][0]["id"], "T1046")

    def test_unknown_incident_id_returns_404(self):
        self._init_incidents_db()
        response = self.client.get("/api/incidents/INC-INCONNU")
        self.assertEqual(response.status_code, 404)

    def test_status_filter_excludes_other_statuses(self):
        conn = self._init_incidents_db()
        incident_engine.record_event(
            conn, source_ip="10.0.0.7", dest_ip=None, dest_port=None,
            detail="Brute Force", event_type="ml_verdict", status="SUSPICIOUS",
            risk_score=0.3, timestamp="2026-09-01T10:00:00+00:00",
        )
        conn.close()
        response = self.client.get("/api/incidents", params={"status": "RESOLVED"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["count"], 0)


class MetricsAndModelsEndpointTests(ApiEndpointTestsBase):
    def test_metrics_returns_503_when_summary_missing(self):
        response = self.client.get("/api/metrics")
        self.assertEqual(response.status_code, 503)

    def test_metrics_returns_summary_content_when_present(self):
        summary_path = Path(api.RESULTS_METRICS_DIR) / "ml_evaluation_summary.json"
        summary_path.write_text(json.dumps({"chosen_variants": {"RandomForest": "smote"}}))
        response = self.client.get("/api/metrics")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["chosen_variants"]["RandomForest"], "smote")

    def test_model_health_reports_artifacts_absent_in_isolated_env(self):
        # Dans l'environnement de test isole, aucun .pkl n'existe sous le
        # PROJECT_ROOT temporaire - artifacts_present doit refleter ca.
        response = self.client.get("/api/model_health")
        self.assertEqual(response.status_code, 200)
        self.assertFalse(response.json()["artifacts_present"])
        self.assertFalse(response.json()["automatic_retraining"])  # Regle 6, jamais True

    def test_model_health_reads_registry_when_present(self):
        registry_path = Path(api.PROJECT_ROOT) / "models" / "registry" / "registry.json"
        registry_path.write_text(json.dumps({"versions": [{"version": "v1.0.0", "status": "DEPLOYED"}]}))
        response = self.client.get("/api/model_health")
        self.assertEqual(response.json()["registry"]["versions"][0]["version"], "v1.0.0")


class GeoipEndpointTests(ApiEndpointTestsBase):
    """lookup_ips() est remplace par fake_lookup_ips() - aucun appel reseau reel."""

    def test_geoip_resolves_public_and_filters_private(self):
        response = self.client.get("/api/geoip", params={"ips": "8.8.8.8,192.168.1.1"})
        self.assertEqual(response.status_code, 200)
        results = response.json()["results"]
        self.assertTrue(results["8.8.8.8"]["public"])
        self.assertFalse(results["192.168.1.1"]["public"])

    def test_geoip_rejects_empty_ip_list(self):
        response = self.client.get("/api/geoip", params={"ips": ""})
        self.assertEqual(response.status_code, 422)

    def test_geoip_rejects_over_500_ips(self):
        too_many = ",".join(f"10.0.{i//256}.{i%256}" for i in range(501))
        response = self.client.get("/api/geoip", params={"ips": too_many})
        self.assertEqual(response.status_code, 422)


class ConfigEndpointTests(ApiEndpointTestsBase):
    def test_get_config_returns_404_when_absent(self):
        response = self.client.get("/api/config")
        self.assertEqual(response.status_code, 404)

    def test_post_then_get_round_trip(self):
        valid_config = {
            "correlation": {"window_seconds": 60},
            "decision_engine": {
                "weight_suricata": 0.40, "weight_ml_confidence": 0.25,
                "weight_model_agreement": 0.10, "weight_anomaly": 0.10,
                "weight_correlation": 0.15, "threshold_critical": 0.75,
                "threshold_attack": 0.45, "threshold_suspicious": 0.20,
            },
            "incident_engine": {"timeout_seconds": 300},
            "llm": {"enabled": True, "model": "qwen2.5:3b", "timeout_seconds": 320, "max_events_in_prompt": 10},
            "logs": {"retention_days": 30},
        }
        post_response = self.client.post("/api/config", json=valid_config)
        self.assertEqual(post_response.status_code, 200)

        get_response = self.client.get("/api/config")
        self.assertEqual(get_response.status_code, 200)
        self.assertEqual(get_response.json()["logs"]["retention_days"], 30)

    def test_post_invalid_config_returns_422_through_the_endpoint(self):
        # Complete test_api_config.py (qui teste validate_config() en
        # isolation) en verifiant que l'endpoint HTTP complet propage bien
        # la meme erreur 422, bout en bout.
        invalid_config = {"decision_engine": {"weight_suricata": 2.0}}
        response = self.client.post("/api/config", json=invalid_config)
        self.assertEqual(response.status_code, 422)


if __name__ == "__main__":
    unittest.main()
