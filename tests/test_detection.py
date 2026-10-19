"""
test_detection.py
AI-HYBRID-IDS - Tests automatises (section 56)

Teste le pipeline COMPLET de live_detection.py: main() de bout en bout,
sur un fichier eve.json temporaire. A la difference de test_suricata.py
(parsing pur) et test_models.py (ML seul), ce fichier verifie que tout
est bien CABLE ensemble: ingestion -> extraction features -> vote ML ->
Decision Engine -> Incident Engine -> logs/detections.csv.

ISOLATION DES DONNEES (important): main() ecrit normalement dans les VRAIS
logs/detections.csv et data/incidents/incidents.db du projet. Ces tests
substituent temporairement les chemins internes du module (PROJECT_ROOT,
LOGS_DIR, DETECTIONS_CSV_PATH, INCIDENTS_DB_PATH) vers des fichiers
temporaires, et les restaurent systematiquement apres chaque test (via
tearDown) - aucune donnee reelle du projet n'est jamais lue ni modifiee.

Necessite les vrais artefacts modeles sur disque (comme test_models.py) -
ignore proprement (skip) si absents.
"""

import json
import os
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src" / "detection"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "features"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "utils"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "correlation"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "incidents"))

import live_detection


def _artifacts_present():
    required = [
        PROJECT_ROOT / "models" / "preprocessing" / "scaler.pkl",
        PROJECT_ROOT / "models" / "preprocessing" / "label_encoder.pkl",
        PROJECT_ROOT / "models" / "supervised" / "random_forest_smote.pkl",
        PROJECT_ROOT / "models" / "supervised" / "xgboost_smote.pkl",
        PROJECT_ROOT / "models" / "supervised" / "lightgbm_classweight.pkl",
        PROJECT_ROOT / "models" / "unsupervised" / "isolation_forest.pkl",
    ]
    return all(path.exists() for path in required)


def make_flow_line(flow_id, src_ip="192.168.100.19", dest_ip="8.8.8.8", dest_port=443):
    """Une ligne eve.json event_type=flow complete et realiste (JSON deja serialise)."""
    event = {
        "event_type": "flow",
        "timestamp": "2026-09-01T10:00:00.000000+0000",
        "flow_id": flow_id,
        "src_ip": src_ip,
        "src_port": 51000,
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": "TCP",
        "flow": {
            "start": "2026-09-01T10:00:00+00:00",
            "end": "2026-09-01T10:00:05+00:00",
            "pkts_toserver": 10,
            "pkts_toclient": 8,
            "bytes_toserver": 1000,
            "bytes_toclient": 8000,
        },
        "tcp": {"fin": True, "psh": False, "ack": True},
    }
    return json.dumps(event)


def make_alert_line(flow_id, src_ip="192.168.100.50", dest_ip="185.28.119.197"):
    """Une ligne eve.json event_type=alert complete et realiste."""
    event = {
        "event_type": "alert",
        "timestamp": "2026-09-01T10:00:00.000000+0000",
        "flow_id": flow_id,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "dest_port": 445,
        "alert": {
            "signature": "ET SCAN Possible Nmap User-Agent Observed",
            "category": "Attempted Information Leak",
            "severity": 2,
            "metadata": {"signature_severity": ["Major"]},
        },
    }
    return json.dumps(event)


@unittest.skipUnless(_artifacts_present(), "Artefacts modeles absents - lancer l'entrainement d'abord (Phases 4-7)")
class DetectionPipelineIntegrationTests(unittest.TestCase):
    """
    Pipeline complet sur des fichiers temporaires - jamais les vraies
    donnees du projet (voir docstring du module pour le detail de
    l'isolation).
    """

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        tmp_path = Path(self.tmp_dir.name)

        self.eve_path = tmp_path / "eve.json"
        self.detections_csv_path = tmp_path / "logs" / "detections.csv"
        self.incidents_db_path = tmp_path / "data" / "incidents" / "incidents.db"

        # Sauvegarde des VRAIES valeurs pour restauration systematique en
        # tearDown - garantit qu'un test qui echoue ne laisse jamais le
        # module pointer vers des chemins temporaires supprimes.
        self._real_project_root = live_detection.PROJECT_ROOT
        self._real_logs_dir = live_detection.LOGS_DIR
        self._real_detections_csv_path = live_detection.DETECTIONS_CSV_PATH
        self._real_incidents_db_path = live_detection.INCIDENTS_DB_PATH

        live_detection.PROJECT_ROOT = str(tmp_path)  # pas de config/config.yaml -> defauts utilises
        live_detection.LOGS_DIR = str(tmp_path / "logs")
        live_detection.DETECTIONS_CSV_PATH = str(self.detections_csv_path)
        live_detection.INCIDENTS_DB_PATH = str(self.incidents_db_path)

    def tearDown(self):
        live_detection.PROJECT_ROOT = self._real_project_root
        live_detection.LOGS_DIR = self._real_logs_dir
        live_detection.DETECTIONS_CSV_PATH = self._real_detections_csv_path
        live_detection.INCIDENTS_DB_PATH = self._real_incidents_db_path
        self.tmp_dir.cleanup()

    def _write_eve_lines(self, lines):
        with open(self.eve_path, "w") as f:
            for line in lines:
                f.write(line + "\n")

    def _run_main_once(self):
        """Traite tout le fichier temporaire puis s'arrete (mode replay, section 25)."""
        live_detection.main(str(self.eve_path), start_at_end=False, follow=False)

    def _read_csv_rows(self):
        import csv
        if not self.detections_csv_path.exists():
            return []
        with open(self.detections_csv_path, newline="") as f:
            return list(csv.DictReader(f))

    def _read_incident_events(self, src_ip):
        conn = sqlite3.connect(self.incidents_db_path)
        cur = conn.execute(
            "SELECT event_type, status, src_ip FROM incident_events WHERE src_ip=?", (src_ip,)
        )
        rows = cur.fetchall()
        conn.close()
        return rows

    # -- Regle 7 (section 9/65): une alerte Suricata cree TOUJOURS un incident ---

    def test_suricata_alert_always_creates_incident_regardless_of_ml(self):
        # Un evenement alert SEUL (aucun flow correspondant) doit quand
        # meme produire un incident avec statut plancher SUSPICIOUS - la
        # regle absolue #7 ne depend d'aucune sortie du modele ML.
        self._write_eve_lines([make_alert_line(flow_id=1, src_ip="192.168.100.50")])
        self._run_main_once()

        events = self._read_incident_events("192.168.100.50")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0][0], "suricata_alert")
        self.assertEqual(events[0][1], "SUSPICIOUS")

    # -- Pipeline flow -> CSV ------------------------------------------------

    def test_valid_flow_produces_one_csv_row_with_expected_columns(self):
        self._write_eve_lines([make_flow_line(flow_id=100)])
        self._run_main_once()

        rows = self._read_csv_rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["src_ip"], "192.168.100.19")
        self.assertEqual(row["dest_ip"], "8.8.8.8")
        self.assertIn(row["status"], {"NORMAL", "SUSPICIOUS", "ATTACK", "CRITICAL", "UNKNOWN"})
        # Les 12 features du contrat doivent toutes apparaitre comme colonnes.
        from feature_extraction import FEATURE_ORDER
        for feature_name in FEATURE_ORDER:
            self.assertIn(feature_name, row)

    def test_incident_created_only_when_status_warrants_it(self):
        # Coherence Decision Engine <-> Incident Engine (section 29): un
        # incident ne doit exister QUE si le statut est SUSPICIOUS/ATTACK/
        # CRITICAL - jamais pour NORMAL ou UNKNOWN. On verifie la
        # coherence quelle que soit la prediction reelle du modele (on ne
        # force pas une classe precise, on verifie la REGLE de cablage).
        self._write_eve_lines([make_flow_line(flow_id=200, src_ip="192.168.100.77")])
        self._run_main_once()

        rows = self._read_csv_rows()
        self.assertEqual(len(rows), 1)
        status = rows[0]["status"]

        events = self._read_incident_events("192.168.100.77")
        if status in ("SUSPICIOUS", "ATTACK", "CRITICAL"):
            self.assertEqual(len(events), 1, f"Statut {status} aurait du creer un incident")
            self.assertEqual(events[0][0], "ml_verdict")
        else:
            self.assertEqual(len(events), 0, f"Statut {status} n'aurait pas du creer d'incident")

    # -- Robustesse: dedup et lignes corrompues ------------------------------

    def test_duplicate_flow_id_is_processed_only_once(self):
        # Suricata peut emettre plusieurs enregistrements pour le meme
        # flow_id (mises a jour de compteurs) - le second doit etre ignore.
        line = make_flow_line(flow_id=300)
        self._write_eve_lines([line, line])
        self._run_main_once()

        rows = self._read_csv_rows()
        self.assertEqual(len(rows), 1)

    def test_malformed_line_does_not_interrupt_processing(self):
        self._write_eve_lines([
            make_flow_line(flow_id=400, src_ip="10.0.0.1"),
            "ceci n'est pas du json",
            make_flow_line(flow_id=401, src_ip="10.0.0.2"),
        ])
        self._run_main_once()

        rows = self._read_csv_rows()
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["src_ip"] for r in rows}, {"10.0.0.1", "10.0.0.2"})

    def test_alert_and_flow_events_can_both_be_processed_in_one_run(self):
        # Scenario mixte realiste: une alerte et un flow independant dans
        # le meme fichier - les deux chemins de traitement (alert / flow)
        # doivent cohabiter sans interference.
        self._write_eve_lines([
            make_alert_line(flow_id=500, src_ip="192.168.100.60"),
            make_flow_line(flow_id=501, src_ip="192.168.100.19"),
        ])
        self._run_main_once()

        rows = self._read_csv_rows()
        self.assertEqual(len(rows), 1)  # seul le flow produit une ligne CSV
        alert_events = self._read_incident_events("192.168.100.60")
        self.assertEqual(len(alert_events), 1)
        self.assertEqual(alert_events[0][0], "suricata_alert")


if __name__ == "__main__":
    unittest.main()
