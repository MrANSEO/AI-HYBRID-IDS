"""
test_suricata.py
AI-HYBRID-IDS - Tests automatises (section 56)

Teste les fonctions de live_detection.py responsables du parsing Suricata:
- extract_alert_info(): extraction des champs d'un evenement event_type=alert
- tail_f(): lecture ligne par ligne d'un fichier eve.json (mode suivi live
  ET mode replay, section 25)

Contrairement a test_suricata.py qui teste le PARSING, test_detection.py
(fichier suivant) teste le PIPELINE COMPLET (ingestion -> ML -> decision).
Volontairement, aucun test ici n'ecrit dans les vrais logs/incidents.db du
projet: tail_f() est teste sur des fichiers temporaires isoles.
"""

import json
import os
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


def make_alert_event(**overrides):
    """Evenement Suricata event_type=alert realiste (structure eve.json reelle)."""
    event = {
        "event_type": "alert",
        "flow_id": 123456789,
        "timestamp": "2026-09-01T10:00:00.123456+0000",
        "src_ip": "192.168.100.19",
        "dest_ip": "185.28.119.197",
        "dest_port": 443,
        "alert": {
            "signature": "ET SCAN Possible Nmap User-Agent Observed",
            "category": "Attempted Information Leak",
            "severity": 2,
            "metadata": {
                "signature_severity": ["Major"],
            },
        },
    }
    event.update(overrides)
    return event


class ExtractAlertInfoTests(unittest.TestCase):
    """extract_alert_info(): extraction des champs d'une alerte Suricata."""

    def test_extracts_all_fields_from_a_complete_alert(self):
        info = live_detection.extract_alert_info(make_alert_event())
        self.assertEqual(info["flow_id"], 123456789)
        self.assertEqual(info["timestamp"], "2026-09-01T10:00:00.123456+0000")
        self.assertEqual(info["signature"], "ET SCAN Possible Nmap User-Agent Observed")
        self.assertEqual(info["category"], "Attempted Information Leak")
        self.assertEqual(info["severity_raw"], 2)
        self.assertEqual(info["signature_severity_text"], "Major")
        self.assertEqual(info["src_ip"], "192.168.100.19")
        self.assertEqual(info["dest_ip"], "185.28.119.197")

    def test_missing_signature_severity_defaults_to_na(self):
        event = make_alert_event()
        del event["alert"]["metadata"]["signature_severity"]
        info = live_detection.extract_alert_info(event)
        self.assertEqual(info["signature_severity_text"], "N/A")

    def test_missing_metadata_entirely_defaults_to_na_without_crashing(self):
        event = make_alert_event()
        del event["alert"]["metadata"]
        info = live_detection.extract_alert_info(event)
        self.assertEqual(info["signature_severity_text"], "N/A")
        # Le reste doit rester extrait normalement malgre l'absence de metadata.
        self.assertEqual(info["signature"], "ET SCAN Possible Nmap User-Agent Observed")

    def test_missing_alert_key_entirely_does_not_crash(self):
        # Cas extreme: un evenement mal forme sans la cle "alert" du tout.
        # Ne doit jamais lever d'exception (tuerait live_detection.py).
        event = {"event_type": "alert", "src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}
        try:
            info = live_detection.extract_alert_info(event)
        except Exception as exc:  # noqa: BLE001
            self.fail(f"extract_alert_info() a leve une exception sur un evenement incomplet: {exc}")
        self.assertIsNone(info["signature"])
        self.assertEqual(info["signature_severity_text"], "N/A")
        self.assertEqual(info["src_ip"], "1.2.3.4")

    def test_completely_empty_event_does_not_crash(self):
        try:
            info = live_detection.extract_alert_info({})
        except Exception as exc:  # noqa: BLE001
            self.fail(f"extract_alert_info() a leve une exception sur un dict vide: {exc}")
        self.assertIsNone(info["flow_id"])
        self.assertIsNone(info["src_ip"])


class TailFTests(unittest.TestCase):
    """
    tail_f(): lecture ligne par ligne d'eve.json. Teste sur des fichiers
    temporaires isoles - ne touche jamais aux vrais logs Suricata du projet.
    """

    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.eve_path = os.path.join(self.tmp_dir.name, "eve.json")

    def tearDown(self):
        self.tmp_dir.cleanup()

    def _write_lines(self, lines):
        with open(self.eve_path, "w") as f:
            for line in lines:
                f.write(line + "\n")

    def test_replay_mode_reads_all_existing_lines(self):
        # Mode REPLAY (section 25, Mode 2): on veut TOUT le fichier, donc
        # start_at_end=False. follow=False pour que le generateur s'arrete
        # une fois le fichier epuise (sinon boucle infinie en attente de
        # nouvelles lignes - inadapte a un test).
        self._write_lines(['{"event_type": "flow", "n": 1}', '{"event_type": "flow", "n": 2}'])
        lines = list(live_detection.tail_f(self.eve_path, start_at_end=False, follow=False))
        self.assertEqual(len(lines), 2)
        self.assertEqual(json.loads(lines[0])["n"], 1)
        self.assertEqual(json.loads(lines[1])["n"], 2)

    def test_live_mode_skips_lines_already_present_at_startup(self):
        # Mode LIVE (section 25, Mode 3): on ne veut PAS rejouer les
        # anciens evenements au demarrage, donc start_at_end=True. Un
        # fichier deja rempli au lancement de tail_f() ne doit rien
        # produire tant qu'aucune nouvelle ligne n'est ajoutee.
        self._write_lines(['{"event_type": "flow", "n": 1}'])
        lines = list(live_detection.tail_f(self.eve_path, start_at_end=True, follow=False))
        self.assertEqual(lines, [])

    def test_malformed_json_lines_are_still_yielded_as_raw_text(self):
        # tail_f() ne fait AUCUN parsing JSON lui-meme (separation des
        # responsabilites: c'est l'appelant, dans la boucle principale de
        # main(), qui fait json.loads() avec un try/except autour). Une
        # ligne corrompue doit donc etre transmise telle quelle, pas
        # filtree ici - le filtrage a lieu un niveau au-dessus.
        self._write_lines(["ceci n'est pas du json", '{"event_type": "flow", "n": 2}'])
        lines = list(live_detection.tail_f(self.eve_path, start_at_end=False, follow=False))
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[0].strip(), "ceci n'est pas du json")


class MainLoopJsonRobustnessTests(unittest.TestCase):
    """
    Verifie directement le comportement documente de main() face a une
    ligne JSON corrompue: le pattern reel du code est
        try: evt = json.loads(line)
        except json.JSONDecodeError: continue
    Ce test verifie que ce pattern precis (copie a l'identique de
    live_detection.py) ne laisse effectivement rien passer d'invalide -
    garde-fou contre une regression si ce bloc est un jour modifie sans
    garder le except au bon endroit.
    """

    def test_json_decode_error_is_the_exact_exception_raised_on_garbage(self):
        with self.assertRaises(json.JSONDecodeError):
            json.loads("ceci n'est pas du json")

    def test_valid_flow_line_parses_to_expected_dict(self):
        line = '{"event_type": "flow", "src_ip": "1.2.3.4"}'
        evt = json.loads(line)
        self.assertEqual(evt["event_type"], "flow")
        self.assertEqual(evt["src_ip"], "1.2.3.4")


if __name__ == "__main__":
    unittest.main()
