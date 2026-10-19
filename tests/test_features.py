"""
test_features.py
AI-HYBRID-IDS - Tests automatises (section 56)

Couvre feature_extraction.py: le contrat de 12 features (Feature Contract,
section 12) et les cas limites qu'on rencontre reellement avec des flows
Suricata (evenements incomplets, duree nulle, flags TCP absents...).

Regle absolue verifiee ici (section 12, "regle absolue"): une feature
utilisee par le modele doit etre reconstructible a l'inference reelle -
donc extract_features() ne doit JAMAIS lever d'exception sur un evenement
malforme, seulement retourner None.
"""

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src" / "features"))

import feature_extraction
from feature_extraction import extract_features, parse_suricata_timestamp, FEATURE_ORDER


def make_flow_event(**overrides):
    """Construit un evenement Suricata event_type=flow valide, avec
    possibilite de surcharger des champs pour tester des cas limites."""
    event = {
        "event_type": "flow",
        "dest_port": 443,
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
    event.update(overrides)
    return event


class FeatureContractTests(unittest.TestCase):
    """Verifie que le contrat de 12 features (section 12) est respecte."""

    def test_feature_order_has_exactly_12_features(self):
        self.assertEqual(len(FEATURE_ORDER), 12)

    def test_valid_flow_returns_features_in_contract_order(self):
        features = extract_features(make_flow_event())
        self.assertIsNotNone(features)
        self.assertEqual(list(features.keys()), FEATURE_ORDER)

    def test_valid_flow_values_are_computed_correctly(self):
        # Flow de 5 secondes, 18 paquets, 9000 bytes au total - valeurs
        # calculees a la main pour verifier qu'aucune formule n'a diverge.
        features = extract_features(make_flow_event())
        self.assertEqual(features["destination_port"], 443)
        self.assertEqual(features["flow_duration"], 5_000_000)  # microsecondes
        self.assertEqual(features["total_fwd_packets"], 10)
        self.assertEqual(features["total_fwd_bytes"], 1000)
        self.assertAlmostEqual(features["flow_bytes_per_sec"], 1800.0)
        self.assertAlmostEqual(features["flow_packets_per_sec"], 3.6)
        self.assertAlmostEqual(features["fwd_packets_per_sec"], 2.0)
        self.assertAlmostEqual(features["bwd_packets_per_sec"], 1.6)
        self.assertAlmostEqual(features["avg_packet_size"], 500.0)
        self.assertEqual(features["fin_flag_present"], 1)
        self.assertEqual(features["psh_flag_present"], 0)
        self.assertEqual(features["ack_flag_present"], 1)


class FeatureExtractionEdgeCaseTests(unittest.TestCase):
    """
    Cas limites qu'on rencontre reellement en production (pas juste en
    theorie): evenements Suricata incomplets, flows instantanes, absence
    de section tcp (flows UDP/ICMP notamment).
    """

    def test_wrong_event_type_returns_none(self):
        event = make_flow_event(event_type="alert")
        self.assertIsNone(extract_features(event))

    def test_missing_flow_key_returns_none(self):
        event = make_flow_event()
        del event["flow"]
        self.assertIsNone(extract_features(event))

    def test_missing_start_timestamp_returns_none_without_crashing(self):
        event = make_flow_event()
        del event["flow"]["start"]
        self.assertIsNone(extract_features(event))

    def test_invalid_timestamp_format_returns_none_without_crashing(self):
        event = make_flow_event()
        event["flow"]["start"] = "pas-une-date"
        self.assertIsNone(extract_features(event))

    def test_zero_duration_flow_does_not_raise_zero_division(self):
        # Suricata peut emettre un flow avec start == end (paquet unique,
        # duree arrondie a 0). Les taux par seconde doivent tomber a 0.0,
        # jamais lever ZeroDivisionError.
        event = make_flow_event()
        event["flow"]["start"] = "2026-09-01T10:00:00+00:00"
        event["flow"]["end"] = "2026-09-01T10:00:00+00:00"
        features = extract_features(event)
        self.assertIsNotNone(features)
        self.assertEqual(features["flow_duration"], 0)
        self.assertEqual(features["flow_bytes_per_sec"], 0.0)
        self.assertEqual(features["flow_packets_per_sec"], 0.0)
        self.assertEqual(features["fwd_packets_per_sec"], 0.0)
        self.assertEqual(features["bwd_packets_per_sec"], 0.0)

    def test_zero_packets_does_not_raise_zero_division_on_avg_size(self):
        # Flow sans aucun paquet compte (rare mais observe sur du trafic
        # reel bruite) - avg_packet_size doit tomber a 0.0, pas planter.
        event = make_flow_event()
        event["flow"]["pkts_toserver"] = 0
        event["flow"]["pkts_toclient"] = 0
        event["flow"]["bytes_toserver"] = 0
        event["flow"]["bytes_toclient"] = 0
        features = extract_features(event)
        self.assertIsNotNone(features)
        self.assertEqual(features["avg_packet_size"], 0.0)

    def test_missing_tcp_section_defaults_flags_to_zero(self):
        # Flows UDP/ICMP: pas de section "tcp" du tout dans l'evenement
        # Suricata. Les 3 flags doivent valoir 0, pas lever de KeyError.
        event = make_flow_event()
        del event["tcp"]
        features = extract_features(event)
        self.assertIsNotNone(features)
        self.assertEqual(features["fin_flag_present"], 0)
        self.assertEqual(features["psh_flag_present"], 0)
        self.assertEqual(features["ack_flag_present"], 0)

    def test_missing_dest_port_defaults_to_zero(self):
        event = make_flow_event()
        del event["dest_port"]
        features = extract_features(event)
        self.assertIsNotNone(features)
        self.assertEqual(features["destination_port"], 0)

    def test_extract_features_never_raises_on_completely_empty_event(self):
        # Robustesse generale: un dict vide ne doit jamais faire planter
        # le pipeline de detection live (une exception ici tuerait
        # live_detection.py sur un evenement Suricata mal forme).
        try:
            result = extract_features({})
        except Exception as exc:  # noqa: BLE001 - on veut capturer TOUT type
            self.fail(f"extract_features() a leve une exception sur un evenement vide: {exc}")
        self.assertIsNone(result)


class TimestampParsingTests(unittest.TestCase):
    def test_parses_valid_iso_timestamp(self):
        dt = parse_suricata_timestamp("2026-09-01T10:00:00+00:00")
        self.assertEqual(dt.year, 2026)
        self.assertEqual(dt.month, 9)
        self.assertEqual(dt.day, 1)

    def test_invalid_timestamp_raises_value_error(self):
        # parse_suricata_timestamp() elle-meme n'est pas censee avaler
        # l'erreur (c'est extract_features() qui le fait, via son
        # try/except) - on verifie que la responsabilite est bien
        # separee comme prevu par le code source.
        with self.assertRaises(ValueError):
            parse_suricata_timestamp("pas-une-date")


if __name__ == "__main__":
    unittest.main()
