"""
test_models.py
AI-HYBRID-IDS - Tests automatises (section 56)

Teste load_artifacts() et predict_flow() de live_detection.py: chargement
des vrais artefacts (scaler, label encoder, 3 modeles supervises, Isolation
Forest), et le pipeline complet features -> scaling -> vote -> anomalie.

Ce sont des tests d'INTEGRATION (pas des mocks): ils chargent les vrais
fichiers .pkl entraines et verifient qu'ils fonctionnent ensemble tels
qu'ils seront reellement utilises par live_detection.py. Si les artefacts
n'existent pas sur la machine (ex: clone frais du depot sans avoir relance
l'entrainement), la classe est ignoree proprement plutot que d'echouer.
"""

import os
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src" / "detection"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "features"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "utils"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "correlation"))
sys.path.insert(0, str(PROJECT_ROOT / "src" / "incidents"))

import live_detection
from feature_extraction import FEATURE_ORDER


def make_valid_features():
    """
    Meme flow synthetique que test_features.py (5s, 18 paquets, 9000 bytes)
    - des valeurs numeriques plausibles, dans l'ordre exact du contrat.
    """
    return {
        "destination_port": 443,
        "flow_duration": 5_000_000,
        "total_fwd_packets": 10,
        "total_fwd_bytes": 1000,
        "flow_bytes_per_sec": 1800.0,
        "flow_packets_per_sec": 3.6,
        "fwd_packets_per_sec": 2.0,
        "bwd_packets_per_sec": 1.6,
        "avg_packet_size": 500.0,
        "fin_flag_present": 1,
        "psh_flag_present": 0,
        "ack_flag_present": 1,
    }


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


@unittest.skipUnless(_artifacts_present(), "Artefacts modeles absents - lancer l'entrainement d'abord (Phases 4-7)")
class ModelLoadingTests(unittest.TestCase):
    """Verifie que load_artifacts() charge correctement les 6 fichiers .pkl attendus."""

    @classmethod
    def setUpClass(cls):
        cls.scaler, cls.label_encoder, cls.models, cls.iso_forest = live_detection.load_artifacts()

    def test_all_three_supervised_models_loaded(self):
        self.assertEqual(set(self.models.keys()), {"RandomForest", "XGBoost", "LightGBM"})

    def test_each_model_exposes_predict_proba(self):
        # Regle absolue implicite du vote (section 7): les 3 modeles doivent
        # renvoyer des probabilites, pas seulement une classe brute.
        for name, model in self.models.items():
            self.assertTrue(hasattr(model, "predict_proba"), f"{name} n'expose pas predict_proba")

    def test_isolation_forest_loaded(self):
        self.assertTrue(hasattr(self.iso_forest, "predict"))
        self.assertTrue(hasattr(self.iso_forest, "decision_function"))

    def test_label_encoder_matches_taxonomy_cicids2017(self):
        # Section 14: la taxonomie doit venir de CICIDS2017, pas etre
        # inventee (pas de R2L/U2R/Spy/Probe).
        classes = set(self.label_encoder.classes_)
        forbidden = {"R2L", "U2R", "Spy", "Probe"}
        self.assertEqual(classes & forbidden, set())


@unittest.skipUnless(_artifacts_present(), "Artefacts modeles absents - lancer l'entrainement d'abord (Phases 4-7)")
class PredictFlowPipelineTests(unittest.TestCase):
    """
    Teste predict_flow() de bout en bout: scaling -> vote des 3 modeles ->
    calcul de confiance -> score Isolation Forest.
    """

    @classmethod
    def setUpClass(cls):
        cls.scaler, cls.label_encoder, cls.models, cls.iso_forest = live_detection.load_artifacts()

    def test_valid_features_produce_complete_result(self):
        result = live_detection.predict_flow(
            make_valid_features(), self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertIsNotNone(result)
        expected_keys = {
            "individual_predictions", "majority_class", "model_agreement",
            "confidence", "is_anomaly", "anomaly_score", "inference_time_ms",
        }
        self.assertEqual(set(result.keys()), expected_keys)

    def test_three_models_each_voted(self):
        result = live_detection.predict_flow(
            make_valid_features(), self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertEqual(set(result["individual_predictions"].keys()), {"RandomForest", "XGBoost", "LightGBM"})

    def test_majority_class_is_a_known_label(self):
        result = live_detection.predict_flow(
            make_valid_features(), self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertIn(result["majority_class"], set(self.label_encoder.classes_))

    def test_model_agreement_format_and_consistency(self):
        # Regle interne (section 7): model_agreement doit refleter le
        # NOMBRE REEL de modeles d'accord avec la classe majoritaire,
        # pas juste un texte fixe "3/3".
        result = live_detection.predict_flow(
            make_valid_features(), self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        agreement_str = result["model_agreement"]
        self.assertRegex(agreement_str, r"^[1-3]/3$")

        agreement_count = int(agreement_str.split("/")[0])
        votes_for_majority = sum(
            1 for pred in result["individual_predictions"].values() if pred == result["majority_class"]
        )
        self.assertEqual(agreement_count, votes_for_majority)

    def test_confidence_is_a_valid_probability(self):
        result = live_detection.predict_flow(
            make_valid_features(), self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertGreaterEqual(result["confidence"], 0.0)
        self.assertLessEqual(result["confidence"], 1.0)

    def test_is_anomaly_is_boolean(self):
        result = live_detection.predict_flow(
            make_valid_features(), self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertIsInstance(result["is_anomaly"], bool)

    def test_inference_time_is_measured_and_non_negative(self):
        result = live_detection.predict_flow(
            make_valid_features(), self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertGreaterEqual(result["inference_time_ms"], 0.0)

    def test_wrong_feature_order_is_rejected(self):
        # Section 57 - Validation du feature vector: un vecteur avec le bon
        # NOMBRE de features mais le mauvais ORDRE doit etre rejete (None),
        # jamais silencieusement mal interprete par le scaler/modele.
        shuffled = make_valid_features()
        # inverse l'ordre des cles en reconstruisant un dict - en Python les
        # dicts conservent l'ordre d'insertion, donc ceci change reellement
        # l'ordre observe par list(features_dict.keys()).
        shuffled_keys = list(reversed(list(shuffled.keys())))
        shuffled = {k: shuffled[k] for k in shuffled_keys}

        result = live_detection.predict_flow(
            shuffled, self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertIsNone(result)

    def test_missing_feature_is_rejected(self):
        # Section 57: un vecteur incomplet (une feature manquante) doit
        # aussi etre rejete, jamais complete silencieusement par une
        # valeur par defaut inventee.
        incomplete = make_valid_features()
        del incomplete["ack_flag_present"]

        result = live_detection.predict_flow(
            incomplete, self.scaler, self.label_encoder, self.models, self.iso_forest
        )
        self.assertIsNone(result)


if __name__ == "__main__":
    unittest.main()
