import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src" / "detection"))

import decision_engine


class DecisionEngineTests(unittest.TestCase):
    def test_normal_flow_is_normal(self):
        decision = decision_engine.evaluate(
            "Normal Traffic", 0.99, "3/3", False, False, []
        )
        self.assertEqual(decision["status"], "NORMAL")
        self.assertEqual(decision["risk_score"], 0.1)

    def test_suricata_alert_is_never_normal(self):
        decision = decision_engine.evaluate(
            "Normal Traffic", 0.99, "3/3", False, True, [],
            suricata_signature_severity_text="Informational",
        )
        self.assertEqual(decision["status"], "SUSPICIOUS")
        self.assertGreater(decision["risk_score"], 0)

    def test_total_model_disagreement_is_unknown(self):
        decision = decision_engine.evaluate(
            "Normal Traffic", 0.51, "1/3", False, False, []
        )
        self.assertEqual(decision["status"], "UNKNOWN")

    def test_unreliable_class_confidence_is_reduced(self):
        adjusted = decision_engine.compute_ml_confidence_adjusted("Bots", 0.8)
        self.assertAlmostEqual(adjusted, 0.4)

    def test_high_severity_fallback_category_weighted_like_major(self):
        # Ajoute le 25/09/2026 suite a la decouverte que "Attempted Denial
        # of Service" (categorie de notre regle locale sid:1000003, sans
        # metadata signature_severity) tombait sur le poids neutre par
        # defaut (0.6) plutot que refleter la gravite reelle d'un DoS
        # confirme par seuil. Verifie que le poids applique est bien celui
        # de HIGH_SEVERITY_FALLBACK_CATEGORIES (0.8, aligne sur "Major"),
        # pas le poids par defaut.
        weight = decision_engine.compute_suricata_severity_weight(
            None, "Attempted Denial of Service"
        )
        self.assertEqual(weight, 0.8)

    def test_icmp_flood_scenario_matches_real_observed_risk_score(self):
        # Reproduit le scenario reel valide en direct le 25/09/2026
        # (ping -f, flood ICMP): ML unanimement "Normal Traffic" (les
        # modeles se trompent, limite connue), Isolation Forest
        # anomalie=True, alerte Suricata categorie DoS sans metadata
        # severity. On ne sait pas avec certitude LEQUEL des 3 signaux
        # "forts" documentes (REPEATED_ML_ATTACK_PREDICTION, POSSIBLE_SCAN,
        # SURICATA_ML_CONVERGENCE) s'est declenche en production - seul le
        # fait qu'un signal fort etait actif est deduit du calcul inverse
        # du risk_score observe (0.67). POSSIBLE_SCAN est utilise ici a
        # titre representatif.
        # risk_score observe en production: 0.67.
        decision = decision_engine.evaluate(
            "Normal Traffic", 0.9395, "3/3", True, True,
            ["POSSIBLE_SCAN"],
            suricata_signature_severity_text=None,
            suricata_category="Attempted Denial of Service",
        )
        self.assertEqual(decision["status"], "ATTACK")
        self.assertAlmostEqual(decision["risk_score"], 0.67, places=2)

    def test_unknown_category_still_uses_neutral_default(self):
        # Garde-fou: une categorie jamais observee (ni dans la liste
        # benigne ni dans la liste avancee) doit continuer a utiliser le
        # poids neutre 0.6 - pas de regression sur ce comportement suite
        # a l'ajout de HIGH_SEVERITY_FALLBACK_CATEGORIES.
        weight = decision_engine.compute_suricata_severity_weight(
            None, "Categorie Jamais Vue Auparavant"
        )
        self.assertEqual(weight, 0.6)


if __name__ == "__main__":
    unittest.main()
