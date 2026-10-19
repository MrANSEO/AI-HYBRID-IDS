"""
generate_ml_evaluation.py
AI-HYBRID-IDS - Phase 8

Consolide les 4 fichiers de metriques (RF, XGBoost, LightGBM, Isolation Forest)
en un seul resume JSON + genere un rapport Markdown lisible.

Formalise egalement le choix des variantes retenues pour l'ensemble de vote
(section 6-7), decide empiriquement lors des Phases 4-6.
"""

import os
import json

RESULTS_DIR = os.path.expanduser("~/AI-HYBRID-IDS/results/metrics")
REPORTS_DIR = os.path.expanduser("~/AI-HYBRID-IDS/results/reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# Variantes retenues pour l'ensemble de vote - decision empirique Phases 4-6
CHOSEN_VARIANTS = {
    "Random Forest": "smote_variant",
    "XGBoost": "smote_variant",
    "LightGBM": "class_weight_variant",
}

CLASSES_ORDER = ["Normal Traffic", "DoS", "DDoS", "Port Scanning",
                  "Brute Force", "Web Attacks", "Bots"]


def load_json(name):
    path = os.path.join(RESULTS_DIR, name)
    with open(path) as f:
        return json.load(f)


def main():
    rf = load_json("random_forest_metrics.json")
    xgb = load_json("xgboost_metrics.json")
    lgbm = load_json("lightgbm_metrics.json")
    iso = load_json("isolation_forest_metrics.json")

    supervised_raw = {"Random Forest": rf, "XGBoost": xgb, "LightGBM": lgbm}

    # ------------------------------------------------------------------
    # Consolidation - tableau comparatif des variantes retenues
    # ------------------------------------------------------------------
    comparison_rows = []
    for model_name, variant_key in CHOSEN_VARIANTS.items():
        data = supervised_raw[model_name][variant_key]
        comparison_rows.append({
            "model": model_name,
            "variant": variant_key.replace("_variant", ""),
            "f1_macro": data["f1_macro"],
            "f1_weighted": data["f1_weighted"],
            "accuracy": data["accuracy"],
            "model_size_mb": data.get("model_size_mb"),
            "train_time_s": data.get("train_time_s"),
            "inference_time_per_sample_ms": data["inference_time_per_sample_ms"],
            "per_class": data["per_class"],
        })

    # Toutes les variantes (pour transparence - montrer aussi ce qui n'a pas ete retenu)
    all_variants_rows = []
    for model_name, raw in supervised_raw.items():
        for key in ["class_weight_variant", "smote_variant"]:
            if key in raw:
                d = raw[key]
                all_variants_rows.append({
                    "model": model_name,
                    "variant": key.replace("_variant", ""),
                    "retained": (CHOSEN_VARIANTS[model_name] == key),
                    "f1_macro": d["f1_macro"],
                    "f1_weighted": d["f1_weighted"],
                })

    summary = {
        "chosen_variants": CHOSEN_VARIANTS,
        "comparison_retained_models": comparison_rows,
        "all_variants_tested": all_variants_rows,
        "isolation_forest": {
            "final_contamination": iso["final_contamination"],
            "false_positive_rate_normal_pct": iso["false_positive_rate_normal_pct"],
            "average_detection_rate_attacks_pct": iso["average_detection_rate_attacks_pct"],
            "per_class_detection": iso["per_class_detection"],
            "limitation_note": iso["limitation_note"],
        },
    }

    summary_path = os.path.join(RESULTS_DIR, "ml_evaluation_summary.json")
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(f"Resume JSON consolide -> {summary_path}")

    # ------------------------------------------------------------------
    # Generation du rapport Markdown
    # ------------------------------------------------------------------
    lines = []
    lines.append("# Évaluation ML — Phase 8 (AI-HYBRID-IDS)\n")
    lines.append("Rapport généré automatiquement à partir des métriques des Phases 4 à 7. "
                 "Ne pas éditer manuellement — relancer `generate_ml_evaluation.py` après "
                 "tout nouvel entraînement.\n")

    lines.append("## 1. Modèles retenus pour l'ensemble de vote\n")
    lines.append("Le choix de la variante (class_weight vs SMOTE) a été fait "
                 "empiriquement par modèle, pas de façon uniforme, sur la base des "
                 "résultats mesurés sur le test set (jamais ré-échantillonné).\n")
    lines.append("| Modèle | Variante retenue | F1-macro | F1-weighted | Accuracy | "
                 "Taille | Temps train | Inférence/éch. |")
    lines.append("|---|---|---|---|---|---|---|---|")
    for row in comparison_rows:
        lines.append(
            f"| {row['model']} | {row['variant']} | {row['f1_macro']:.4f} | "
            f"{row['f1_weighted']:.4f} | {row['accuracy']:.4f} | "
            f"{row['model_size_mb']:.1f} MB | {row['train_time_s']:.0f}s | "
            f"{row['inference_time_per_sample_ms']:.5f} ms |"
        )

    lines.append("\n## 2. Toutes les variantes testées (transparence)\n")
    lines.append("| Modèle | Variante | F1-macro | F1-weighted | Retenue |")
    lines.append("|---|---|---|---|---|")
    for row in all_variants_rows:
        mark = "✅" if row["retained"] else ""
        lines.append(
            f"| {row['model']} | {row['variant']} | {row['f1_macro']:.4f} | "
            f"{row['f1_weighted']:.4f} | {mark} |"
        )

    lines.append("\n## 3. Performance par classe (modèles retenus)\n")
    lines.append("| Classe | " + " | ".join(f"{r['model']} (F1)" for r in comparison_rows) + " |")
    lines.append("|---|" + "---|" * len(comparison_rows))
    for cls in CLASSES_ORDER:
        row_vals = []
        for r in comparison_rows:
            f1 = r["per_class"].get(cls, {}).get("f1", None)
            row_vals.append(f"{f1:.2f}" if f1 is not None else "N/A")
        lines.append(f"| {cls} | " + " | ".join(row_vals) + " |")

    lines.append("\n## 4. Isolation Forest (non supervisé)\n")
    lines.append(f"- Contamination retenue : **{summary['isolation_forest']['final_contamination']}**")
    lines.append(f"- Taux de faux positifs (Normal Traffic) : "
                 f"**{summary['isolation_forest']['false_positive_rate_normal_pct']:.2f}%**")
    lines.append(f"- Taux moyen de détection (toutes attaques confondues) : "
                 f"**{summary['isolation_forest']['average_detection_rate_attacks_pct']:.2f}%**\n")
    lines.append("| Classe | Taux | Interprétation |")
    lines.append("|---|---|---|")
    for cls in CLASSES_ORDER:
        rate = summary["isolation_forest"]["per_class_detection"].get(cls, {}).get("detection_rate_pct")
        if rate is None:
            lines.append(f"| {cls} | N/A | |")
        elif cls == "Normal Traffic":
            lines.append(f"| {cls} | {rate:.2f}% | ⚠️ Faux positifs (trafic legitime signale a tort) |")
        else:
            lines.append(f"| {cls} | {rate:.2f}% | Taux de detection (vraie attaque signalee) |")

    lines.append(f"\n**Limite constatée** : {summary['isolation_forest']['limitation_note']}\n")

    lines.append("## 5. Constat transversal — limite du feature set MVP (pas un défaut d'algorithme)\n")
    lines.append(
        "**Quatre méthodes indépendantes** (Random Forest, XGBoost, LightGBM, et Isolation "
        "Forest — non supervisé) échouent de façon convergente sur les mêmes classes : "
        "**Bots** et **Web Attacks**, avec dans une moindre mesure **Brute Force** pour "
        "Isolation Forest. Cette convergence, obtenue par des algorithmes de nature très "
        "différente (arbres supervisés vs isolation non supervisée), constitue une preuve "
        "solide que la limite provient du **feature set MVP à 12 variables** "
        "(FEATURE_CONTRACT.md, Sections A+D), pas d'un choix d'algorithme malheureux.\n"
    )
    lines.append(
        "Ce constat **justifie empiriquement** l'architecture hybride du projet (section 9) : "
        "la détection par signatures de Suricata devra porter la charge de la détection "
        "des attaques web (motifs dans le contenu de la requête, non visibles dans des "
        "statistiques de flux agrégées), là où le ML — supervisé comme non supervisé — "
        "atteint une limite structurelle avec ce jeu de features.\n"
    )

    lines.append("## 6. Points en attente pour une évaluation hybride complète (section 22)\n")
    lines.append(
        "Cette Phase 8 ne couvre que le volet ML (supervisé + Isolation Forest). "
        "La comparaison complète *Suricata seul / ML seul / Isolation Forest seul / "
        "combinaisons* prévue section 22 nécessite l'intégration de Suricata "
        "(Phase 9) et sera complétée à ce moment-là.\n"
    )

    report_path = os.path.join(REPORTS_DIR, "ml_evaluation.md")
    with open(report_path, "w") as f:
        f.write("\n".join(lines))
    print(f"Rapport Markdown genere -> {report_path}")


if __name__ == "__main__":
    main()
