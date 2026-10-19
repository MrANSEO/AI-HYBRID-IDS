"""Compare les features live au train sans jamais declencher de retraining."""

import argparse
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "features"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "utils"))
from feature_extraction import FEATURE_ORDER
from paths_utils import get_project_root


def population_stability_index(reference, current, bins=10):
    """Retourne le PSI d'une feature numerique."""
    reference = np.asarray(reference, dtype=float)
    current = np.asarray(current, dtype=float)
    edges = np.unique(np.quantile(reference, np.linspace(0, 1, bins + 1)))
    if len(edges) < 2:
        return 0.0
    edges[0] = -np.inf
    edges[-1] = np.inf
    ref_counts = np.histogram(reference, bins=edges)[0].astype(float)
    cur_counts = np.histogram(current, bins=edges)[0].astype(float)
    ref_pct = np.maximum(ref_counts / max(ref_counts.sum(), 1), 1e-6)
    cur_pct = np.maximum(cur_counts / max(cur_counts.sum(), 1), 1e-6)
    return float(np.sum((cur_pct - ref_pct) * np.log(cur_pct / ref_pct)))


def compute_drift(project_root=None, limit=5000):
    project_root = project_root or get_project_root()
    train_path = os.path.join(project_root, "data", "processed", "train_classweight.csv")
    live_path = os.path.join(project_root, "logs", "detections.csv")
    scaler_path = os.path.join(project_root, "models", "preprocessing", "scaler.pkl")

    if not all(os.path.exists(path) for path in (train_path, live_path, scaler_path)):
        return {"status": "UNAVAILABLE", "reason": "train, live log ou scaler manquant"}

    train = pd.read_csv(train_path)
    live = pd.read_csv(live_path).tail(limit)
    missing = [feature for feature in FEATURE_ORDER if feature not in live.columns]
    if missing or live.empty:
        return {
            "status": "UNAVAILABLE",
            "reason": "les journaux live ne contiennent pas encore toutes les features",
            "missing_features": missing,
        }

    scaler = joblib.load(scaler_path)
    reference = train[FEATURE_ORDER].dropna()
    current_raw = live[FEATURE_ORDER].apply(pd.to_numeric, errors="coerce").dropna()
    if current_raw.empty:
        return {"status": "UNAVAILABLE", "reason": "aucune feature live numerique exploitable"}

    current = pd.DataFrame(
        scaler.transform(current_raw), columns=FEATURE_ORDER
    )
    results = {}
    for feature in FEATURE_ORDER:
        score = population_stability_index(reference[feature], current[feature])
        results[feature] = {
            "psi": round(score, 6),
            "status": "HIGH" if score >= 0.25 else "MEDIUM" if score >= 0.1 else "LOW",
        }
    high_features = [name for name, result in results.items() if result["status"] == "HIGH"]
    return {
        "status": "DRIFT_HIGH" if high_features else "OK",
        "samples": len(current),
        "features": results,
        "high_drift_features": high_features,
        "recommendation": "Retraining recommended" if high_features else "No action",
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Analyse prudente du feature drift")
    parser.add_argument("--limit", type=int, default=5000)
    parser.add_argument("--output", default=None)
    args = parser.parse_args()
    report = compute_drift(limit=args.limit)
    output = json.dumps(report, indent=2)
    print(output)
    if args.output:
        with open(args.output, "w") as output_file:
            output_file.write(output + "\n")