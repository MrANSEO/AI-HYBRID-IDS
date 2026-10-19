"""
live_detection.py
AI-HYBRID-IDS - Phases 11 + 12 + 13
(section 25 Mode 3 - LIVE, section 9/28 - Correlation, section 10-11 - Decision Engine)

Pipeline complet: eve.json (flow + alert) -> extraction features -> vote ML ->
Isolation Forest -> Correlation Engine -> Decision Engine (status/risk_score).

Usage:
    sudo venv/bin/python3 src/detection/live_detection.py
    (Ctrl+C pour arreter proprement)
"""

import os
import sys
import json
import time
import csv
import sqlite3
import pwd
import yaml
import joblib
import numpy as np
import pandas as pd
import argparse
import tempfile
from datetime import datetime, timedelta
from collections import deque

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "features"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "utils"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "correlation"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "incidents"))
from feature_extraction import extract_features, FEATURE_ORDER
from paths_utils import get_project_root
from correlation_engine import CorrelationEngine
import decision_engine
import incident_engine

EVE_JSON_PATH = "/var/log/suricata/eve.json"
PROJECT_ROOT = get_project_root()
PREPROC_DIR = os.path.join(PROJECT_ROOT, "models", "preprocessing")
SUPERVISED_DIR = os.path.join(PROJECT_ROOT, "models", "supervised")
UNSUPERVISED_DIR = os.path.join(PROJECT_ROOT, "models", "unsupervised")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
DETECTIONS_CSV_PATH = os.path.join(LOGS_DIR, "detections.csv")
INCIDENTS_DB_PATH = os.path.join(PROJECT_ROOT, "data", "incidents", "incidents.db")
CSV_FIELDS = [
    "timestamp", "src_ip", "dest_ip", "dest_port", "proto",
    "predicted_class", "model_agreement", "confidence", "is_anomaly",
    "status", "risk_score", "has_suricata_alert", "inference_time_ms",
] + FEATURE_ORDER


def fix_ownership_for_sudo_user(path):
    """
    Corrige le proprietaire d'un fichier/dossier cree sous sudo (root) pour
    qu'il appartienne a l'utilisateur reel - necessaire pour que l'API
    (Phase 15, tournant SANS sudo, section 53 moindre privilege) puisse
    ensuite lire logs/detections.csv et data/incidents/incidents.db.
    Meme pattern de correctif que traffic_replay.py (Phase 10).
    """
    sudo_user = os.environ.get("SUDO_USER")
    if not sudo_user:
        return
    try:
        pw = pwd.getpwnam(sudo_user)
        os.chown(path, pw.pw_uid, pw.pw_gid)
    except (KeyError, PermissionError, FileNotFoundError):
        pass


def log_detection_to_csv(row_dict):
    """Ecrit une ligne dans logs/detections.csv (section 55) - permet l'analyse
    quantitative precise (ex: taux reel d'anomalie sur trafic live), plus fiable
    qu'un parsing du log console a colonnes fixes."""
    os.makedirs(LOGS_DIR, exist_ok=True)
    file_exists = os.path.exists(DETECTIONS_CSV_PATH)
    if file_exists:
        with open(DETECTIONS_CSV_PATH, newline="") as existing_file:
            existing_reader = csv.DictReader(existing_file)
            existing_fields = existing_reader.fieldnames or []
            if existing_fields != CSV_FIELDS:
                fd, migrated_path = tempfile.mkstemp(dir=LOGS_DIR, text=True)
                os.close(fd)
                with open(migrated_path, "w", newline="") as migrated_file:
                    migrated_writer = csv.DictWriter(migrated_file, fieldnames=CSV_FIELDS)
                    migrated_writer.writeheader()
                    for existing_row in existing_reader:
                        migrated_writer.writerow(existing_row)
                os.replace(migrated_path, DETECTIONS_CSV_PATH)
    with open(DETECTIONS_CSV_PATH, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if not file_exists:
            writer.writeheader()
        writer.writerow(row_dict)
    fix_ownership_for_sudo_user(LOGS_DIR)
    fix_ownership_for_sudo_user(DETECTIONS_CSV_PATH)


def prune_detection_log(retention_days):
    """Supprime les detections plus anciennes que la retention configuree."""
    if not os.path.exists(DETECTIONS_CSV_PATH) or retention_days <= 0:
        return
    cutoff = datetime.now().astimezone() - timedelta(days=retention_days)
    fd, pruned_path = tempfile.mkstemp(dir=LOGS_DIR, text=True)
    os.close(fd)
    try:
        with open(DETECTIONS_CSV_PATH, newline="") as source, open(pruned_path, "w", newline="") as target:
            reader = csv.DictReader(source)
            writer = csv.DictWriter(target, fieldnames=CSV_FIELDS)
            writer.writeheader()
            for row in reader:
                try:
                    keep = datetime.fromisoformat(row["timestamp"]) >= cutoff
                except (KeyError, TypeError, ValueError):
                    keep = True
                if keep:
                    writer.writerow(row)
        os.replace(pruned_path, DETECTIONS_CSV_PATH)
        fix_ownership_for_sudo_user(DETECTIONS_CSV_PATH)
    finally:
        if os.path.exists(pruned_path):
            os.remove(pruned_path)

MODEL_FILES = {
    "RandomForest": "random_forest_smote.pkl",
    "XGBoost": "xgboost_smote.pkl",
    "LightGBM": "lightgbm_classweight.pkl",
}

STATUS_TAG = {
    "NORMAL": "",
    "SUSPICIOUS": " [SUSPICIOUS]",
    "ATTACK": " [ATTACK]",
    "CRITICAL": " [!!! CRITICAL !!!]",
    "UNKNOWN": " [UNKNOWN]",
}


def load_artifacts():
    print("Chargement des artefacts (scaler, label encoder, modeles)...")
    scaler = joblib.load(os.path.join(PREPROC_DIR, "scaler.pkl"))
    label_encoder = joblib.load(os.path.join(PREPROC_DIR, "label_encoder.pkl"))

    models = {}
    for name, filename in MODEL_FILES.items():
        path = os.path.join(SUPERVISED_DIR, filename)
        models[name] = joblib.load(path)
        print(f"  {name:<15} -> {filename}")

    iso_forest = joblib.load(os.path.join(UNSUPERVISED_DIR, "isolation_forest.pkl"))
    print("  IsolationForest -> isolation_forest.pkl")
    print("Artefacts charges avec succes.\n")

    return scaler, label_encoder, models, iso_forest


def predict_flow(features_dict, scaler, label_encoder, models, iso_forest):
    """Scaling -> vote des 3 modeles -> confiance -> score d'anomalie."""
    if list(features_dict.keys()) != FEATURE_ORDER:
        return None

    inference_start = time.perf_counter()
    X = pd.DataFrame([features_dict], columns=FEATURE_ORDER)
    X_scaled = pd.DataFrame(scaler.transform(X), columns=FEATURE_ORDER)

    predictions = {}
    confidences = {}
    for name, model in models.items():
        proba = model.predict_proba(X_scaled)[0]
        pred_idx = int(np.argmax(proba))
        pred_label = label_encoder.inverse_transform([pred_idx])[0]
        predictions[name] = pred_label
        confidences[name] = float(proba[pred_idx])

    votes = list(predictions.values())
    vote_counts = pd.Series(votes).value_counts()
    majority_class = vote_counts.index[0]
    model_agreement = int(vote_counts.iloc[0])

    avg_confidence = np.mean([
        confidences[m] for m in models if predictions[m] == majority_class
    ])

    anomaly_pred = iso_forest.predict(X_scaled)[0]
    anomaly_score = float(iso_forest.decision_function(X_scaled)[0])

    return {
        "individual_predictions": predictions,
        "majority_class": majority_class,
        "model_agreement": f"{model_agreement}/{len(models)}",
        "confidence": round(avg_confidence, 4),
        "is_anomaly": bool(anomaly_pred == -1),
        "anomaly_score": round(anomaly_score, 4),
        "inference_time_ms": round((time.perf_counter() - inference_start) * 1000, 3),
    }


def tail_f(path, heartbeat_every=15, start_at_end=True, follow=True):
    """Lit un fichier en continu ou une seule fois pour traiter un replay."""
    while not os.path.exists(path):
        print(f"En attente de la creation de {path}...")
        time.sleep(2)

    with open(path, "r") as f:
        if start_at_end:
            f.seek(0, os.SEEK_END)
        last_activity = time.time()
        while True:
            line = f.readline()
            if not line:
                if not follow:
                    return
                if time.time() - last_activity > heartbeat_every:
                    print(f"  [toujours a l'ecoute - aucun evenement depuis "
                          f"{heartbeat_every}s, normal si le trafic est calme]")
                    last_activity = time.time()
                time.sleep(0.3)
                continue
            last_activity = time.time()
            yield line


def extract_alert_info(evt):
    """Extrait les infos essentielles d'un event_type=alert."""
    alert = evt.get("alert", {})
    metadata = alert.get("metadata", {})
    sev_meta = metadata.get("signature_severity")
    return {
        "flow_id": evt.get("flow_id"),
        "timestamp": evt.get("timestamp"),
        "signature": alert.get("signature"),
        "category": alert.get("category"),
        "severity_raw": alert.get("severity"),
        "signature_severity_text": sev_meta[0] if sev_meta else "N/A",
        "src_ip": evt.get("src_ip"),
        "dest_ip": evt.get("dest_ip"),
    }


def print_signals(src_ip, signals):
    print(f"           >>> CORRELATION [{src_ip}]:")
    for s in signals:
        print(f"               - {s}")


def main(eve_json_path=EVE_JSON_PATH, start_at_end=True, follow=True):
    scaler, label_encoder, models, iso_forest = load_artifacts()
    config_path = os.path.join(PROJECT_ROOT, "config", "config.yaml")
    correlation_window = 60  # valeur par defaut si config.yaml absent/invalide
    scan_port_threshold = 10
    repeated_attack_threshold = 3
    flood_packets_per_sec_threshold = 1000
    flood_bytes_per_sec_threshold = 1_000_000
    if os.path.exists(config_path):
        try:
            with open(config_path) as f:
                cfg = yaml.safe_load(f) or {}
            correlation_window = cfg.get("correlation", {}).get("window_seconds", 60)
            correlation_cfg = cfg.get("correlation", {})
            scan_port_threshold = correlation_cfg.get("scan_port_threshold", 10)
            repeated_attack_threshold = correlation_cfg.get("repeated_attack_threshold", 3)
            flood_packets_per_sec_threshold = correlation_cfg.get(
                "flood_packets_per_sec_threshold", 1000
            )
            flood_bytes_per_sec_threshold = correlation_cfg.get(
                "flood_bytes_per_sec_threshold", 1_000_000
            )
            incident_engine.INCIDENT_TIMEOUT_SECONDS = cfg.get(
                "incident_engine", {}
            ).get("timeout_seconds", incident_engine.INCIDENT_TIMEOUT_SECONDS)
            prune_detection_log(cfg.get("logs", {}).get("retention_days", 30))
        except Exception:
            pass  # config corrompue -> on garde la valeur par defaut
    correlation_engine = CorrelationEngine(window_seconds=correlation_window)

    os.makedirs(os.path.dirname(INCIDENTS_DB_PATH), exist_ok=True)
    fix_ownership_for_sudo_user(os.path.dirname(INCIDENTS_DB_PATH))
    incident_conn = sqlite3.connect(INCIDENTS_DB_PATH)
    incident_engine.init_db(incident_conn)
    fix_ownership_for_sudo_user(INCIDENTS_DB_PATH)
    print(f"Incident Engine actif (base: {INCIDENTS_DB_PATH})")

    recent_alerts_by_flow_id = {}
    last_signals_shown = {}
    processed_flow_ids = set()
    processed_flow_order = deque(maxlen=100000)

    print(f"Ecoute en continu de: {eve_json_path}")
    print(f"Correlation Engine actif (fenetre glissante: {correlation_engine.window_seconds}s)")
    print("Decision Engine actif (voir docs/DECISION_ENGINE.md pour la formule)")
    print("(Ctrl+C pour arreter)\n")
    print(f"{'Heure':<10} {'Source':<22} {'Destination':<22} {'Proto':<6} "
          f"{'Vote':<15} {'Accord':<8} {'Conf.':<7} {'Anomalie':<10} "
          f"{'Statut':<12} {'Risk':<6}")
    print("-" * 130)

    flow_count = 0
    alert_count = 0
    try:
        for line in tail_f(
            eve_json_path, start_at_end=start_at_end, follow=follow
        ):
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue

            event_type = evt.get("event_type")

            if event_type == "alert":
                alert_count += 1
                alert_info = extract_alert_info(evt)
                recent_alerts_by_flow_id[alert_info["flow_id"]] = alert_info
                src_ip = alert_info["src_ip"]

                correlation_engine.add_alert(
                    src_ip=src_ip,
                    signature=alert_info["signature"],
                    category=alert_info["category"],
                    severity_text=alert_info["signature_severity_text"],
                    flow_id=alert_info["flow_id"],
                    timestamp_str=alert_info["timestamp"],
                )

                hour = (alert_info["timestamp"] or "")[11:19]
                print(f"{hour:<10} [ALERTE SURICATA] {src_ip} -> "
                      f"{alert_info['dest_ip']} | {alert_info['signature']} "
                      f"(categorie: {alert_info['category']}, "
                      f"severite_texte: {alert_info['signature_severity_text']})")

                _, signals = correlation_engine.evaluate_signals(src_ip)
                if signals and last_signals_shown.get(src_ip) != signals:
                    print_signals(src_ip, signals)
                    last_signals_shown[src_ip] = signals

                severity_weight = decision_engine.compute_suricata_severity_weight(
                    alert_info["signature_severity_text"], alert_info["category"]
                )
                alert_risk = round(decision_engine.WEIGHT_SURICATA * severity_weight, 4)
                incident_engine.record_event(
                    incident_conn, source_ip=src_ip, dest_ip=alert_info["dest_ip"],
                    dest_port=evt.get("dest_port"), detail=alert_info["signature"],
                    event_type="suricata_alert", status="SUSPICIOUS",
                    risk_score=alert_risk, timestamp=alert_info["timestamp"],
                )
                continue

            if event_type != "flow":
                continue

            features = extract_features(evt)
            if features is None:
                continue

            result = predict_flow(features, scaler, label_encoder, models, iso_forest)
            if result is None:
                continue

            flow_count += 1
            flow_id = evt.get("flow_id")
            if flow_id is not None and flow_id in processed_flow_ids:
                continue
            if flow_id is not None:
                if len(processed_flow_order) == processed_flow_order.maxlen:
                    processed_flow_ids.discard(processed_flow_order.popleft())
                processed_flow_ids.add(flow_id)
                processed_flow_order.append(flow_id)
            src_ip = evt.get("src_ip")
            dest_ip = evt.get("dest_ip")
            dest_port = evt.get("dest_port")
            src = f"{src_ip}:{evt.get('src_port')}"
            dst = f"{dest_ip}:{dest_port}"
            hour = (evt.get("timestamp") or "")[11:19]
            anomaly_flag = "OUI" if result["is_anomaly"] else "non"

            matching_alert = recent_alerts_by_flow_id.get(flow_id)
            has_suricata_alert = matching_alert is not None
            suricata_tag = " [+ALERTE]" if has_suricata_alert else ""

            correlation_engine.add_flow_verdict(
                src_ip=src_ip, dest_ip=dest_ip, dest_port=dest_port,
                predicted_class=result["majority_class"],
                confidence=result["confidence"],
                model_agreement=result["model_agreement"],
                is_anomaly=result["is_anomaly"],
                anomaly_score=result["anomaly_score"],
                flow_id=flow_id, timestamp_str=evt.get("timestamp"),
                packets=evt.get("flow", {}).get("pkts_toserver", 0) + evt.get("flow", {}).get("pkts_toclient", 0),
                bytes_total=evt.get("flow", {}).get("bytes_toserver", 0) + evt.get("flow", {}).get("bytes_toclient", 0),
                packets_per_sec=features["flow_packets_per_sec"],
                bytes_per_sec=features["flow_bytes_per_sec"],
            )

            _, correlation_signals = correlation_engine.evaluate_signals(
                src_ip,
                scan_port_threshold=scan_port_threshold,
                repeated_attack_threshold=repeated_attack_threshold,
                flood_packets_per_sec_threshold=flood_packets_per_sec_threshold,
                flood_bytes_per_sec_threshold=flood_bytes_per_sec_threshold,
            )

            # --- Decision Engine (Phase 13) ---
            decision = decision_engine.evaluate(
                predicted_class=result["majority_class"],
                ml_confidence=result["confidence"],
                model_agreement_str=result["model_agreement"],
                is_anomaly=result["is_anomaly"],
                has_suricata_alert=has_suricata_alert,
                correlation_signals=correlation_signals,
                suricata_signature_severity_text=(
                    matching_alert["signature_severity_text"] if matching_alert else None
                ),
                suricata_category=(
                    matching_alert["category"] if matching_alert else None
                ),
            )
            status_tag = STATUS_TAG.get(decision["status"], "")

            print(f"{hour:<10} {src:<22} {dst:<22} {evt.get('proto', ''):<6} "
                  f"{result['majority_class']:<15} {result['model_agreement']:<8} "
                  f"{result['confidence']:<7} {anomaly_flag:<10} "
                  f"{decision['status']:<12} {decision['risk_score']:<6}"
                  f"{suricata_tag}{status_tag}")

            if correlation_signals and last_signals_shown.get(src_ip) != correlation_signals:
                print_signals(src_ip, correlation_signals)
                last_signals_shown[src_ip] = correlation_signals

            log_detection_to_csv({
                "timestamp": evt.get("timestamp"),
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "dest_port": dest_port,
                "proto": evt.get("proto", ""),
                "predicted_class": result["majority_class"],
                "model_agreement": result["model_agreement"],
                "confidence": result["confidence"],
                "is_anomaly": result["is_anomaly"],
                "status": decision["status"],
                "risk_score": decision["risk_score"],
                "has_suricata_alert": has_suricata_alert,
                "inference_time_ms": result["inference_time_ms"],
                **features,
            })

            if decision["status"] in ("SUSPICIOUS", "ATTACK", "CRITICAL"):
                incident_id = incident_engine.record_event(
                    incident_conn, source_ip=src_ip, dest_ip=dest_ip, dest_port=dest_port,
                    detail=result["majority_class"], event_type="ml_verdict",
                    status=decision["status"], risk_score=decision["risk_score"],
                    timestamp=evt.get("timestamp"), flow_id=flow_id,
                )
                if decision["status"] in ("ATTACK", "CRITICAL"):
                    print(f"           >>> INCIDENT [{incident_id}] mis a jour "
                          f"(severite courante: {decision['status']})")

    except KeyboardInterrupt:
        print(f"\n\nArret demande. {flow_count} flows traites, {alert_count} alertes recues au total.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Moteur de detection AI-HYBRID-IDS")
    parser.add_argument(
        "--eve-json", default=EVE_JSON_PATH,
        help="Fichier eve.json a suivre (defaut: /var/log/suricata/eve.json)",
    )
    parser.add_argument(
        "--from-start", action="store_true",
        help="Relit les evenements existants au lieu de commencer a la fin",
    )
    parser.add_argument(
        "--once", action="store_true",
        help="Traite le fichier jusqu'a la fin puis s'arrete (mode replay)",
    )
    args = parser.parse_args()
    main(
        eve_json_path=args.eve_json,
        start_at_end=not args.from_start,
        follow=not args.once,
    )
