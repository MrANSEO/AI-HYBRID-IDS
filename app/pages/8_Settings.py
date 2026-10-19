"""
8_Settings.py
AI-HYBRID-IDS - Phase 16 (suite) - Page Settings (section 45)

IMPORTANT: un changement sauvegarde ici necessite un REDEMARRAGE de
live_detection.py pour s'appliquer - pas de rechargement a chaud. Precise
explicitement dans l'interface pour ne pas induire en erreur.
"""

import os
import sys
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get, API_BASE_URL
from auth import check_password
import requests

st.set_page_config(page_title="AI-HYBRID-IDS - Settings", layout="wide")
if not check_password():
    st.stop()
st.title("Settings")
st.warning(
    "⚠️ Les changements sauvegardes ici necessitent un **redemarrage de "
    "live_detection.py** pour s'appliquer (pas de rechargement a chaud)."
)

config, err = api_get("/api/config")
if err:
    st.error(err)
    st.stop()

st.subheader("Correlation Engine (Phase 12)")
corr_window = st.number_input(
    "Fenetre glissante (secondes)",
    min_value=10, max_value=600,
    value=config.get("correlation", {}).get("window_seconds", 60),
)
corr_cfg = config.get("correlation", {})
scan_port_threshold = st.number_input(
    "Ports distincts avant signal de scan",
    min_value=2, max_value=10000,
    value=corr_cfg.get("scan_port_threshold", 10),
)
repeated_attack_threshold = st.number_input(
    "Predictions ML avant repetition",
    min_value=2, max_value=1000,
    value=corr_cfg.get("repeated_attack_threshold", 3),
)
flood_packets_threshold = st.number_input(
    "Debit flood (paquets/s)", min_value=1.0, max_value=10000000.0,
    value=float(corr_cfg.get("flood_packets_per_sec_threshold", 1000)),
)
flood_bytes_threshold = st.number_input(
    "Debit flood (octets/s)", min_value=1.0, max_value=10000000000.0,
    value=float(corr_cfg.get("flood_bytes_per_sec_threshold", 1000000)),
)

st.divider()
st.subheader("Decision Engine (Phase 13)")
st.caption("Voir docs/DECISION_ENGINE.md pour la justification de chaque coefficient.")

de = config.get("decision_engine", {})
col1, col2 = st.columns(2)
with col1:
    st.markdown("**Poids de la formule (doivent sommer a ~1.0)**")
    w_suricata = st.slider("Poids Suricata", 0.0, 1.0, de.get("weight_suricata", 0.40), 0.05)
    w_ml = st.slider("Poids confiance ML", 0.0, 1.0, de.get("weight_ml_confidence", 0.25), 0.05)
    w_agreement = st.slider("Poids accord modeles", 0.0, 1.0, de.get("weight_model_agreement", 0.10), 0.05)
    w_anomaly = st.slider("Poids anomalie IsoForest", 0.0, 1.0, de.get("weight_anomaly", 0.10), 0.05)
    w_correlation = st.slider("Poids correlation", 0.0, 1.0, de.get("weight_correlation", 0.15), 0.05)

    total_weight = w_suricata + w_ml + w_agreement + w_anomaly + w_correlation
    if abs(total_weight - 1.0) > 0.01:
        st.warning(f"⚠️ Somme actuelle: {total_weight:.2f} (recommande: ~1.0)")
    else:
        st.success(f"Somme: {total_weight:.2f} ✓")

with col2:
    st.markdown("**Seuils de statut**")
    t_critical = st.slider("Seuil CRITICAL", 0.0, 1.0, de.get("threshold_critical", 0.75), 0.05)
    t_attack = st.slider("Seuil ATTACK", 0.0, 1.0, de.get("threshold_attack", 0.45), 0.05)
    t_suspicious = st.slider("Seuil SUSPICIOUS", 0.0, 1.0, de.get("threshold_suspicious", 0.20), 0.05)

    if not (t_suspicious < t_attack < t_critical):
        st.error("⚠️ Les seuils doivent etre ordonnes: SUSPICIOUS < ATTACK < CRITICAL")

st.divider()
st.subheader("Incident Engine (Phase 14)")
incident_timeout = st.number_input(
    "Timeout d'inactivite avant cloture (secondes)",
    min_value=60, max_value=3600,
    value=config.get("incident_engine", {}).get("timeout_seconds", 300),
)

st.divider()
st.subheader("LLM / Ollama (Phase 17)")
llm_cfg = config.get("llm", {})
llm_enabled = st.checkbox("Generation de rapports LLM activee", value=llm_cfg.get("enabled", True))
llm_model = st.text_input("Modele Ollama", value=llm_cfg.get("model", "qwen2.5:3b"))
llm_timeout = st.number_input(
    "Timeout de generation (secondes)",
    min_value=30, max_value=600, value=llm_cfg.get("timeout_seconds", 320),
)

st.divider()
st.subheader("Mode de fonctionnement (section 25)")
mode = st.selectbox(
    "Mode", ["live", "replay", "offline"],
    index=["live", "replay", "offline"].index(config.get("mode", "live")),
)
st.caption("Informatif pour l'instant - le choix effectif du mode se fait "
           "par le script lance (live_detection.py vs traffic_replay.py).")

st.divider()

if st.button("💾 Sauvegarder la configuration", type="primary"):
    new_config = {
        "correlation": {
            "window_seconds": corr_window,
            "scan_port_threshold": scan_port_threshold,
            "repeated_attack_threshold": repeated_attack_threshold,
            "flood_packets_per_sec_threshold": flood_packets_threshold,
            "flood_bytes_per_sec_threshold": flood_bytes_threshold,
        },
        "decision_engine": {
            "weight_suricata": w_suricata,
            "weight_ml_confidence": w_ml,
            "weight_model_agreement": w_agreement,
            "weight_anomaly": w_anomaly,
            "weight_correlation": w_correlation,
            "threshold_critical": t_critical,
            "threshold_attack": t_attack,
            "threshold_suspicious": t_suspicious,
            "unreliable_class_factors": de.get(
                "unreliable_class_factors", {"Web Attacks": 0.3, "Bots": 0.5}
            ),
        },
        "incident_engine": {"timeout_seconds": incident_timeout},
        "llm": {"enabled": llm_enabled, "model": llm_model, "timeout_seconds": llm_timeout,
                "max_events_in_prompt": llm_cfg.get("max_events_in_prompt", 10)},
        "logs": config.get("logs", {"retention_days": 30}),
        "mode": mode,
    }

    try:
        resp = requests.post(f"{API_BASE_URL}/api/config", json=new_config, timeout=10)
        resp.raise_for_status()
        st.success("Configuration sauvegardee. " + resp.json().get("note", ""))
    except requests.exceptions.RequestException as e:
        st.error(f"Erreur lors de la sauvegarde: {e}")
