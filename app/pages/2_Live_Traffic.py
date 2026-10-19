"""
2_Live_Traffic.py
AI-HYBRID-IDS - Phase 16 - Page Live Traffic (section 36)

Code couleur (section 36):
NORMAL -> vert | SUSPICIOUS -> jaune/orange | ATTACK -> orange/rouge
CRITICAL -> rouge | UNKNOWN -> gris
"""

import os
import sys
from datetime import datetime

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - Live Traffic", layout="wide")
if not check_password():
    st.stop()
st.title("Live Traffic")

STATUS_COLORS = {
    "NORMAL": "#2ecc71",       # vert
    "SUSPICIOUS": "#f1c40f",   # jaune/orange
    "ATTACK": "#e67e22",       # orange/rouge
    "CRITICAL": "#e74c3c",     # rouge
    "UNKNOWN": "#95a5a6",      # gris
}


def color_status(val):
    color = STATUS_COLORS.get(val, "#ffffff")
    return f"background-color: {color}; color: black;"


limit = st.slider("Nombre de flux a afficher", 20, 500, 100, step=20)
st.caption("Actualisation automatique toutes les 5 secondes.")


@st.fragment(run_every="5s")
def render_live_traffic(flow_limit):
    flows_data, err = api_get("/api/flows", params={"limit": flow_limit})
    st.caption(f"Derniere mise a jour : {datetime.now().astimezone():%H:%M:%S}")

    if err:
        st.error(err)
        return

    if flows_data["count"] == 0:
        st.info("Aucun flux enregistre - verifiez que live_detection.py tourne.")
        return

    df = pd.DataFrame(flows_data["flows"])
    df = df.sort_values("timestamp", ascending=False)

    display_cols = [
        "timestamp", "src_ip", "dest_ip", "dest_port", "proto",
        "predicted_class", "model_agreement", "confidence", "is_anomaly",
        "status", "risk_score", "has_suricata_alert", "inference_time_ms",
    ]
    df_display = df[[column for column in display_cols if column in df.columns]]

    styled = df_display.style.map(color_status, subset=["status"])
    st.dataframe(styled, width="stretch", hide_index=True, height=600)

    st.divider()
    st.markdown("**Legende**")
    legend_cols = st.columns(len(STATUS_COLORS))
    for col, (label, color) in zip(legend_cols, STATUS_COLORS.items()):
        col.markdown(
            f"<div style='background-color:{color}; padding:8px; "
            f"border-radius:4px; text-align:center; color:black;'>{label}</div>",
            unsafe_allow_html=True,
        )


render_live_traffic(limit)
