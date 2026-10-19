"""
6_Detection_Engines.py
AI-HYBRID-IDS - Phase 16 (suite) - Page Detection Engines (section 41)

Compare les moteurs de detection entre eux SUR DONNEES DE PRODUCTION REELLES
(pas seulement les metriques de labo, deja vues dans ML Analytics), et met en
evidence les cas de DESACCORD entre moteurs - le coeur de l'interet d'une
architecture hybride (section 22).
"""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - Detection Engines", layout="wide")
if not check_password():
    st.stop()
st.title("Detection Engines")
st.caption("Comparaison des moteurs sur le trafic reellement analyse")

limit = st.slider("Nombre de flux a analyser", 100, 1000, 500, step=100)

flows_data, flows_err = api_get("/api/flows", params={"limit": limit})
alerts_data, alerts_err = api_get("/api/alerts", params={"limit": 500})
incidents_data, incidents_err = api_get("/api/incidents")

if flows_err:
    st.error(flows_err)
    st.stop()
if flows_data["count"] == 0:
    st.info("Aucun flux analyse - lancez live_detection.py.")
    st.stop()

df = pd.DataFrame(flows_data["flows"])

# ----------------------------------------------------------------------------
# Vue d'ensemble par moteur
# ----------------------------------------------------------------------------
st.subheader("Volume detecte par moteur")

n_suricata = int(df["has_suricata_alert"].sum())
n_ml_attack = int((df["predicted_class"] != "Normal Traffic").sum())
n_anomaly = int(df["is_anomaly"].sum())
n_incidents = incidents_data["count"] if not incidents_err else 0

c1, c2, c3, c4 = st.columns(4)
c1.metric("Suricata (flux avec alerte)", n_suricata)
c2.metric("ML Ensemble (hors Normal)", n_ml_attack)
c3.metric("Isolation Forest (anomalies)", n_anomaly)
c4.metric("Incidents correles", n_incidents)

st.bar_chart(pd.Series({
    "Suricata": n_suricata,
    "ML Ensemble": n_ml_attack,
    "Isolation Forest": n_anomaly,
    "Incidents correles": n_incidents,
}))

st.divider()

# ----------------------------------------------------------------------------
# Cas de desaccord entre moteurs (section 41)
# ----------------------------------------------------------------------------
st.subheader("Cas de desaccord entre moteurs")

df["ml_says_attack"] = df["predicted_class"] != "Normal Traffic"

# Categorisation des combinaisons de signaux
def categorize(row):
    s, m, a = row["has_suricata_alert"], row["ml_says_attack"], row["is_anomaly"]
    if s and m and a:
        return "Accord total (3 moteurs)"
    if s and m:
        return "Suricata + ML (sans anomalie)"
    if s and a:
        return "Suricata + IsoForest (ML dit Normal)"
    if m and a:
        return "ML + IsoForest (sans alerte Suricata)"
    if s:
        return "Suricata SEUL"
    if m:
        return "ML SEUL"
    if a:
        return "IsoForest SEUL"
    return "Aucun signal (Normal)"

df["combinaison"] = df.apply(categorize, axis=1)
combo_counts = df["combinaison"].value_counts()

col_a, col_b = st.columns([1, 1])
with col_a:
    st.markdown("**Repartition des combinaisons de signaux**")
    st.dataframe(
        combo_counts.reset_index().rename(columns={"index": "Combinaison", "count": "Nombre"}),
        width="stretch", hide_index=True,
    )
with col_b:
    disagreements = combo_counts[combo_counts.index != "Aucun signal (Normal)"]
    if len(disagreements) > 0:
        st.markdown("**Signaux non-nuls uniquement**")
        st.bar_chart(disagreements)
    else:
        st.info("Aucun signal de detection dans cet echantillon.")

st.info(
    "**Lecture**: 'Suricata SEUL' illustre la Regle 7 (une alerte n'est jamais "
    "ignoree, meme si le ML dit Normal). 'IsoForest SEUL' correspond "
    "majoritairement aux faux positifs lies au data drift identifie en Phase 13 "
    "(~33% d'anomalies en production contre ~5% attendu en labo)."
)

st.divider()

# ----------------------------------------------------------------------------
# Detail des flux ou les moteurs divergent
# ----------------------------------------------------------------------------
st.subheader("Detail des flux avec signal de detection")

df_signals = df[df["combinaison"] != "Aucun signal (Normal)"]

if len(df_signals) == 0:
    st.info("Aucun flux avec signal dans cet echantillon.")
else:
    selected_combo = st.selectbox(
        "Filtrer par combinaison", ["Toutes"] + sorted(df_signals["combinaison"].unique())
    )
    df_display = df_signals if selected_combo == "Toutes" else df_signals[
        df_signals["combinaison"] == selected_combo
    ]

    st.dataframe(
        df_display[[
            "timestamp", "src_ip", "dest_ip", "dest_port", "proto",
            "predicted_class", "confidence", "is_anomaly",
            "has_suricata_alert", "status", "risk_score", "combinaison",
        ]].sort_values("timestamp", ascending=False),
        width="stretch", hide_index=True, height=400,
    )
