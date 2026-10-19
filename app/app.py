"""
app.py
AI-HYBRID-IDS - Phase 16 - Page principale: SOC Overview (section 35)

Page d'accueil du dashboard Streamlit. Les autres pages (Incidents,
Live Traffic) sont dans app/pages/ - Streamlit les detecte automatiquement
et construit la navigation laterale.

Lancement (depuis le dossier app/):
    streamlit run app.py
"""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "components"))
from auth import check_password
from api_client import api_get

st.set_page_config(page_title="AI-HYBRID-IDS - SOC Overview", layout="wide")

if not check_password():
    st.stop()

st.title("AI-HYBRID-IDS — SOC Overview")
st.caption("Mini-console SOC — Phase 16 (MVP: SOC Overview + Incidents + Live Traffic)")

# ----------------------------------------------------------------------------
# Etat systeme
# ----------------------------------------------------------------------------
status_data, status_err = api_get("/api/status")

col1, col2, col3, col4 = st.columns(4)

if status_err:
    st.error(status_err)
else:
    with col1:
        running = status_data["detection_engine_running"]
        st.metric("Moteur de detection", "ACTIF" if running else "ARRETE")
    with col2:
        st.metric("PID", status_data["detection_engine_pid"] or "N/A")
    with col3:
        st.metric("logs/detections.csv", "OK" if status_data["detections_csv_exists"] else "ABSENT")
    with col4:
        st.metric("incidents.db", "OK" if status_data["incidents_db_exists"] else "ABSENT")

st.divider()

# ----------------------------------------------------------------------------
# Incidents - resume
# ----------------------------------------------------------------------------
st.subheader("Incidents")

incidents_data, incidents_err = api_get("/api/incidents")

if incidents_err:
    st.warning(incidents_err)
elif incidents_data["count"] == 0:
    st.info("Aucun incident enregistre pour l'instant.")
else:
    df_incidents = pd.DataFrame(incidents_data["incidents"])

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total incidents", len(df_incidents))
    c2.metric("Ouverts (OPEN)", (df_incidents["status"] == "OPEN").sum())
    c3.metric("CRITICAL", (df_incidents["severity"] == "CRITICAL").sum())
    c4.metric("ATTACK", (df_incidents["severity"] == "ATTACK").sum())

    st.markdown("**Repartition par severite**")
    severity_counts = df_incidents["severity"].value_counts()
    st.bar_chart(severity_counts)

    st.markdown("**Top IP sources (par nombre d'evenements)**")
    top_ips = df_incidents.sort_values("events_count", ascending=False)[
        ["source_ip", "events_count", "severity", "status"]
    ].head(10)
    st.dataframe(top_ips, width="stretch", hide_index=True)

st.divider()

# ----------------------------------------------------------------------------
# Flux recents - distribution des statuts (section 35: evolution des attaques)
# ----------------------------------------------------------------------------
st.subheader("Flux recents")

flows_data, flows_err = api_get("/api/flows", params={"limit": 300})

if flows_err:
    st.warning(flows_err)
elif flows_data["count"] == 0:
    st.info("Aucun flux enregistre pour l'instant - lancez live_detection.py.")
else:
    df_flows = pd.DataFrame(flows_data["flows"])

    c1, c2, c3 = st.columns(3)
    c1.metric("Flux analyses (echantillon)", len(df_flows))
    c2.metric("Taux d'anomalie (IsoForest)", f"{100*df_flows['is_anomaly'].mean():.1f}%")
    c3.metric("Flux avec alerte Suricata", int(df_flows["has_suricata_alert"].sum()))

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("**Distribution des statuts (Decision Engine)**")
        st.bar_chart(df_flows["status"].value_counts())
    with col_b:
        st.markdown("**Classes predites (ML)**")
        st.bar_chart(df_flows["predicted_class"].value_counts())
