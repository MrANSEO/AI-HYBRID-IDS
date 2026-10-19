"""
4_Attack_Analysis.py
AI-HYBRID-IDS - Phase 16 (suite) - Page Attack Analysis (section 39)

Analyse aggregee des flows analyses par le moteur de detection.
"""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - Attack Analysis", layout="wide")
if not check_password():
    st.stop()
st.title("Attack Analysis")

limit = st.slider("Nombre de flux a analyser", 100, 1000, 500, step=100)

flows_data, err = api_get("/api/flows", params={"limit": limit})

if err:
    st.error(err)
    st.stop()

if flows_data["count"] == 0:
    st.info("Aucun flux enregistre - lancez live_detection.py.")
    st.stop()

df = pd.DataFrame(flows_data["flows"])
df["timestamp"] = pd.to_datetime(df["timestamp"], format="mixed", utc=True)

non_normal = df[df["predicted_class"] != "Normal Traffic"]
if len(non_normal) == 0:
    st.warning(
        "Aucun flux classe hors 'Normal Traffic' dans cet echantillon. "
        "C'est attendu tant que le laboratoire de test (section 26) n'est pas "
        "monte: le trafic analyse ici est du trafic legitime. Les graphiques "
        "ci-dessous refletent donc principalement le trafic normal et le bruit "
        "de detection (data drift identifie en Phase 13)."
    )

# ----------------------------------------------------------------------------
# Metriques generales
# ----------------------------------------------------------------------------
c1, c2, c3, c4 = st.columns(4)
c1.metric("Flux analyses", len(df))
c2.metric("Classes hors Normal", len(non_normal))
c3.metric("Anomalies (IsoForest)", int(df["is_anomaly"].sum()))
c4.metric("Avec alerte Suricata", int(df["has_suricata_alert"].sum()))

st.divider()

# ----------------------------------------------------------------------------
# Distributions
# ----------------------------------------------------------------------------
col_a, col_b = st.columns(2)
with col_a:
    st.subheader("Types de classes predites (ML)")
    st.bar_chart(df["predicted_class"].value_counts())
with col_b:
    st.subheader("Distribution de severite (Decision Engine)")
    st.bar_chart(df["status"].value_counts())

col_c, col_d = st.columns(2)
with col_c:
    st.subheader("Top 10 IP sources")
    st.bar_chart(df["src_ip"].value_counts().head(10))
with col_d:
    st.subheader("Top 10 IP destinations")
    st.bar_chart(df["dest_ip"].value_counts().head(10))

col_e, col_f = st.columns(2)
with col_e:
    st.subheader("Top 10 ports destination")
    port_counts = df["dest_port"].dropna().astype(int).astype(str).value_counts().head(10)
    st.bar_chart(port_counts)
with col_f:
    st.subheader("Protocoles")
    st.bar_chart(df["proto"].value_counts())

st.divider()

# ----------------------------------------------------------------------------
# Evolution temporelle
# ----------------------------------------------------------------------------
st.subheader("Evolution temporelle")

df_time = df.set_index("timestamp")

col_g, col_h = st.columns(2)
with col_g:
    st.markdown("**Flux par heure**")
    hourly = df_time.resample("1h").size()
    st.line_chart(hourly)
with col_h:
    st.markdown("**Flux par jour**")
    daily = df_time.resample("1D").size()
    st.bar_chart(daily)

st.markdown("**Anomalies detectees dans le temps (par heure)**")
anomaly_mask = df_time["is_anomaly"].fillna(False).astype(bool)
anomalies_hourly = df_time[anomaly_mask].resample("1h").size()
if len(anomalies_hourly) > 0:
    st.line_chart(anomalies_hourly)
else:
    st.info("Aucune anomalie dans cet echantillon.")
