"""
3_Alerts.py
AI-HYBRID-IDS - Phase 16 (suite) - Page Alerts (section 37)

Note honnete: la categorie de l'alerte n'est pas persistee separement de la
signature dans incident_events (seulement utilisee en memoire par
live_detection.py) - cette page n'affiche donc que les champs reellement
stockes: timestamp, source, destination, signature, statut, risk_score,
incident associe.
"""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - Alerts", layout="wide")
if not check_password():
    st.stop()
st.title("Alerts")
st.caption("Alertes Suricata brutes enregistrees comme preuves d'incidents")

alerts_data, err = api_get("/api/alerts", params={"limit": 500})

if err:
    st.error(err)
    st.stop()

if alerts_data["count"] == 0:
    st.info("Aucune alerte enregistree pour l'instant.")
    st.stop()

df = pd.DataFrame(alerts_data["alerts"])
df = df.sort_values("timestamp", ascending=False)

col1, col2 = st.columns([2, 1])
with col1:
    search = st.text_input("Rechercher (IP, signature, incident)", "")
with col2:
    sort_by = st.selectbox("Trier par", ["timestamp", "risk_score", "src_ip"])

if search:
    mask = df.apply(lambda row: search.lower() in str(row.values).lower(), axis=1)
    df = df[mask]

df = df.sort_values(sort_by, ascending=(sort_by != "timestamp"))

st.markdown(f"**{len(df)} alerte(s)** correspondant aux criteres")
st.dataframe(df, width="stretch", hide_index=True, height=500)

csv_data = df.to_csv(index=False).encode("utf-8")
st.download_button(
    "Exporter en CSV", data=csv_data,
    file_name="alerts_export.csv", mime="text/csv",
)
