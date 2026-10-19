"""
1_Incidents.py
AI-HYBRID-IDS - Phase 16 - Page Incidents (section 38)
"""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get, api_post
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - Incidents", layout="wide")
if not check_password():
    st.stop()
st.title("Incidents")

status_filter = st.selectbox(
    "Filtrer par statut", ["Tous", "OPEN", "INVESTIGATING", "RESOLVED", "FALSE_POSITIVE"]
)

params = {} if status_filter == "Tous" else {"status": status_filter}
incidents_data, err = api_get("/api/incidents", params=params)

if err:
    st.error(err)
    st.stop()

if incidents_data["count"] == 0:
    st.info("Aucun incident pour ce filtre.")
    st.stop()

df = pd.DataFrame(incidents_data["incidents"])
df_display = df[["id", "source_ip", "severity", "status", "max_risk_score",
                  "events_count", "first_seen", "last_seen"]]

st.markdown(f"**{len(df)} incident(s)**")
st.dataframe(df_display, width="stretch", hide_index=True)

st.divider()
st.subheader("Detail d'un incident")

selected_id = st.selectbox("Choisir un incident", df["id"].tolist())

if selected_id:
    detail, detail_err = api_get(f"/api/incidents/{selected_id}")
    if detail_err:
        st.error(detail_err)
    else:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Severite", detail["severity"])
        c2.metric("Statut", detail["status"])
        c3.metric("Risk score max", detail["max_risk_score"])
        c4.metric("Evenements", detail["events_count"])

        st.markdown(f"**IP source:** `{detail['source_ip']}`")
        st.markdown(f"**Destinations:** {', '.join(detail['destination_ips']) or 'N/A'}")
        st.markdown(f"**Types/signatures observes:** {', '.join(detail['attack_types']) or 'N/A'}")
        st.markdown(f"**Premiere activite:** {detail['first_seen']}")
        st.markdown(f"**Derniere activite:** {detail['last_seen']}")

        st.markdown("**Evenements de preuve associes**")
        df_events = pd.DataFrame(detail["events"])
        st.dataframe(df_events, width="stretch", hide_index=True)

        if st.button("Generer le rapport LLM", type="primary"):
            with st.spinner(
                "Generation du rapport en cours. Le premier appel peut prendre plusieurs minutes..."
            ):
                report_result, report_err = api_post(
                    f"/api/incidents/{selected_id}/report",
                    timeout=610,
                )
            if report_err:
                st.error(report_err)
            else:
                st.subheader("Rapport d'incident (Ollama)")
                st.markdown(report_result["report"])
