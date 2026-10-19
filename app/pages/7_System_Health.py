"""
7_System_Health.py
AI-HYBRID-IDS - Phase 16 (suite) - Page System Health (section 44)
"""

import os
import sys
from datetime import datetime

import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - System Health", layout="wide")
if not check_password():
    st.stop()
st.title("System Health")
st.caption("Actualisation automatique toutes les 10 secondes.")


@st.fragment(run_every="10s")
def render_system_health():
    health, err = api_get("/api/system_health")
    st.caption(f"Derniere mise a jour : {datetime.now().astimezone():%H:%M:%S}")

    if err:
        st.error(err)
        return

    # ----------------------------------------------------------------------------
    # Signaux d'alerte (section 44: CPU HIGH, RAM HIGH, SURICATA DOWN...)
    # ----------------------------------------------------------------------------
    warnings = health.get("warnings", [])
    if warnings:
        st.error("⚠️ " + " | ".join(warnings))
    else:
        st.success("Aucun signal d'alerte systeme.")

    st.divider()

    # ----------------------------------------------------------------------------
    # Ressources materielles
    # ----------------------------------------------------------------------------
    st.subheader("Ressources")

    c1, c2, c3 = st.columns(3)
    with c1:
        st.metric("CPU", f"{health['cpu_percent']:.1f}%")
        st.caption(f"{health['cpu_count_logical']} threads logiques")
    with c2:
        mem = health["memory"]
        st.metric("RAM", f"{mem['percent']:.1f}%")
        st.caption(f"{mem['used_gb']} / {mem['total_gb']} Go utilises "
                   f"({mem['available_gb']} Go disponibles)")
    with c3:
        disk = health["disk"]
        st.metric("Disque", f"{disk['percent']:.1f}%")
        st.caption(f"{disk['used_gb']} / {disk['total_gb']} Go utilises "
                   f"({disk['free_gb']} Go libres)")

    st.divider()

    # ----------------------------------------------------------------------------
    # Etat des services / processus
    # ----------------------------------------------------------------------------
    st.subheader("Services et processus")

    def status_badge(is_up):
        if is_up is True:
            return "🟢 ACTIF"
        if is_up is False:
            return "🔴 ARRETE"
        return "⚪ INCONNU"

    services = health.get("services", {})

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown("**Suricata**")
        st.markdown(status_badge(services.get("suricata")))
    with c2:
        st.markdown("**Ollama (service)**")
        st.markdown(status_badge(services.get("ollama")))
        st.caption("Optionnel : requis uniquement pour generer des rapports LLM.")
    with c3:
        st.markdown("**Ollama (API reachable)**")
        st.markdown(status_badge(health.get("ollama_api_reachable")))
    with c4:
        st.markdown("**Moteur de detection**")
        running = health.get("detection_engine_running")
        st.markdown(status_badge(running))
        if running and health.get("detection_engine_pid"):
            st.caption(f"PID: {health['detection_engine_pid']}")

    st.divider()

    # ----------------------------------------------------------------------------
    # Modeles et derniere activite
    # ----------------------------------------------------------------------------
    st.subheader("Modeles et activite")

    c1, c2 = st.columns(2)
    with c1:
        st.markdown("**Fichiers modeles presents**")
        st.markdown(status_badge(health.get("models_present")))
        if not health.get("models_present"):
            st.caption("Verifier models/supervised/ et models/unsupervised/ - "
                       "voir Phases 4-7 pour regenerer si necessaire.")
    with c2:
        st.markdown("**Derniere activite de detection**")
        last = health.get("last_detection_activity")
        st.markdown(f"`{last}`" if last else "Aucune activite enregistree")


render_system_health()
