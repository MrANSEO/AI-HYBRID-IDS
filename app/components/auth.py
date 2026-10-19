"""
auth.py - AI-HYBRID-IDS Phase 16 (section 46)
Authentification minimale du dashboard. Mot de passe stocke dans
.streamlit/secrets.toml (jamais dans le code - section 46).
"""
import streamlit as st

def check_password():
    if st.session_state.get("authenticated", False):
        return True

    st.title("AI-HYBRID-IDS — Connexion")
    pwd = st.text_input("Mot de passe", type="password")
    if st.button("Se connecter"):
        try:
            correct = st.secrets["dashboard_password"]
        except (KeyError, FileNotFoundError):
            st.error("secrets.toml manquant ou mal configure (voir .streamlit/secrets.toml)")
            return False
        if pwd == correct:
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Mot de passe incorrect")
    return False
