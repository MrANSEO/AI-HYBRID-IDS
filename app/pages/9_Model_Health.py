import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - Model Health", layout="wide")
if not check_password():
    st.stop()

st.title("Model Health")
st.caption("Etat des artefacts et metriques du modele actuellement deploye")

models_data, models_error = api_get("/api/models")
metrics_data, metrics_error = api_get("/api/metrics")
health_data, health_error = api_get("/api/model_health")

if models_error:
    st.error(models_error)
    st.stop()

models = models_data.get("models") or []
if not models:
    st.warning("Aucun modele retenu expose par l'API.")
else:
    rows = []
    for model in models:
        rows.append({
            "Modele": model.get("model"),
            "Variante": model.get("variant"),
            "Macro-F1": model.get("f1_macro"),
            "Weighted-F1": model.get("f1_weighted"),
            "Inference (ms)": model.get("inference_time_per_sample_ms"),
            "Taille (MB)": model.get("model_size_mb"),
        })
    st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)

st.divider()
st.subheader("Etat des controles")
col1, col2, col3 = st.columns(3)
with col1:
    artifacts_present = health_data.get("artifacts_present") if not health_error else False
    st.metric("Artefacts", "PRESENTS" if artifacts_present else "ERREUR")
with col2:
    drift = health_data.get("drift", {}) if not health_error else {}
    st.metric("Data drift", drift.get("status", "INCONNU"))
with col3:
    st.metric("Retraining automatique", "DESACTIVE")

if health_error:
    st.warning(health_error)
else:
    st.info(health_data.get("drift", {}).get("recommendation", "Aucune recommandation"))

    registry = health_data.get("registry", {}) if not health_error else {}
    versions = registry.get("versions", [])
    if versions:
        st.subheader("Model Registry")
        st.dataframe(
            pd.DataFrame([
                {
                    "Version": item.get("version"),
                    "Statut": item.get("status"),
                    "Enregistre le": item.get("registered_at"),
                    "Deploiement automatique": item.get("automatic_deployment"),
                }
                for item in versions
            ]),
            width="stretch",
            hide_index=True,
        )
    else:
        st.caption("Aucune version de registre. Enregistrer manuellement une version apres validation.")

if not metrics_error:
    iso = metrics_data.get("isolation_forest") or {}
    st.subheader("Isolation Forest")
    st.json({
        "contamination": iso.get("contamination"),
        "average_detection_rate_attacks_pct": iso.get("average_detection_rate_attacks_pct"),
        "average_false_positive_rate_pct": iso.get("average_false_positive_rate_pct"),
    })
