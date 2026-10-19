"""
5_ML_Analytics.py
AI-HYBRID-IDS - Phase 16 (suite) - Page ML Analytics (section 40)

Affiche les performances des 3 modeles retenus (Phase 8) + l'accord entre
modeles observe en production (logs/detections.csv).

Limite assumee: la confusion matrix complete existe dans les fichiers
individuels (results/metrics/*_metrics.json) mais n'est pas exposee par
/api/metrics (qui sert ml_evaluation_summary.json). Cette page affiche donc
precision/recall/F1 par classe, pas la matrice complete.
"""

import os
import sys
import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - ML Analytics", layout="wide")
if not check_password():
    st.stop()
st.title("ML Analytics")

metrics, err = api_get("/api/metrics")

if err:
    st.error(err)
    st.stop()

# ----------------------------------------------------------------------------
# Comparatif des modeles retenus
# ----------------------------------------------------------------------------
st.subheader("Modeles retenus pour l'ensemble de vote")

models = metrics.get("comparison_retained_models", [])
df_models = pd.DataFrame([{
    "Modele": m["model"],
    "Variante": m["variant"],
    "F1-macro": round(m["f1_macro"], 4),
    "F1-weighted": round(m["f1_weighted"], 4),
    "Accuracy": round(m["accuracy"], 4),
    "Taille (MB)": round(m["model_size_mb"], 1),
    "Train (s)": round(m["train_time_s"]),
    "Inference (ms/ech.)": round(m["inference_time_per_sample_ms"], 5),
} for m in models])

st.dataframe(df_models, width="stretch", hide_index=True)

col1, col2 = st.columns(2)
with col1:
    st.markdown("**F1-macro par modele**")
    st.bar_chart(df_models.set_index("Modele")["F1-macro"])
with col2:
    st.markdown("**Taille des modeles (MB)**")
    st.bar_chart(df_models.set_index("Modele")["Taille (MB)"])

st.divider()

# ----------------------------------------------------------------------------
# Performance par classe
# ----------------------------------------------------------------------------
st.subheader("Performance par classe (F1-score)")

rows = []
for m in models:
    for cls, vals in m["per_class"].items():
        rows.append({
            "Modele": m["model"], "Classe": cls,
            "Precision": round(vals["precision"], 3),
            "Recall": round(vals["recall"], 3),
            "F1": round(vals["f1"], 3),
            "Support": vals["support"],
        })
df_per_class = pd.DataFrame(rows)

pivot_f1 = df_per_class.pivot(index="Classe", columns="Modele", values="F1")
st.bar_chart(pivot_f1)

selected_model = st.selectbox("Detail par modele", df_per_class["Modele"].unique())
st.dataframe(
    df_per_class[df_per_class["Modele"] == selected_model].drop(columns=["Modele"]),
    width="stretch", hide_index=True,
)

st.warning(
    "Classes faibles confirmees (Phase 8): 'Web Attacks' (precision ~0.12) et "
    "'Bots' (precision ~0.30-0.46). Les 3 modeles echouent de facon convergente "
    "sur ces classes - limite du feature set MVP a 12 variables, pas un defaut "
    "d'algorithme. C'est ce qui justifie l'architecture hybride avec Suricata."
)

st.divider()

# ----------------------------------------------------------------------------
# Toutes les variantes testees (transparence)
# ----------------------------------------------------------------------------
st.subheader("Toutes les variantes testees")
df_variants = pd.DataFrame(metrics.get("all_variants_tested", []))
if not df_variants.empty:
    df_variants["f1_macro"] = df_variants["f1_macro"].round(4)
    df_variants["f1_weighted"] = df_variants["f1_weighted"].round(4)
    st.dataframe(df_variants, width="stretch", hide_index=True)

st.divider()

# ----------------------------------------------------------------------------
# Accord entre modeles observe EN PRODUCTION (pas en labo)
# ----------------------------------------------------------------------------
st.subheader("Accord entre modeles observe en production")

flows_data, flows_err = api_get("/api/flows", params={"limit": 500})
if flows_err:
    st.warning(flows_err)
elif flows_data["count"] == 0:
    st.info("Aucun flux analyse pour l'instant.")
else:
    df_flows = pd.DataFrame(flows_data["flows"])
    agreement_counts = df_flows["model_agreement"].value_counts()

    c1, c2 = st.columns([1, 2])
    with c1:
        total = len(df_flows)
        full_agreement = (df_flows["model_agreement"] == "3/3").sum()
        c1.metric("Accord unanime (3/3)", f"{100*full_agreement/total:.1f}%")
        c1.metric("Flux analyses", total)
    with c2:
        st.markdown("**Repartition de l'accord inter-modeles**")
        st.bar_chart(agreement_counts)

    st.caption(
        "Un accord 2/3 ou 1/3 signale un cas ambigu ou les modeles divergent - "
        "pris en compte par le Decision Engine (poids model_agreement, Phase 13)."
    )
