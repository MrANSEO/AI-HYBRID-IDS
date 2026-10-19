import os
import sys

import pandas as pd
import streamlit as st

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "components"))
from api_client import api_get
from auth import check_password

st.set_page_config(page_title="AI-HYBRID-IDS - Network Map", layout="wide")
if not check_password():
    st.stop()

st.title("Network Map")
st.caption("Topologie reconstruite a partir des flux observes")

flows_data, flows_error = api_get("/api/flows", params={"limit": 500})
if flows_error:
    st.error(flows_error)
    st.stop()
if flows_data.get("count", 0) == 0:
    st.info("Aucun flux disponible pour construire la topologie.")
    st.stop()

flows = pd.DataFrame(flows_data["flows"])
connections = flows[["src_ip", "dest_ip", "status", "risk_score"]].copy()
connections["src_ip"] = connections["src_ip"].fillna("unknown")
connections["dest_ip"] = connections["dest_ip"].fillna("unknown")

col1, col2, col3 = st.columns(3)
col1.metric("Sources", connections["src_ip"].nunique())
col2.metric("Destinations", connections["dest_ip"].nunique())
col3.metric("Connexions", len(connections))

st.subheader("Connexions observees")
st.dataframe(
    connections.sort_values("risk_score", ascending=False),
    width="stretch",
    hide_index=True,
)

st.subheader("Visualisation topologique")
lines = ["digraph IDS {", "rankdir=LR;", "node [shape=box];"]
for index, row in connections.head(100).iterrows():
    source = str(row["src_ip"]).replace('"', '')
    destination = str(row["dest_ip"]).replace('"', '')
    status = str(row["status"]).replace('"', '')
    lines.append(
        f'"src:{source}" -> "dst:{destination}" '
        f'[label="{status} {float(row["risk_score"]):.2f}"];'
    )
lines.append("}")
st.graphviz_chart("\n".join(lines), use_container_width=True)

# ----------------------------------------------------------------------------
# GeoIP (Phase 18 - section 32)
# ----------------------------------------------------------------------------
st.subheader("Localisation GeoIP (IP publiques)")
st.caption(
    "Localisation estimee (au niveau ville/FAI), JAMAIS la position exacte "
    "de l'attaquant (section 32). Les IP privees ne sont jamais envoyees "
    "au fournisseur GeoIP - filtrage fait cote backend (geoip_lookup.py)."
)

all_ips = [ip for ip in pd.concat([connections["src_ip"], connections["dest_ip"]]).unique() if ip != "unknown"]

if not all_ips:
    st.info("Aucune IP a geolocaliser.")
else:
    geoip_data, geoip_error = api_get("/api/geoip", params={"ips": ",".join(all_ips[:500])})

    if geoip_error:
        st.warning(f"GeoIP indisponible: {geoip_error}")
    else:
        results = geoip_data.get("results", {})
        resolved = {
            ip: record for ip, record in results.items()
            if record.get("public") and record.get("status") in ("resolved", "cached")
        }

        if not resolved:
            st.info("Aucune IP publique geolocalisable parmi les flux affiches.")
        else:
            import folium
            from streamlit_folium import st_folium

            geo_map = folium.Map(location=[20, 0], zoom_start=2)  # tiles OpenStreetMap par defaut, gratuit, sans cle API

            source_ips = set(connections["src_ip"])
            destination_ips = set(connections["dest_ip"])

            for ip, record in resolved.items():
                if ip in source_ips and ip in destination_ips:
                    role, color = "source et destination", "orange"
                elif ip in source_ips:
                    role, color = "source", "red"
                else:
                    role, color = "destination", "blue"

                popup_text = (
                    f"<b>{ip}</b> ({role})<br>"
                    f"{record.get('city') or '?'}, {record.get('country') or '?'}<br>"
                    f"ISP: {record.get('isp') or '?'}"
                )
                folium.CircleMarker(
                    location=[record["lat"], record["lon"]],
                    radius=6,
                    color=color,
                    fill=True,
                    fill_opacity=0.8,
                    popup=folium.Popup(popup_text, max_width=250),
                ).add_to(geo_map)

            st.caption("Rouge: source d'attaque - Bleu: destination - Orange: les deux")
            st_folium(geo_map, width=1100, height=500, returned_objects=[])

            unavailable_public = [
                ip for ip, record in results.items()
                if record.get("public") and record.get("status") not in ("resolved", "cached")
            ]
            if unavailable_public:
                st.caption(
                    f"{len(unavailable_public)} IP publique(s) non geolocalisee(s) "
                    "(fournisseur GeoIP indisponible ou reponse invalide)."
                )
