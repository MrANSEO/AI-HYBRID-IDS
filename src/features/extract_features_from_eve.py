"""
extract_features_from_eve.py
AI-HYBRID-IDS - Phase 9 (etape 1/2)

Lit les evenements event_type=flow d'un fichier eve.json et les transforme
en vecteurs de 12 features, identiques en structure/echelle au Feature Contract MVP.

ETAPE 1 SEULEMENT: extraction et affichage, PAS de prediction.
Objectif: valider visuellement le mapping avant de brancher les modeles (Phase 9 etape 2).
"""

import json
import sys
from datetime import datetime

FEATURE_ORDER = [
    "destination_port", "flow_duration", "total_fwd_packets", "total_fwd_bytes",
    "flow_bytes_per_sec", "flow_packets_per_sec", "fwd_packets_per_sec",
    "bwd_packets_per_sec", "avg_packet_size", "fin_flag_present",
    "psh_flag_present", "ack_flag_present",
]


def parse_suricata_timestamp(ts_str):
    """Parse un timestamp Suricata ISO8601 avec timezone (ex: 2026-09-04T16:31:53.850058+0200)."""
    return datetime.fromisoformat(ts_str)


def extract_features(flow_event):
    """
    Transforme un evenement event_type=flow de Suricata en dict de 12 features.
    Retourne None si l'evenement est invalide/incomplet (pas assez d'info pour extraire).
    """
    if flow_event.get("event_type") != "flow":
        return None

    flow = flow_event.get("flow")
    if flow is None:
        return None

    try:
        start = parse_suricata_timestamp(flow["start"])
        end = parse_suricata_timestamp(flow["end"])
    except (KeyError, ValueError):
        return None

    duration_seconds = (end - start).total_seconds()
    flow_duration_us = int(duration_seconds * 1_000_000)

    pkts_toserver = flow.get("pkts_toserver", 0)
    pkts_toclient = flow.get("pkts_toclient", 0)
    bytes_toserver = flow.get("bytes_toserver", 0)
    bytes_toclient = flow.get("bytes_toclient", 0)

    total_packets = pkts_toserver + pkts_toclient
    total_bytes = bytes_toserver + bytes_toclient

    # Protection division par zero (flows tres courts, duration=0 ou 1 seul paquet)
    if duration_seconds > 0:
        flow_bytes_per_sec = total_bytes / duration_seconds
        flow_packets_per_sec = total_packets / duration_seconds
        fwd_packets_per_sec = pkts_toserver / duration_seconds
        bwd_packets_per_sec = pkts_toclient / duration_seconds
    else:
        # Duree nulle (paquets quasi-simultanes) - eviter Inf, mettre a 0
        # (coherent avec le nettoyage Phase 2 qui a supprime les valeurs Inf/negatives)
        flow_bytes_per_sec = 0.0
        flow_packets_per_sec = 0.0
        fwd_packets_per_sec = 0.0
        bwd_packets_per_sec = 0.0

    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0.0

    tcp_info = flow_event.get("tcp", {})
    fin_flag = int(tcp_info.get("fin", False))
    psh_flag = int(tcp_info.get("psh", False))
    ack_flag = int(tcp_info.get("ack", False))

    features = {
        "destination_port": flow_event.get("dest_port", 0),
        "flow_duration": flow_duration_us,
        "total_fwd_packets": pkts_toserver,
        "total_fwd_bytes": bytes_toserver,
        "flow_bytes_per_sec": flow_bytes_per_sec,
        "flow_packets_per_sec": flow_packets_per_sec,
        "fwd_packets_per_sec": fwd_packets_per_sec,
        "bwd_packets_per_sec": bwd_packets_per_sec,
        "avg_packet_size": avg_packet_size,
        "fin_flag_present": fin_flag,
        "psh_flag_present": psh_flag,
        "ack_flag_present": ack_flag,
    }

    # Validation section 57 - verifier que le vecteur a exactement les features attendues,
    # dans l'ordre attendu, avant de le considerer valide
    if list(features.keys()) != FEATURE_ORDER:
        print("ERREUR: schema de features incoherent - ne devrait jamais arriver ici",
              file=sys.stderr)
        return None

    return features, flow_event


def main(eve_path, max_flows=10):
    print(f"Lecture de: {eve_path}")
    print(f"Extraction des {max_flows} derniers evenements 'flow' valides\n")

    flow_events = []
    with open(eve_path, "r") as f:
        for line in f:
            try:
                evt = json.loads(line)
            except json.JSONDecodeError:
                continue
            if evt.get("event_type") == "flow":
                flow_events.append(evt)

    flow_events = flow_events[-max_flows:]
    print(f"{len(flow_events)} evenements 'flow' trouves (sur les derniers du fichier)\n")

    for i, evt in enumerate(flow_events):
        result = extract_features(evt)
        print(f"--- Flow #{i+1} ---")
        print(f"  Source: {evt.get('src_ip')}:{evt.get('src_port')} -> "
              f"{evt.get('dest_ip')}:{evt.get('dest_port')} ({evt.get('proto')})")

        if result is None:
            print("  IGNORE - donnees insuffisantes pour extraction\n")
            continue

        features, _ = result
        for name in FEATURE_ORDER:
            print(f"    {name:<22} = {features[name]}")
        print()


if __name__ == "__main__":
    eve_path = sys.argv[1] if len(sys.argv) > 1 else "/var/log/suricata/eve.json"
    max_flows = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    main(eve_path, max_flows)
