"""
feature_extraction.py
AI-HYBRID-IDS - Module partage

Logique d'extraction des 12 features MVP depuis un evenement Suricata
event_type=flow. Utilise par extract_features_from_eve.py (Phase 9) et
live_detection.py (Phase 11).
"""

from datetime import datetime

FEATURE_ORDER = [
    "destination_port", "flow_duration", "total_fwd_packets", "total_fwd_bytes",
    "flow_bytes_per_sec", "flow_packets_per_sec", "fwd_packets_per_sec",
    "bwd_packets_per_sec", "avg_packet_size", "fin_flag_present",
    "psh_flag_present", "ack_flag_present",
]


def parse_suricata_timestamp(ts_str):
    return datetime.fromisoformat(ts_str)


def extract_features(flow_event):
    """
    Transforme un evenement event_type=flow de Suricata en dict de 12 features.
    Retourne None si l'evenement est invalide/incomplet.
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

    if duration_seconds > 0:
        flow_bytes_per_sec = total_bytes / duration_seconds
        flow_packets_per_sec = total_packets / duration_seconds
        fwd_packets_per_sec = pkts_toserver / duration_seconds
        bwd_packets_per_sec = pkts_toclient / duration_seconds
    else:
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

    assert list(features.keys()) == FEATURE_ORDER, "Schema de features incoherent"

    return features
