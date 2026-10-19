"""
correlation_engine.py
AI-HYBRID-IDS - Phase 12 (sections 9, 28)

Moteur de correlation temporelle par IP source.
Ne prend AUCUNE decision finale (pas de status/severity/risk_score - ce sera
le role du Decision Engine, Phase 13). Se contente de regrouper le contexte
recent (verdicts ML + alertes Suricata) et de calculer des signaux de
correlation simples et transparents.

Regles respectees (section 9):
- Une alerte Suricata n'est jamais ignoree parce que le ML dit "Normal".
- Une detection ML est prise en compte meme sans alerte Suricata correspondante.
"""

import time
from collections import defaultdict, deque


class CorrelationEngine:
    def __init__(self, window_seconds=60):
        self.window_seconds = window_seconds
        # Un deque d'evenements par IP source, trie par temps d'arrivee
        self._events_by_ip = defaultdict(deque)

    def _prune_old(self, src_ip, now):
        """Supprime les evenements plus vieux que la fenetre glissante pour cette IP."""
        events = self._events_by_ip[src_ip]
        while events and (now - events[0]["_internal_time"]) > self.window_seconds:
            events.popleft()

    def add_flow_verdict(self, src_ip, dest_ip, dest_port, predicted_class,
                          confidence, model_agreement, is_anomaly, anomaly_score,
                          flow_id, timestamp_str, packets=0, bytes_total=0,
                          packets_per_sec=0.0, bytes_per_sec=0.0):
        now = time.time()
        self._events_by_ip[src_ip].append({
            "_internal_time": now,
            "type": "ml_verdict",
            "timestamp": timestamp_str,
            "dest_ip": dest_ip,
            "dest_port": dest_port,
            "predicted_class": predicted_class,
            "confidence": confidence,
            "model_agreement": model_agreement,
            "is_anomaly": is_anomaly,
            "anomaly_score": anomaly_score,
            "flow_id": flow_id,
            "packets": packets or 0,
            "bytes_total": bytes_total or 0,
            "packets_per_sec": packets_per_sec or 0.0,
            "bytes_per_sec": bytes_per_sec or 0.0,
        })
        self._prune_old(src_ip, now)

    def add_alert(self, src_ip, signature, category, severity_text,
                  flow_id, timestamp_str):
        now = time.time()
        self._events_by_ip[src_ip].append({
            "_internal_time": now,
            "type": "suricata_alert",
            "timestamp": timestamp_str,
            "signature": signature,
            "category": category,
            "severity_text": severity_text,
            "flow_id": flow_id,
        })
        self._prune_old(src_ip, now)

    def get_context(self, src_ip):
        """
        Retourne le contexte agrege recent pour une IP source:
        signaux bruts, PAS de decision finale.
        """
        now = time.time()
        self._prune_old(src_ip, now)
        events = list(self._events_by_ip[src_ip])

        ml_events = [e for e in events if e["type"] == "ml_verdict"]
        alert_events = [e for e in events if e["type"] == "suricata_alert"]

        distinct_dest_ports = len(set(e["dest_port"] for e in ml_events))
        distinct_dest_ips = len(set(e["dest_ip"] for e in ml_events))
        attack_predictions = [e for e in ml_events if e["predicted_class"] != "Normal Traffic"]
        anomaly_flags = [e for e in ml_events if e["is_anomaly"]]
        total_packets = sum(e["packets"] for e in ml_events)
        total_bytes = sum(e["bytes_total"] for e in ml_events)
        peak_packets_per_sec = max(
            (e["packets_per_sec"] for e in ml_events), default=0.0
        )
        peak_bytes_per_sec = max(
            (e["bytes_per_sec"] for e in ml_events), default=0.0
        )

        return {
            "src_ip": src_ip,
            "window_seconds": self.window_seconds,
            "total_ml_events": len(ml_events),
            "total_alert_events": len(alert_events),
            "distinct_dest_ports": distinct_dest_ports,
            "distinct_dest_ips": distinct_dest_ips,
            "attack_class_count": len(attack_predictions),
            "attack_classes_seen": sorted(set(e["predicted_class"] for e in attack_predictions)),
            "anomaly_count": len(anomaly_flags),
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "peak_packets_per_sec": peak_packets_per_sec,
            "peak_bytes_per_sec": peak_bytes_per_sec,
            "alert_signatures": [e["signature"] for e in alert_events],
        }

    def evaluate_signals(self, src_ip,
                          scan_port_threshold=10,
                          repeated_attack_threshold=3,
                          flood_packets_per_sec_threshold=1000,
                          flood_bytes_per_sec_threshold=1_000_000):
        """
        Calcule des signaux de correlation simples, explicites et documentes.
        Ce ne sont PAS des verdicts finaux (pas de status/severity) - juste des
        indices transparents que le Decision Engine (Phase 13) pourra utiliser.
        """
        ctx = self.get_context(src_ip)
        signals = []

        if ctx["distinct_dest_ports"] >= scan_port_threshold:
            signals.append(
                f"POSSIBLE_SCAN: {ctx['distinct_dest_ports']} ports distincts "
                f"contactes en {self.window_seconds}s"
            )

        if (
            ctx["peak_packets_per_sec"] >= flood_packets_per_sec_threshold
            or ctx["peak_bytes_per_sec"] >= flood_bytes_per_sec_threshold
        ):
            signals.append(
                f"POSSIBLE_FLOOD: pic={ctx['peak_packets_per_sec']:.1f} paquets/s, "
                f"{ctx['peak_bytes_per_sec']:.1f} octets/s en {self.window_seconds}s"
            )

        if ctx["attack_class_count"] >= repeated_attack_threshold:
            signals.append(
                f"REPEATED_ML_ATTACK_PREDICTION: {ctx['attack_class_count']} flows "
                f"classes hors Normal en {self.window_seconds}s "
                f"(classes: {', '.join(ctx['attack_classes_seen'])})"
            )

        if ctx["total_alert_events"] > 0 and ctx["attack_class_count"] > 0:
            signals.append(
                f"SURICATA_ML_CONVERGENCE: {ctx['total_alert_events']} alerte(s) Suricata "
                f"ET {ctx['attack_class_count']} prediction(s) ML d'attaque pour la meme IP"
            )
        elif ctx["total_alert_events"] > 0:
            # Rule section 9: une alerte Suricata compte MEME si le ML dit Normal
            signals.append(
                f"SURICATA_ALONE: {ctx['total_alert_events']} alerte(s) Suricata "
                f"sans confirmation ML d'attaque - a ne jamais ignorer"
            )

        return ctx, signals
