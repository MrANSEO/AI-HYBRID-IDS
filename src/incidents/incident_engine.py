"""
incident_engine.py
AI-HYBRID-IDS - Phase 14 (section 29)

Transforme les evenements (verdicts ML + alertes Suricata) en incidents
persistants stockes en SQLite. Un incident regroupe l'activite d'une IP
source sur une fenetre glissante (par defaut 300s de silence = incident
considere termine, passe automatiquement en RESOLVED).

Ne cree/etend un incident que pour les statuts SUSPICIOUS/ATTACK/CRITICAL
(jamais NORMAL, jamais UNKNOWN) - coherent avec le Decision Engine (Phase 13).
Les alertes Suricata brutes generent TOUJOURS au moins un incident (Regle 7),
meme sans confirmation ML, avec un statut plancher SUSPICIOUS.
"""

import json
import sqlite3
import uuid
from datetime import datetime

SEVERITY_RANK = {"SUSPICIOUS": 1, "ATTACK": 2, "CRITICAL": 3}
INCIDENT_TIMEOUT_SECONDS = 300  # 5 min de silence -> incident clos automatiquement


def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id TEXT PRIMARY KEY,
            source_ip TEXT NOT NULL,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            destination_ips TEXT NOT NULL DEFAULT '[]',
            attack_types TEXT NOT NULL DEFAULT '[]',
            status TEXT NOT NULL DEFAULT 'OPEN',
            severity TEXT NOT NULL,
            max_risk_score REAL NOT NULL DEFAULT 0.0,
            events_count INTEGER NOT NULL DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS incident_events (
            event_id INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            timestamp TEXT,
            event_type TEXT NOT NULL,   -- 'ml_verdict' ou 'suricata_alert'
            src_ip TEXT,
            dest_ip TEXT,
            dest_port INTEGER,
            detail TEXT,                -- classe predite ou signature
            status TEXT,
            risk_score REAL,
            flow_id INTEGER,
            FOREIGN KEY(incident_id) REFERENCES incidents(id)
        )
    """)
    conn.commit()


def _parse_ts(ts_str):
    """Parse un timestamp Suricata ISO8601, avec repli sur l'heure actuelle si absent/invalide."""
    if not ts_str:
        return datetime.now().astimezone()
    try:
        return datetime.fromisoformat(ts_str)
    except ValueError:
        return datetime.now().astimezone()


def _generate_incident_id(event_dt):
    date_str = event_dt.strftime("%Y%m%d")
    return f"INC-{date_str}-{uuid.uuid4().hex[:8]}"


def get_or_create_incident(conn, source_ip, event_timestamp_str, initial_severity):
    """
    Retourne l'ID d'un incident OPEN existant pour cette IP source si son
    dernier evenement date de moins de INCIDENT_TIMEOUT_SECONDS, sinon cree
    un nouvel incident (et cloture l'ancien en RESOLVED s'il existait mais
    etait perime).
    """
    event_dt = _parse_ts(event_timestamp_str)

    cur = conn.execute(
        "SELECT id, last_seen FROM incidents WHERE source_ip=? AND status='OPEN' "
        "ORDER BY last_seen DESC LIMIT 1",
        (source_ip,),
    )
    row = cur.fetchone()

    if row is not None:
        incident_id, last_seen_str = row
        last_seen_dt = _parse_ts(last_seen_str)
        elapsed = abs((event_dt - last_seen_dt).total_seconds())
        if elapsed <= INCIDENT_TIMEOUT_SECONDS:
            return incident_id
        else:
            # Incident perime (silence > timeout) - on le cloture proprement
            conn.execute("UPDATE incidents SET status='RESOLVED' WHERE id=?", (incident_id,))

    new_id = _generate_incident_id(event_dt)
    conn.execute(
        "INSERT INTO incidents (id, source_ip, first_seen, last_seen, "
        "destination_ips, attack_types, status, severity, max_risk_score, events_count) "
        "VALUES (?, ?, ?, ?, '[]', '[]', 'OPEN', ?, 0.0, 0)",
        (new_id, source_ip, event_timestamp_str, event_timestamp_str, initial_severity),
    )
    conn.commit()
    return new_id


def record_event(conn, source_ip, dest_ip, dest_port, detail, event_type,
                  status, risk_score, timestamp, flow_id=None):
    """
    Point d'entree principal (Phase 14). Enregistre un evenement (verdict ML
    ou alerte Suricata) dans l'incident actif pour cette IP source (le cree
    si besoin), et met a jour les champs agreges de l'incident.
    """
    if status not in SEVERITY_RANK:
        return None  # NORMAL ou UNKNOWN - pas d'incident (section 29)

    incident_id = get_or_create_incident(conn, source_ip, timestamp, status)

    cur = conn.execute(
        "SELECT destination_ips, attack_types, severity, max_risk_score, events_count "
        "FROM incidents WHERE id=?",
        (incident_id,),
    )
    dest_ips_json, attack_types_json, current_severity, max_risk, events_count = cur.fetchone()
    dest_ips = set(json.loads(dest_ips_json))
    attack_types = set(json.loads(attack_types_json))

    if dest_ip:
        dest_ips.add(dest_ip)
    if detail and detail != "Normal Traffic":
        attack_types.add(detail)

    new_severity = current_severity
    if SEVERITY_RANK.get(status, 0) > SEVERITY_RANK.get(current_severity, 0):
        new_severity = status

    new_max_risk = max(max_risk, risk_score or 0.0)

    conn.execute(
        "UPDATE incidents SET last_seen=?, destination_ips=?, attack_types=?, "
        "severity=?, max_risk_score=?, events_count=? WHERE id=?",
        (
            timestamp, json.dumps(sorted(dest_ips)), json.dumps(sorted(attack_types)),
            new_severity, new_max_risk, events_count + 1, incident_id,
        ),
    )

    conn.execute(
        "INSERT INTO incident_events (incident_id, timestamp, event_type, src_ip, "
        "dest_ip, dest_port, detail, status, risk_score, flow_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (incident_id, timestamp, event_type, source_ip, dest_ip, dest_port,
         detail, status, risk_score, flow_id),
    )
    conn.commit()
    return incident_id
