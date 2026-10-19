"""
api.py
AI-HYBRID-IDS - Phase 15 (section 33)

API FastAPI, INDEPENDANTE du dashboard (section 34) et du processus de
detection live (section 53 - moindre privilege : cette API ne tourne PAS
sous sudo, contrairement a live_detection.py).

Lit uniquement les donnees deja persistees (logs/detections.csv,
data/incidents/incidents.db, results/metrics/*.json) - ne duplique pas la
logique de lecture temps reel d'eve.json (decision validee en Phase 15).

Lancement:
    uvicorn api:app --reload --port 8000
"""

import os
import sys
import json
import sqlite3
import subprocess
import signal
import psutil
import yaml
from datetime import datetime

import pandas as pd
from fastapi import FastAPI, HTTPException, Query

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "src", "utils"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "src", "evaluation"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "llm"))
sys.path.insert(0, os.path.join(SCRIPT_DIR, "..", "src", "network"))
from paths_utils import get_project_root
from check_data_drift import compute_drift
import report_generator
from geoip_lookup import lookup_ips

PROJECT_ROOT = get_project_root()
DETECTIONS_CSV_PATH = os.path.join(PROJECT_ROOT, "logs", "detections.csv")
INCIDENTS_DB_PATH = os.path.join(PROJECT_ROOT, "data", "incidents", "incidents.db")
RESULTS_METRICS_DIR = os.path.join(PROJECT_ROOT, "results", "metrics")
CONFIG_PATH = os.path.join(PROJECT_ROOT, "config", "config.yaml")
DETECTION_SCRIPT_PATH = os.path.join(PROJECT_ROOT, "src", "detection", "live_detection.py")
VENV_PYTHON_PATH = os.path.join(PROJECT_ROOT, "venv", "bin", "python3")
PID_FILE_PATH = os.path.join(PROJECT_ROOT, "logs", "live_detection.pid")

app = FastAPI(
    title="AI-HYBRID-IDS API",
    description="API de consultation des detections, alertes et incidents (section 33)",
    version="0.1.0",
)


def _read_detection_pid():
    """Lit un PID valide et supprime le fichier s'il est corrompu."""
    if not os.path.exists(PID_FILE_PATH):
        return None
    try:
        with open(PID_FILE_PATH) as pid_file:
            pid = int(pid_file.read().strip())
        if pid <= 0:
            raise ValueError
        return pid
    except (OSError, ValueError):
        try:
            os.remove(PID_FILE_PATH)
        except OSError:
            pass
        return None


def _is_detection_process_running(pid):
    """Evite de confondre un ancien PID recycle avec le moteur IDS."""
    if pid is None:
        return False
    try:
        process = psutil.Process(pid)
        if not process.is_running():
            return False
        command_line = " ".join(process.cmdline())
        return "live_detection.py" in command_line
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return False


def get_incidents_connection():
    if not os.path.exists(INCIDENTS_DB_PATH):
        raise HTTPException(status_code=503, detail=(
            "Base incidents introuvable - live_detection.py n'a probablement "
            "jamais ete lance. Chemin attendu: " + INCIDENTS_DB_PATH
        ))
    return sqlite3.connect(INCIDENTS_DB_PATH)


# ----------------------------------------------------------------------------
# GET /api/health
# ----------------------------------------------------------------------------
@app.get("/api/health")
def health():
    """Sante de l'API elle-meme (pas du systeme IDS complet - voir /api/status)."""
    return {"status": "ok", "timestamp": datetime.now().isoformat()}


# ----------------------------------------------------------------------------
# GET /api/status
# ----------------------------------------------------------------------------
@app.get("/api/status")
def status():
    """Etat du systeme: le processus de detection live tourne-t-il, fichiers presents."""
    detection_running = False
    pid = None
    pid = _read_detection_pid()
    detection_running = _is_detection_process_running(pid)

    return {
        "detection_engine_running": detection_running,
        "detection_engine_pid": pid,
        "detections_csv_exists": os.path.exists(DETECTIONS_CSV_PATH),
        "incidents_db_exists": os.path.exists(INCIDENTS_DB_PATH),
    }


# ----------------------------------------------------------------------------
# GET /api/flows
# ----------------------------------------------------------------------------
import math

def sanitize_nan(obj):
    """
    Remplace recursivement tout float NaN par None, quelle que soit sa
    provenance (colonnes pandas float64 avec valeurs manquantes, ex:
    dest_port absent sur les flows ICMP). Necessaire car df.where(...,None)
    seul est insuffisant: pandas reinjecte NaN dans une colonne float64 des
    qu'on tente d'y stocker un None (le dtype ne peut pas contenir de None).
    """
    if isinstance(obj, float) and math.isnan(obj):
        return None
    if isinstance(obj, dict):
        return {k: sanitize_nan(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_nan(v) for v in obj]
    return obj


MITRE_MAPPINGS = {
    "port scan": ("T1046", "Network Service Scanning"),
    "port scanning": ("T1046", "Network Service Scanning"),
    "brute force": ("T1110", "Brute Force"),
    "ddos": ("T1498", "Network Denial of Service"),
    "dos": ("T1498", "Network Denial of Service"),
    "web attacks": ("T1190", "Exploit Public-Facing Application"),
}


def enrich_incident_context(incident, events=None):
    """Ajoute des IOC observables et des mappings MITRE justifies."""
    events = events or []
    source_ips = {incident.get("source_ip")} if incident.get("source_ip") else set()
    destination_ips = set(incident.get("destination_ips") or [])
    ports = set()
    protocols = set()
    for event in events:
        if event.get("src_ip"):
            source_ips.add(event["src_ip"])
        if event.get("dest_ip"):
            destination_ips.add(event["dest_ip"])
        if event.get("dest_port") is not None:
            ports.add(event["dest_port"])

    techniques = []
    seen_techniques = set()
    for attack_type in incident.get("attack_types") or []:
        mapping = MITRE_MAPPINGS.get(str(attack_type).strip().lower())
        if mapping and mapping[0] not in seen_techniques:
            technique_id, name = mapping
            techniques.append({
                "id": technique_id,
                "name": name,
                "basis": f"Type observe: {attack_type}",
            })
            seen_techniques.add(technique_id)

    incident["iocs"] = {
        "source_ips": sorted(source_ips),
        "destination_ips": sorted(destination_ips),
        "destination_ports": sorted(ports),
        "protocols": sorted(protocols),
        "domains": [],
        "urls": [],
        "note": "IOC extraits des evenements observes; ils ne constituent pas une preuve absolue.",
    }
    incident["mitre_techniques"] = techniques
    return incident


def validate_config(config):
    """Refuse les reglages qui rendraient les decisions incoherentes."""
    if not isinstance(config, dict):
        raise HTTPException(status_code=422, detail="La configuration doit etre un objet JSON")

    decision = config.get("decision_engine", {})
    if not isinstance(decision, dict):
        raise HTTPException(status_code=422, detail="decision_engine doit etre un objet")

    weight_keys = [
        "weight_suricata", "weight_ml_confidence", "weight_model_agreement",
        "weight_anomaly", "weight_correlation",
    ]
    try:
        weights = [float(decision[key]) for key in weight_keys]
        thresholds = [
            float(decision["threshold_suspicious"]),
            float(decision["threshold_attack"]),
            float(decision["threshold_critical"]),
        ]
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Poids ou seuils decision_engine invalides")

    if any(not math.isfinite(value) or value < 0 or value > 1 for value in weights):
        raise HTTPException(status_code=422, detail="Chaque poids doit etre compris entre 0 et 1")
    if not math.isclose(sum(weights), 1.0, abs_tol=0.01):
        raise HTTPException(status_code=422, detail="La somme des poids doit etre egale a 1")
    if not all(0 <= value <= 1 for value in thresholds) or not (
        thresholds[0] < thresholds[1] < thresholds[2]
    ):
        raise HTTPException(status_code=422, detail="Les seuils doivent respecter 0 <= suspicious < attack < critical <= 1")

    correlation = config.get("correlation", {})
    incident = config.get("incident_engine", {})
    if not isinstance(correlation, dict) or not isinstance(incident, dict):
        raise HTTPException(status_code=422, detail="Les sections correlation et incident_engine sont invalides")
    try:
        window_seconds = int(correlation["window_seconds"])
        timeout_seconds = int(incident["timeout_seconds"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Les durees de correlation et d'incident sont invalides")
    if not 10 <= window_seconds <= 3600 or not 60 <= timeout_seconds <= 86400:
        raise HTTPException(status_code=422, detail="Les durees configurees sont hors limites")
    try:
        scan_port_threshold = int(correlation.get("scan_port_threshold", 10))
        repeated_attack_threshold = int(correlation.get("repeated_attack_threshold", 3))
        flood_packets_threshold = float(correlation.get("flood_packets_per_sec_threshold", 1000))
        flood_bytes_threshold = float(correlation.get("flood_bytes_per_sec_threshold", 1_000_000))
    except (TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Les seuils de correlation sont invalides")
    if not 2 <= scan_port_threshold <= 10000 or not 2 <= repeated_attack_threshold <= 1000:
        raise HTTPException(status_code=422, detail="Les seuils scan/repetition sont hors limites")
    if not 1 <= flood_packets_threshold <= 10_000_000 or not 1 <= flood_bytes_threshold <= 10_000_000_000:
        raise HTTPException(status_code=422, detail="Les seuils flood sont hors limites")

    llm = config.get("llm", {})
    if not isinstance(llm, dict):
        raise HTTPException(status_code=422, detail="La section llm est invalide")
    if not isinstance(llm.get("enabled"), bool) or not isinstance(llm.get("model"), str):
        raise HTTPException(status_code=422, detail="Les parametres LLM enabled/model sont invalides")
    try:
        llm_timeout = int(llm["timeout_seconds"])
        max_events = int(llm["max_events_in_prompt"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="Les parametres LLM numeriques sont invalides")
    if not 30 <= llm_timeout <= 600 or not 1 <= max_events <= 100:
        raise HTTPException(status_code=422, detail="Les limites LLM sont hors limites")

    logs = config.get("logs", {})
    if not isinstance(logs, dict):
        raise HTTPException(status_code=422, detail="La section logs est invalide")
    try:
        retention_days = int(logs["retention_days"])
    except (KeyError, TypeError, ValueError):
        raise HTTPException(status_code=422, detail="La retention des logs est invalide")
    if not 1 <= retention_days <= 3650:
        raise HTTPException(status_code=422, detail="La retention des logs est hors limites")


@app.get("/api/flows")
def get_flows(limit: int = Query(50, ge=1, le=1000)):
    """Derniers flows traites par le moteur de detection (logs/detections.csv)."""
    if not os.path.exists(DETECTIONS_CSV_PATH):
        return {"flows": [], "note": "Aucune donnee - live_detection.py n'a pas encore tourne"}

    df = pd.read_csv(DETECTIONS_CSV_PATH)
    df = df.tail(limit)
    records = sanitize_nan(df.to_dict(orient="records"))
    return {"count": len(records), "flows": records}


# ----------------------------------------------------------------------------
# GET /api/alerts
# ----------------------------------------------------------------------------
@app.get("/api/alerts")
def get_alerts(limit: int = Query(50, ge=1, le=1000)):
    """
    Alertes Suricata brutes enregistrees comme preuves d'incidents
    (incident_events, event_type='suricata_alert') - reutilise le stockage
    deja existant plutot que de dupliquer dans un fichier separe.
    """
    conn = get_incidents_connection()
    cur = conn.execute(
        "SELECT timestamp, src_ip, dest_ip, dest_port, detail AS signature, "
        "status, risk_score, incident_id "
        "FROM incident_events WHERE event_type='suricata_alert' "
        "ORDER BY event_id DESC LIMIT ?",
        (limit,),
    )
    cols = [d[0] for d in cur.description]
    rows = [dict(zip(cols, row)) for row in cur.fetchall()]
    conn.close()
    return {"count": len(rows), "alerts": rows}


# ----------------------------------------------------------------------------
# GET /api/incidents
# ----------------------------------------------------------------------------
@app.get("/api/incidents")
def get_incidents(status_filter: str = Query(None, alias="status")):
    """Liste des incidents (section 29). Filtre optionnel par statut."""
    conn = get_incidents_connection()
    query = "SELECT * FROM incidents"
    params = ()
    if status_filter:
        query += " WHERE status=?"
        params = (status_filter,)
    query += " ORDER BY last_seen DESC"

    cur = conn.execute(query, params)
    cols = [d[0] for d in cur.description]
    rows = []
    for row in cur.fetchall():
        record = dict(zip(cols, row))
        record["destination_ips"] = json.loads(record["destination_ips"])
        record["attack_types"] = json.loads(record["attack_types"])
        rows.append(enrich_incident_context(record))
    conn.close()
    return {"count": len(rows), "incidents": rows}


@app.get("/api/incidents/{incident_id}")
def get_incident_detail(incident_id: str):
    """Detail d'un incident + tous ses evenements de preuve associes."""
    conn = get_incidents_connection()
    cur = conn.execute("SELECT * FROM incidents WHERE id=?", (incident_id,))
    cols = [d[0] for d in cur.description]
    row = cur.fetchone()
    if row is None:
        conn.close()
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} introuvable")

    incident = dict(zip(cols, row))
    incident["destination_ips"] = json.loads(incident["destination_ips"])
    incident["attack_types"] = json.loads(incident["attack_types"])

    cur = conn.execute(
        "SELECT timestamp, event_type, src_ip, dest_ip, dest_port, detail, "
        "status, risk_score, flow_id FROM incident_events "
        "WHERE incident_id=? ORDER BY event_id ASC",
        (incident_id,),
    )
    ev_cols = [d[0] for d in cur.description]
    events = [dict(zip(ev_cols, r)) for r in cur.fetchall()]
    conn.close()

    incident["events"] = events
    return enrich_incident_context(incident, events)


# ----------------------------------------------------------------------------
# POST /api/incidents/{id}/report (Phase 17 - section 47)
# ----------------------------------------------------------------------------
@app.post("/api/incidents/{incident_id}/report")
def generate_incident_report_endpoint(incident_id: str):
    """
    Genere un rapport en francais via Ollama/Qwen pour cet incident.
    Le LLM ne prend AUCUNE decision - il redige uniquement a partir des
    faits deja etablis (section 47, Regle 5). Si Ollama est indisponible,
    retourne une erreur claire SANS faire planter l'API (le reste du
    systeme continue de fonctionner normalement).
    """
    incident = get_incident_detail(incident_id)  # reutilise la logique existante
    result = report_generator.generate_incident_report(incident)

    if not result["success"]:
        raise HTTPException(status_code=503, detail=result["error"])

    return {"incident_id": incident_id, "report": result["report"]}


# ----------------------------------------------------------------------------
# GET /api/metrics
# ----------------------------------------------------------------------------
@app.get("/api/metrics")
def get_metrics():
    """Metriques ML consolidees (Phase 8) + isolation forest."""
    summary_path = os.path.join(RESULTS_METRICS_DIR, "ml_evaluation_summary.json")
    if not os.path.exists(summary_path):
        raise HTTPException(status_code=503, detail="ml_evaluation_summary.json introuvable")
    with open(summary_path) as f:
        return json.load(f)


# ----------------------------------------------------------------------------
# GET /api/models
# ----------------------------------------------------------------------------
@app.get("/api/models")
def get_models():
    """Modeles actuellement retenus pour la production (section 6-7)."""
    summary_path = os.path.join(RESULTS_METRICS_DIR, "ml_evaluation_summary.json")
    if not os.path.exists(summary_path):
        raise HTTPException(status_code=503, detail="ml_evaluation_summary.json introuvable")
    with open(summary_path) as f:
        summary = json.load(f)
    return {
        "chosen_variants": summary.get("chosen_variants"),
        "models": summary.get("comparison_retained_models"),
        "isolation_forest": summary.get("isolation_forest"),
    }


@app.get("/api/model_health")
def get_model_health():
    """Etat des artefacts et resultat du controle de drift non destructif."""
    required_models = [
        os.path.join(PROJECT_ROOT, "models", "supervised", "random_forest_smote.pkl"),
        os.path.join(PROJECT_ROOT, "models", "supervised", "xgboost_smote.pkl"),
        os.path.join(PROJECT_ROOT, "models", "supervised", "lightgbm_classweight.pkl"),
        os.path.join(PROJECT_ROOT, "models", "unsupervised", "isolation_forest.pkl"),
    ]
    registry_path = os.path.join(PROJECT_ROOT, "models", "registry", "registry.json")
    registry = {"versions": []}
    if os.path.exists(registry_path):
        try:
            with open(registry_path) as registry_file:
                registry = json.load(registry_file)
        except (OSError, json.JSONDecodeError):
            registry = {"versions": [], "error": "registry.json invalide"}
    return {
        "artifacts_present": all(os.path.exists(path) for path in required_models),
        "automatic_retraining": False,
        "drift": compute_drift(PROJECT_ROOT),
        "registry": registry,
    }


# ----------------------------------------------------------------------------
# GET /api/geoip (Phase 18 - section 32)
# ----------------------------------------------------------------------------
@app.get("/api/geoip")
def get_geoip(ips: str = Query(..., description="Liste d'IP separees par des virgules")):
    """
    Resout une liste d'IP en localisation approximative (section 32).
    Ne geolocalise jamais les IP privees - filtrage fait dans geoip_lookup.py.
    Cet endpoint ne doit jamais faire echouer le dashboard: en cas de
    probleme reseau, les IP concernees reviennent avec status="unavailable"
    plutot que de lever une erreur HTTP.
    """
    ip_list = [ip.strip() for ip in ips.split(",") if ip.strip()]
    if not ip_list:
        raise HTTPException(status_code=422, detail="Parametre 'ips' vide")
    if len(ip_list) > 500:
        raise HTTPException(status_code=422, detail="Maximum 500 IP par requete")

    return {"results": lookup_ips(ip_list)}


# ----------------------------------------------------------------------------
# GET /api/system_health (Phase 16 - section 44)
# ----------------------------------------------------------------------------
@app.get("/api/system_health")
def get_system_health():
    """
    Etat systeme: CPU/RAM/disque, statut des services (Suricata, Ollama,
    notre propre detection engine), derniere activite connue.
    """
    import psutil

    cpu_percent = psutil.cpu_percent(interval=0.5)
    mem = psutil.virtual_memory()
    disk = psutil.disk_usage(PROJECT_ROOT)

    def service_active(name):
        try:
            r = subprocess.run(
                ["systemctl", "is-active", name],
                capture_output=True, text=True, timeout=3,
            )
            return r.stdout.strip() == "active"
        except Exception:
            return None  # inconnu (systemctl absent ou timeout) plutot que faux

    def ollama_reachable():
        try:
            r = subprocess.run(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                 "--max-time", "2", "http://localhost:11434/api/tags"],
                capture_output=True, text=True,
            )
            return r.stdout.strip() == "200"
        except Exception:
            return False

    last_detection_activity = None
    if os.path.exists(DETECTIONS_CSV_PATH):
        try:
            df_last = pd.read_csv(DETECTIONS_CSV_PATH).tail(1)
            if len(df_last) > 0:
                ts_value = df_last.iloc[0]["timestamp"]
                # Une derniere ligne peut etre tronquee (process tue en plein
                # ecriture, ex: pkill pendant les tests) -> pandas lit alors
                # NaN plutot qu'un timestamp. NaN n'est pas serialisable en
                # JSON strict (deja rencontre sur /api/flows) - on le detecte
                # explicitement ici plutot que de laisser planter la reponse.
                if pd.notna(ts_value):
                    last_detection_activity = str(ts_value)
        except Exception:
            pass

    # Verification REELLE que le process est vivant, pas juste que le fichier
    # PID existe (un fichier perime apres un crash donnerait un faux positif -
    # bug corrige suite a relecture, meme logique que /api/status).
    detection_running = False
    detection_pid = None
    detection_pid = _read_detection_pid()
    detection_running = _is_detection_process_running(detection_pid)

    required_models = [
        os.path.join(PROJECT_ROOT, "models", "supervised", "random_forest_smote.pkl"),
        os.path.join(PROJECT_ROOT, "models", "supervised", "xgboost_smote.pkl"),
        os.path.join(PROJECT_ROOT, "models", "supervised", "lightgbm_classweight.pkl"),
        os.path.join(PROJECT_ROOT, "models", "unsupervised", "isolation_forest.pkl"),
    ]
    models_present = all(os.path.exists(p) for p in required_models)

    return {
        "cpu_percent": cpu_percent,
        "cpu_count_logical": psutil.cpu_count(logical=True),
        "memory": {
            "total_gb": round(mem.total / (1024**3), 2),
            "used_gb": round(mem.used / (1024**3), 2),
            "available_gb": round(mem.available / (1024**3), 2),
            "percent": mem.percent,
        },
        "disk": {
            "total_gb": round(disk.total / (1024**3), 2),
            "used_gb": round(disk.used / (1024**3), 2),
            "free_gb": round(disk.free / (1024**3), 2),
            "percent": disk.percent,
        },
        "services": {
            "suricata": service_active("suricata"),
            "ollama": service_active("ollama"),
        },
        "ollama_api_reachable": ollama_reachable(),
        "detection_engine_running": detection_running,
        "detection_engine_pid": detection_pid,
        "models_present": models_present,
        "last_detection_activity": last_detection_activity,
        "warnings": _compute_health_warnings(
            cpu_percent, mem.percent, disk.percent,
            detection_running, service_active("suricata"), models_present,
        ),
    }


def _compute_health_warnings(cpu_pct, mem_pct, disk_pct, detection_running,
                              suricata_active, models_present,
                              cpu_threshold=90, mem_threshold=90, disk_threshold=90):
    """Signaux simples style section 44 (CPU HIGH, RAM HIGH, SURICATA DOWN...)."""
    warnings = []
    if cpu_pct >= cpu_threshold:
        warnings.append("CPU HIGH")
    if mem_pct >= mem_threshold:
        warnings.append("RAM HIGH")
    if disk_pct >= disk_threshold:
        warnings.append("DISK HIGH")
    if suricata_active is False:
        warnings.append("SURICATA DOWN")
    if not detection_running:
        warnings.append("DETECTION ENGINE DOWN")
    if not models_present:
        warnings.append("MODEL ERROR")
    return warnings


# ----------------------------------------------------------------------------
# POST /api/start | POST /api/stop
# ----------------------------------------------------------------------------
# ----------------------------------------------------------------------------
# GET/POST /api/config (Phase 16 suite - section 45)
# ----------------------------------------------------------------------------
@app.get("/api/config")
def get_config():
    """Lit config/config.yaml tel quel. Un changement via POST necessite un
    redemarrage de live_detection.py pour s'appliquer (pas de rechargement
    a chaud - limite assumee et documentee)."""
    if not os.path.exists(CONFIG_PATH):
        raise HTTPException(status_code=404, detail="config.yaml introuvable")
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f) or {}


@app.post("/api/config")
def update_config(new_config: dict):
    """
    Ecrit une nouvelle version de config.yaml. Validation minimale volontaire
    (on ne bloque pas sur des valeurs "bizarres" - l'utilisateur reste
    responsable, comme pour un fichier edite a la main). Sauvegarde l'ancienne
    version avant d'ecraser, par prudence.
    """
    validate_config(new_config)

    if os.path.exists(CONFIG_PATH):
        backup_path = CONFIG_PATH + ".bak"
        with open(CONFIG_PATH) as f_in, open(backup_path, "w") as f_out:
            f_out.write(f_in.read())

    with open(CONFIG_PATH, "w") as f:
        yaml.safe_dump(new_config, f, allow_unicode=True, sort_keys=False)

    return {
        "status": "saved",
        "note": "Redemarrez live_detection.py pour appliquer les changements "
                "(pas de rechargement a chaud).",
    }


@app.post("/api/start")
def start_detection():
    """
    Lance live_detection.py en arriere-plan.

    LIMITE DE SECURITE EXPLICITE (section 53): live_detection.py necessite
    sudo pour lire /var/log/suricata/eve.json (proprietaire root). Cette API
    tourne volontairement SANS sudo (moindre privilege). Pour que ce endpoint
    fonctionne sans intervention manuelle, une regle sudoers NOPASSWD dediee
    et limitee a ce script precis doit etre configuree par l'administrateur -
    ce n'est PAS fait automatiquement ici, et ne doit jamais l'etre de façon
    generique (risque de privilege escalation majeur si mal configure).
    """
    old_pid = _read_detection_pid()
    if _is_detection_process_running(old_pid):
        return {"status": "already_running", "pid": old_pid}

    if not os.path.isfile(VENV_PYTHON_PATH) or not os.path.isfile(DETECTION_SCRIPT_PATH):
        raise HTTPException(status_code=500, detail="Python virtuel ou moteur de detection introuvable")

    os.makedirs(os.path.join(PROJECT_ROOT, "logs"), exist_ok=True)
    log_path = os.path.join(PROJECT_ROOT, "logs", "live_detection_stdout.log")
    log_file = open(log_path, "a")
    try:
        proc = subprocess.Popen(
            ["sudo", "-n", VENV_PYTHON_PATH, DETECTION_SCRIPT_PATH],
            stdout=log_file,
            stderr=subprocess.STDOUT,
        )
    except OSError as e:
        log_file.close()
        raise HTTPException(status_code=500, detail=f"Echec lancement: {e}")
    finally:
        log_file.close()

    os.makedirs(os.path.dirname(PID_FILE_PATH), exist_ok=True)
    with open(PID_FILE_PATH, "w") as f:
        f.write(str(proc.pid))

    return {
        "status": "started",
        "pid": proc.pid,
        "warning": (
            "Necessite une regle sudoers NOPASSWD prealable pour ce script "
            "precis, sinon 'sudo -n' echouera silencieusement (verifier "
            "/api/status juste apres pour confirmer)."
        ),
    }


@app.post("/api/stop")
def stop_detection():
    """Arrete proprement live_detection.py (SIGINT, meme mecanisme que Ctrl+C)."""
    pid = _read_detection_pid()
    if pid is None:
        raise HTTPException(status_code=404, detail="Aucun processus de detection connu")

    if not _is_detection_process_running(pid):
        try:
            os.remove(PID_FILE_PATH)
        except OSError:
            pass
        raise HTTPException(status_code=404, detail="Processus de detection deja arrete")

    try:
        os.kill(pid, signal.SIGINT)
    except ProcessLookupError:
        os.remove(PID_FILE_PATH)
        raise HTTPException(status_code=404, detail="Processus deja arrete")

    os.remove(PID_FILE_PATH)
    return {"status": "stopped", "pid": pid}
