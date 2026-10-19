"""
report_generator.py
AI-HYBRID-IDS - Phase 17 (sections 47-48)

Genere un rapport en francais pour un incident, via Ollama/Qwen local.

REGLES ABSOLUES RESPECTEES:
- Le LLM ne prend JAMAIS de decision de securite (Regle 5) - il redige
  uniquement un rapport a partir de faits DEJA etablis par le Decision Engine
  et l'Incident Engine (Phases 13-14).
- Le systeme continue de fonctionner si Ollama est indisponible (section 47) -
  aucune exception ne doit remonter jusqu'a l'appelant sans etre geree.
- Le rapport distingue explicitement FAITS OBSERVES et INTERPRETATION
  (section 48), pour limiter les hallucinations du LLM.
"""

import os
import sys

import requests
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "utils"))
from paths_utils import get_project_root

OLLAMA_URL = "http://localhost:11434/api/generate"
OLLAMA_MODEL = "qwen2.5:3b"
# Calcule a partir de mesures reelles (05/09-12/09/2026, CPU i5-6200U 4 threads,
# test isole sans concurrence avec live_detection.py):
# incident volumineux (14 dest IP, 6 types attaque, prompt tronque a 15 evenements
# = 2143 tokens): 123.8s traitement prompt + 73.5s generation (plafonnee a 400
# tokens) = 221.7s mesures. Marge fixee a 320s pour absorber le rechargement
# eventuel du modele en memoire (Ollama decharge apres inactivite) et une
# possible concurrence CPU avec live_detection.py en usage reel simultane.
OLLAMA_TIMEOUT_SECONDS = 320


MAX_EVENTS_IN_PROMPT = 15


def _load_llm_config():
    """Charge les reglages LLM sans rendre le rapport dependant de YAML."""
    defaults = {
        "enabled": True,
        "model": OLLAMA_MODEL,
        "timeout_seconds": OLLAMA_TIMEOUT_SECONDS,
        "max_events_in_prompt": MAX_EVENTS_IN_PROMPT,
    }
    config_path = os.path.join(get_project_root(), "config", "config.yaml")
    try:
        with open(config_path) as config_file:
            values = yaml.safe_load(config_file).get("llm", {}) or {}
        defaults.update(values)
    except (OSError, AttributeError, TypeError, yaml.YAMLError):
        pass
    return defaults


def build_prompt(incident):
    """
    Construit un prompt structure a partir des faits de l'incident
    (dict au format retourne par GET /api/incidents/{id}).
    Le prompt liste explicitement les faits et interdit au modele d'en
    inventer d'autres.

    Les evenements sont tronques a MAX_EVENTS_IN_PROMPT (les plus recents) -
    necessaire car certains incidents accumulent des dizaines d'evenements
    (observe empiriquement: un incident a atteint 80 evenements), ce qui
    ferait exploser la taille du prompt et le temps de traitement CPU.
    """
    llm_config = _load_llm_config()
    max_events = max(1, int(llm_config["max_events_in_prompt"]))
    events = incident.get("events", [])
    total_events = len(events)
    truncated = total_events > max_events
    events_to_show = events[-max_events:] if truncated else events

    events_summary = "\n".join(
        f"  - {e['timestamp']} | {e['event_type']} | {e['src_ip']} -> "
        f"{e.get('dest_ip', 'N/A')}:{e.get('dest_port', 'N/A')} | "
        f"{e['detail']} | statut={e['status']} | risk={e['risk_score']}"
        for e in events_to_show
    )
    if truncated:
        omitted = total_events - max_events
        events_summary += (
            f"\n  - [... {omitted} evenement(s) plus ancien(s) non affiches "
            f"ici, mais comptabilises dans le total ci-dessus ...]"
        )

    prompt = f"""Tu es un assistant qui redige des rapports d'incident de securite en francais, pour un mini-SOC.

REGLES STRICTES A RESPECTER:
1. N'utilise QUE les faits fournis ci-dessous. N'invente RIEN.
2. INTERDICTION ABSOLUE de recopier des listes brutes (IP, signatures) en
   puces une par une - resume-les en une phrase (ex: "14 adresses IP
   distinctes ont ete contactees, principalement vers des services cloud").
   Chaque section doit rester COURTE pour laisser de la place aux suivantes.
3. Structure ta reponse en TROIS sections clairement separees et TOUTES
   presentes: "FAITS OBSERVES" (2-3 phrases resumees, pas de liste brute),
   "INTERPRETATION" (ton analyse possible, en precisant que c'est une
   hypothese, pas une certitude), "RECOMMANDATIONS" (exactement 2 actions,
   une phrase courte chacune, moins de 15 mots).
4. Tu ne dois JAMAIS affirmer avec certitude qu'il s'agit d'une attaque
   confirmee si les donnees ne le confirment pas explicitement (severite/statut).
5. Reste concis: 150-200 mots maximum au total pour les TROIS sections.

DONNEES DE L'INCIDENT (faits etablis par le systeme, pas par toi):
- ID incident: {incident['id']}
- IP source: {incident['source_ip']}
- Nombre d'IP destination distinctes: {len(incident['destination_ips'])}
  (exemples: {', '.join(incident['destination_ips'][:3])}{'...' if len(incident['destination_ips']) > 3 else ''})
- Types/signatures observes ({len(incident['attack_types'])} au total): {'; '.join(incident['attack_types'][:4])}{'; ...' if len(incident['attack_types']) > 4 else ''}
- Severite (la plus haute observee): {incident['severity']}
- Score de risque maximum: {incident['max_risk_score']}
- Statut de l'incident: {incident['status']}
- Nombre total d'evenements: {incident['events_count']}
- Premiere activite: {incident['first_seen']}
- Derniere activite: {incident['last_seen']}

EVENEMENTS DE PREUVE (chronologiques):
{events_summary}

Redige maintenant le rapport en francais, en respectant strictement la structure demandee."""

    return prompt


def generate_incident_report(incident):
    """
    Point d'entree principal. Retourne un dict:
    {"success": bool, "report": str|None, "error": str|None}

    Ne leve JAMAIS d'exception - le systeme doit continuer a fonctionner
    meme si Ollama est indisponible (section 47).
    """
    llm_config = _load_llm_config()
    if not llm_config["enabled"]:
        return {"success": False, "report": None, "error": "Generation LLM desactivee dans la configuration"}
    prompt = build_prompt(incident)

    try:
        response = requests.post(
            OLLAMA_URL,
            json={
                "model": llm_config["model"],
                "prompt": prompt,
                "stream": False,
                "options": {
                    # Plafond DUR sur le nombre de tokens generes - le modele
                    # ignore frequemment la consigne textuelle de longueur
                    # (observe empiriquement: 583 tokens generes pour une
                    # consigne de 150-250 mots). Sans ce parametre, la duree
                    # de generation n'est pas bornee de facon fiable.
                    # Plafond releve a 500 (mesure du 12/09/2026: ~5.4 tokens/s
                    # en generation -> +100 tokens ajoute ~18s, marge
                    # confortable sous le timeout de 320s). Motif: a 400
                    # tokens, le rapport se coupait en plein milieu de la
                    # section RECOMMANDATIONS (phrase inachevee) - observe
                    # empiriquement sur incident INC-20260910-9137f030.
                    "num_predict": 500,
                },
            },
            timeout=float(llm_config["timeout_seconds"]),
        )
        response.raise_for_status()
        data = response.json()
        report_text = data.get("response", "").strip()

        if not report_text:
            return {"success": False, "report": None,
                    "error": "Reponse vide recue d'Ollama"}

        return {"success": True, "report": report_text, "error": None}

    except requests.exceptions.ConnectionError:
        return {
            "success": False, "report": None,
            "error": (
                "Ollama indisponible (service non demarre ou modele non "
                f"telecharge - verifier 'ollama list' contient '{llm_config['model']}'). "
                "Le systeme continue de fonctionner normalement sans rapport LLM."
            ),
        }
    except requests.exceptions.Timeout:
        return {
            "success": False, "report": None,
            "error": f"Timeout ({llm_config['timeout_seconds']}s) - generation trop lente sur ce CPU.",
        }
    except requests.exceptions.RequestException as e:
        return {"success": False, "report": None, "error": f"Erreur Ollama: {e}"}
