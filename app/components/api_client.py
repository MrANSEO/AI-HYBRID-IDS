"""
api_client.py
AI-HYBRID-IDS - Phase 16 (composant partage du dashboard)

Petit client HTTP vers l'API FastAPI (Phase 15). Le dashboard ne touche
JAMAIS directement aux fichiers CSV/SQLite - toujours via l'API, pour
respecter la separation d'architecture (section 33: API independante du
dashboard, mais le dashboard, lui, depend de l'API).
"""

import os
import requests

API_BASE_URL = os.environ.get("IDS_API_URL", "http://localhost:8000")


def api_get(path, params=None):
    """
    Retourne (data, error). error est None si tout s'est bien passe,
    sinon un message lisible a afficher dans le dashboard.
    """
    try:
        resp = requests.get(f"{API_BASE_URL}{path}", params=params, timeout=5)
        resp.raise_for_status()
        return resp.json(), None
    except requests.exceptions.ConnectionError:
        return None, (
            f"Impossible de contacter l'API ({API_BASE_URL}). "
            f"Verifiez qu'uvicorn tourne (voir Phase 15)."
        )
    except requests.exceptions.RequestException as e:
        return None, f"Erreur API: {e}"


def api_post(path, json=None, timeout=5):
    """Envoie une requete POST a l'API et retourne (data, error)."""
    try:
        resp = requests.post(
            f"{API_BASE_URL}{path}",
            json=json,
            timeout=timeout,
        )
        resp.raise_for_status()
        return resp.json(), None
    except requests.exceptions.ConnectionError:
        return None, (
            f"Impossible de contacter l'API ({API_BASE_URL}). "
            "Verifiez qu'uvicorn tourne."
        )
    except requests.exceptions.HTTPError as e:
        try:
            detail = resp.json().get("detail")
        except (ValueError, AttributeError):
            detail = None
        return None, f"Erreur API: {detail or e}"
    except requests.exceptions.RequestException as e:
        return None, f"Erreur API: {e}"
