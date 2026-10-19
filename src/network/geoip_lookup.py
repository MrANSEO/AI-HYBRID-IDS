"""
geoip_lookup.py
AI-HYBRID-IDS - Phase 18 (section 32)

Resout des IP publiques en localisation approximative (pays/ville/lat/lon)
via l'API gratuite ip-api.com (endpoint batch), avec cache local et
filtrage strict des IP privees/reservees (jamais envoyees a l'API externe).

Ne doit JAMAIS lever d'exception non geree: en cas d'echec reseau, les IP
concernees sont simplement marquees "indisponibles" (meme philosophie que
la gestion d'Ollama dans le reste du projet - une panne de ce module ne
doit jamais faire planter le dashboard ou l'API).

Usage en module:
    from geoip_lookup import lookup_ips
    resultats = lookup_ips(["8.8.8.8", "192.168.1.10"])

Usage en CLI (test manuel):
    python3 geoip_lookup.py 8.8.8.8 1.1.1.1 192.168.1.10
"""

import os
import sys
import json
import time
import ipaddress
from datetime import datetime, timezone

import requests

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_SCRIPT_DIR, "..", "utils"))
from paths_utils import get_project_root  # noqa: E402

CACHE_PATH = os.path.join(get_project_root(), "data", "geoip_cache.json")
CACHE_TTL_DAYS = 30

BATCH_URL = "http://ip-api.com/batch"
BATCH_FIELDS = "status,message,country,city,lat,lon,isp,query"
BATCH_CHUNK_SIZE = 100  # limite de l'API ip-api.com par requete batch
REQUEST_TIMEOUT_SECONDS = 5
DELAY_BETWEEN_CHUNKS_SECONDS = 1.5  # marge de securite si plusieurs chunks


def is_public_ip(ip_str):
    """
    Renvoie True uniquement si l'IP est publique et geolocalisable.
    Exclut: prive, loopback, link-local, multicast, reserve, non-specifie.
    Renvoie False (sans exception) si la chaine n'est pas une IP valide.
    """
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _load_cache():
    if not os.path.exists(CACHE_PATH):
        return {}
    try:
        with open(CACHE_PATH) as cache_file:
            return json.load(cache_file)
    except (OSError, json.JSONDecodeError):
        # Cache corrompu: on repart d'un cache vide plutot que de planter.
        return {}


def _save_cache(cache):
    os.makedirs(os.path.dirname(CACHE_PATH), exist_ok=True)
    try:
        with open(CACHE_PATH, "w") as cache_file:
            json.dump(cache, cache_file, indent=2, ensure_ascii=False)
    except OSError:
        pass  # ecriture cache non critique: on continue sans planter


def _is_cache_entry_fresh(entry):
    cached_at = entry.get("cached_at")
    if not cached_at:
        return False
    try:
        cached_time = datetime.fromisoformat(cached_at)
    except ValueError:
        return False
    age_days = (datetime.now(timezone.utc) - cached_time).total_seconds() / 86400
    return age_days < CACHE_TTL_DAYS


def _query_batch(ip_chunk):
    """
    Interroge ip-api.com/batch pour un chunk d'IP (max 100).
    Renvoie un dict ip -> resultat brut de l'API, ou {} si l'appel echoue
    entierement (jamais d'exception propagee).
    """
    payload = [{"query": ip, "fields": BATCH_FIELDS} for ip in ip_chunk]
    try:
        response = requests.post(BATCH_URL, json=payload, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()
        results = response.json()
    except (requests.exceptions.RequestException, ValueError):
        return {}

    return {item.get("query"): item for item in results if item.get("query")}


def lookup_ips(ip_list):
    """
    Resout une liste d'IP en localisations approximatives.

    Renvoie un dict {ip: record} pour CHAQUE ip de ip_list (dedupliquee),
    avec record toujours de la forme:
        {
            "public": bool,
            "status": "cached" | "resolved" | "unavailable" | "private",
            "country": str | None,
            "city": str | None,
            "lat": float | None,
            "lon": float | None,
            "isp": str | None,
        }
    """
    unique_ips = list(dict.fromkeys(ip_list))  # deduplique en gardant l'ordre
    results = {}
    cache = _load_cache()
    cache_dirty = False

    to_query = []
    for ip in unique_ips:
        if not is_public_ip(ip):
            results[ip] = {
                "public": False, "status": "private",
                "country": None, "city": None, "lat": None, "lon": None, "isp": None,
            }
            continue

        cached_entry = cache.get(ip)
        if cached_entry and _is_cache_entry_fresh(cached_entry):
            results[ip] = {
                "public": True, "status": "cached",
                "country": cached_entry.get("country"),
                "city": cached_entry.get("city"),
                "lat": cached_entry.get("lat"),
                "lon": cached_entry.get("lon"),
                "isp": cached_entry.get("isp"),
            }
        else:
            to_query.append(ip)

    for i in range(0, len(to_query), BATCH_CHUNK_SIZE):
        chunk = to_query[i:i + BATCH_CHUNK_SIZE]
        api_results = _query_batch(chunk)

        for ip in chunk:
            api_record = api_results.get(ip)
            if api_record and api_record.get("status") == "success":
                record = {
                    "public": True, "status": "resolved",
                    "country": api_record.get("country"),
                    "city": api_record.get("city"),
                    "lat": api_record.get("lat"),
                    "lon": api_record.get("lon"),
                    "isp": api_record.get("isp"),
                }
                cache[ip] = {**record, "cached_at": datetime.now(timezone.utc).isoformat()}
                cache_dirty = True
            else:
                record = {
                    "public": True, "status": "unavailable",
                    "country": None, "city": None, "lat": None, "lon": None, "isp": None,
                }
            results[ip] = record

        if i + BATCH_CHUNK_SIZE < len(to_query):
            time.sleep(DELAY_BETWEEN_CHUNKS_SECONDS)

    if cache_dirty:
        _save_cache(cache)

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 geoip_lookup.py <ip1> [ip2] [ip3] ...")
        sys.exit(1)

    output = lookup_ips(sys.argv[1:])
    print(json.dumps(output, indent=2, ensure_ascii=False))
