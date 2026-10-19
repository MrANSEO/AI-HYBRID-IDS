"""
traffic_replay.py
AI-HYBRID-IDS - Phase 10 (section 27)

Rejoue un fichier PCAP a travers Suricata en mode offline (-r), sans generer
de trafic reseau reel. Suit le Mode 2 (REPLAY) de la section 25:
PCAP -> Suricata -> EVE JSON -> Feature Engineering -> ML -> Decision Engine

Les logs de replay sont ecrits dans un dossier separe, jamais dans le
eve.json de production (evite tout melange avec le trafic live).

Usage:
    python3 traffic_replay.py --pcap /chemin/vers/fichier.pcap
"""

import argparse
import os
import pwd
import subprocess
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src", "utils"))
from paths_utils import get_project_root


def get_real_home():
    """
    Resout le VRAI home de l'utilisateur, meme quand le script tourne sous sudo
    (os.path.expanduser('~') se resoudrait sinon vers /root, pas vers l'utilisateur reel).
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


SURICATA_CONFIG = "/etc/suricata/suricata.yaml"
REPLAY_OUTPUT_BASE = os.path.join(get_project_root(), "data", "interim", "replay_output")


def run_replay(pcap_path):
    if not os.path.exists(pcap_path):
        print(f"ERREUR: fichier PCAP introuvable -> {pcap_path}", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(SURICATA_CONFIG):
        print(f"ERREUR: config Suricata introuvable -> {SURICATA_CONFIG}", file=sys.stderr)
        sys.exit(1)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    pcap_name = os.path.splitext(os.path.basename(pcap_path))[0]
    output_dir = os.path.join(REPLAY_OUTPUT_BASE, f"{pcap_name}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)

    print(f"PCAP source:     {pcap_path}")
    print(f"Config Suricata: {SURICATA_CONFIG}")
    print(f"Sortie replay:   {output_dir}")
    print("\nLancement de Suricata en mode offline (-r)...")
    print("NOTE: necessite sudo (lecture config Suricata + ecriture logs systeme-like)\n")

    cmd = [
        "suricata",
        "-r", pcap_path,
        "-c", SURICATA_CONFIG,
        "-l", output_dir,
        "-k", "none",  # desactive la verification de checksum (souvent invalide sur PCAP captures/generes)
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    print("--- STDOUT Suricata ---")
    print(result.stdout)
    if result.stderr:
        print("--- STDERR Suricata ---")
        print(result.stderr)

    eve_path = os.path.join(output_dir, "eve.json")
    if os.path.exists(eve_path):
        with open(eve_path) as f:
            lines = f.readlines()
        print(f"\neve.json genere avec succes: {len(lines)} evenements au total")

        event_types = {}
        for line in lines:
            try:
                import json
                evt = json.loads(line)
                et = evt.get("event_type", "unknown")
                event_types[et] = event_types.get(et, 0) + 1
            except json.JSONDecodeError:
                continue
        print("Repartition par type d'evenement:")
        for et, count in sorted(event_types.items(), key=lambda x: -x[1]):
            print(f"  {et:<15} {count}")
    else:
        print("\nATTENTION: aucun eve.json genere - verifier les erreurs ci-dessus")
        sys.exit(1)

    print(f"\nReplay termine. Logs disponibles dans: {output_dir}")

    # Remettre les fichiers a l'utilisateur reel (pas root) pour usage normal ensuite
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            pw = pwd.getpwnam(sudo_user)
            for root_dir, dirs, files in os.walk(output_dir):
                for name in dirs + files:
                    os.chown(os.path.join(root_dir, name), pw.pw_uid, pw.pw_gid)
            os.chown(output_dir, pw.pw_uid, pw.pw_gid)
            print(f"Permissions corrigees pour l'utilisateur: {sudo_user}")
        except (KeyError, PermissionError) as e:
            print(f"ATTENTION: correction des permissions echouee ({e}) - "
                  f"utiliser 'sudo chown -R {sudo_user}:{sudo_user} {output_dir}' manuellement")

    return output_dir


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rejoue un PCAP a travers Suricata (mode offline)")
    parser.add_argument("--pcap", required=True, help="Chemin vers le fichier .pcap a rejouer")
    args = parser.parse_args()
    run_replay(args.pcap)
