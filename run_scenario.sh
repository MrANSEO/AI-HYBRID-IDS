#!/bin/bash
# run_scenario.sh
# AI-HYBRID-IDS - Campagne d'evaluation etiquetee (section 22 du cahier des charges)
#
# Execute UNE commande (attaque de labo ou periode de trafic normal) et enregistre
# dans results/evaluation/ground_truth.csv l'heure exacte de debut et de fin, avec
# le decalage horaire explicite (les fichiers du projet ont deja melange +0100 et
# +0200, on ne veut plus d'ambiguite).
#
# Usage:
#   ./run_scenario.sh <id> <type> <ip_victime|none> -- <commande...>
#
# Exemples:
#   ./run_scenario.sh baseline_1 benign none -- sleep 1800
#   ./run_scenario.sh scan_1 port_scan 192.168.100.38 -- sudo nmap -sS -p 1-1000 192.168.100.38
#
# Securite (Regle 9): la victime doit etre une IP privee ET tu dois confirmer
# qu'elle t'appartient. Aucun test offensif hors laboratoire autorise.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="$SCRIPT_DIR/results/evaluation"
OUT_FILE="$OUT_DIR/ground_truth.csv"
IFACE="${IDS_IFACE:-wlan0}"

if [ "$#" -lt 5 ] || [ "$4" != "--" ]; then
    echo "Usage: $0 <id> <type> <ip_victime|none> -- <commande...>" >&2
    exit 2
fi

SCENARIO_ID="$1"
SCENARIO_TYPE="$2"
VICTIM_IP="$3"
shift 4

if [ "$VICTIM_IP" != "none" ]; then
    if ! [[ "$VICTIM_IP" =~ ^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.) ]]; then
        echo "REFUS: $VICTIM_IP n'est pas une IP privee. Tests offensifs limites au labo." >&2
        exit 3
    fi
    read -r -p "Confirmer que $VICTIM_IP est une machine de LABORATOIRE qui t'appartient [oui/N] : " REPLY
    if [ "$REPLY" != "oui" ]; then
        echo "Annule."
        exit 4
    fi
fi

ATTACKER_IP="${ATTACKER_IP:-$(ip -4 -o addr show dev "$IFACE" | awk '{print $4}' | cut -d/ -f1 | head -1)}"
if [ -z "$ATTACKER_IP" ]; then
    echo "ERREUR: IP de l'interface $IFACE introuvable (definir ATTACKER_IP=...)." >&2
    exit 5
fi

mkdir -p "$OUT_DIR"
if [ ! -f "$OUT_FILE" ]; then
    echo "id,type,attacker_ip,victim_ip,start,end,exit_code,command" > "$OUT_FILE"
fi

CMD_STR="$*"
START="$(date -Iseconds)"
echo "[$START] Debut $SCENARIO_ID ($SCENARIO_TYPE) attaquant=$ATTACKER_IP victime=$VICTIM_IP"

"$@"
EXIT_CODE=$?

END="$(date -Iseconds)"
SAFE_CMD="${CMD_STR//\"/\"\"}"
printf '%s,%s,%s,%s,%s,%s,%s,"%s"\n' \
    "$SCENARIO_ID" "$SCENARIO_TYPE" "$ATTACKER_IP" "$VICTIM_IP" "$START" "$END" "$EXIT_CODE" "$SAFE_CMD" \
    >> "$OUT_FILE"

echo "[$END] Fin $SCENARIO_ID (code de sortie $EXIT_CODE) -> $OUT_FILE"
