#!/bin/bash
# start_ids.sh
# AI-HYBRID-IDS - Lance les 3 composants (detection, API, dashboard) en une
# seule commande, avec arret propre de tout au Ctrl+C.
#
# Usage: ./start_ids.sh
# (necessite d'etre executable: chmod +x start_ids.sh, une seule fois)

set -e

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${IDS_PROJECT_ROOT:-$SCRIPT_DIR}"
VENV_PY="$PROJECT_ROOT/venv/bin/python3"
LOGS_DIR="$PROJECT_ROOT/logs"
PID_FILE="$LOGS_DIR/live_detection.pid"
LOCK_FILE="$LOGS_DIR/ids.lock"

mkdir -p "$LOGS_DIR"

if ! command -v flock >/dev/null 2>&1; then
    echo "ERREUR: la commande flock est requise pour eviter les doubles lancements." >&2
    exit 1
fi

exec 9>"$LOCK_FILE"
if ! flock -n 9; then
    echo "ERREUR: AI-HYBRID-IDS est deja lance dans une autre session." >&2
    exit 1
fi

DETECTION_PID=""
API_PID=""
DASHBOARD_PID=""
CLEANUP_DONE=0

require_file() {
    if [ ! -f "$1" ]; then
        echo "ERREUR: fichier introuvable: $1" >&2
        exit 1
    fi
}

require_process() {
    if ! kill -0 "$1" 2>/dev/null; then
        echo "ERREUR: composant termine au demarrage (PID $1)" >&2
        exit 1
    fi
}

cleanup() {
    if [ "$CLEANUP_DONE" -eq 1 ]; then
        return
    fi
    CLEANUP_DONE=1
    echo ""
    echo "Arret de tous les composants..."
    if [ -n "$DASHBOARD_PID" ]; then
        kill "$DASHBOARD_PID" 2>/dev/null || true
    fi
    if [ -n "$API_PID" ]; then
        kill "$API_PID" 2>/dev/null || true
    fi
    if [ -n "$DETECTION_PID" ]; then
        sudo kill -INT "$DETECTION_PID" 2>/dev/null || true
        sleep 1
        sudo kill -TERM "$DETECTION_PID" 2>/dev/null || true
    fi
    rm -f "$PID_FILE"
    sleep 1
    echo "Arret termine."
}
trap cleanup EXIT INT TERM

echo "=========================================="
echo "AI-HYBRID-IDS - Lancement complet"
echo "=========================================="

require_file "$VENV_PY"
require_file "$PROJECT_ROOT/src/detection/live_detection.py"
require_file "$PROJECT_ROOT/app/api.py"
require_file "$PROJECT_ROOT/app/app.py"

echo ""
echo "[0/3] Authentification sudo (mot de passe demande UNE fois, mis en cache)..."
sudo -v
# IMPORTANT: sudo -v doit etre execute AVANT tout 'sudo ... &' en arriere-plan.
# Sans ca, un sudo lance directement en arriere-plan reste bloque indefiniment
# a attendre un mot de passe qu'il ne peut plus recevoir (pas de terminal
# interactif une fois backgrounded) - bug corrige suite a un test reel.

echo ""
echo "[1/3] Moteur de detection..."
sudo "$VENV_PY" "$PROJECT_ROOT/src/detection/live_detection.py" \
    > "$LOGS_DIR/live_detection_stdout.log" 2>&1 &
DETECTION_PID=$!
echo "$DETECTION_PID" > "$PID_FILE"
echo "      PID: $DETECTION_PID (sortie: logs/live_detection_stdout.log)"
echo "      PID synchronise avec l'API -> logs/live_detection.pid"

for attempt in 1 2 3 4 5; do
    if kill -0 "$DETECTION_PID" 2>/dev/null; then
        break
    fi
    sleep 1
done
require_process "$DETECTION_PID"

echo ""
echo "[2/3] API FastAPI..."
cd "$PROJECT_ROOT/app"
"$PROJECT_ROOT/venv/bin/uvicorn" api:app --port 8000 > "$LOGS_DIR/api_stdout.log" 2>&1 &
API_PID=$!
echo "      PID: $API_PID (sortie: logs/api_stdout.log)"

sleep 2
require_process "$API_PID"

echo ""
echo "[3/3] Dashboard Streamlit..."
STREAMLIT_BROWSER_GATHER_USAGE_STATS=false \
    "$PROJECT_ROOT/venv/bin/streamlit" run app.py > "$LOGS_DIR/dashboard_stdout.log" 2>&1 &
DASHBOARD_PID=$!
echo "      PID: $DASHBOARD_PID (sortie: logs/dashboard_stdout.log)"

sleep 2
require_process "$DASHBOARD_PID"

echo ""
echo "=========================================="
echo "Tout est lance."
echo "Dashboard: http://localhost:8501"
echo "API:       http://localhost:8000"
echo ""
echo "Ctrl+C pour tout arreter proprement."
echo "=========================================="

wait
