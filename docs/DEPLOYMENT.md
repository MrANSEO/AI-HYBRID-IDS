# Deploiement

## Principe general (inchange)

L'API et Streamlit tournent sans root. Seul le moteur qui lit EVE JSON peut
necessiter `sudo` (lecture de `/var/log/suricata/eve.json`, propriete root).

Deux methodes de deploiement coexistent dans ce projet : les services
**systemd** (recommandee, methode de production) et le script
**`start_ids.sh`** (lancement manuel, utile en developpement/debogage).
**Ne jamais faire tourner les deux methodes en meme temps** : ca lancerait
deux moteurs de detection concurrents sur le meme `eve.json`.

## Methode recommandee : services systemd

Trois services, installes dans `/etc/systemd/system/` :

- `ai-hybrid-ids-detection.service` — tourne en `root` (necessaire pour lire
  `eve.json`). Definit `Environment=SUDO_USER=<utilisateur>` : voir "Pieges
  connus" ci-dessous, c'est necessaire pour que les fichiers de logs restent
  lisibles par l'API.
- `ai-hybrid-ids-api.service` — tourne sans privileges, sous l'utilisateur
  reel.
- `ai-hybrid-ids-dashboard.service` — tourne sans privileges, sous
  l'utilisateur reel.

Dependances : `detection` demarre apres `suricata.service` (et en depend),
`api` demarre apres `detection`, `dashboard` demarre apres `api`. Suricata
doit donc etre installe et active comme service systemd au prealable
(c'est deja le cas dans cet environnement : `systemctl is-active suricata`).

### Installation

```bash
sudo cp ai-hybrid-ids-detection.service ai-hybrid-ids-api.service \
        ai-hybrid-ids-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable ai-hybrid-ids-detection.service
sudo systemctl enable ai-hybrid-ids-api.service
sudo systemctl enable ai-hybrid-ids-dashboard.service
```

### Demarrage / arret / statut

```bash
sudo systemctl start   ai-hybrid-ids-detection.service ai-hybrid-ids-api.service ai-hybrid-ids-dashboard.service
sudo systemctl stop    ai-hybrid-ids-detection.service ai-hybrid-ids-api.service ai-hybrid-ids-dashboard.service
sudo systemctl restart ai-hybrid-ids-detection.service   # apres une modif de config.yaml, par exemple
systemctl status ai-hybrid-ids-detection.service ai-hybrid-ids-api.service ai-hybrid-ids-dashboard.service --no-pager
```

Logs en direct :

```bash
sudo journalctl -u ai-hybrid-ids-detection.service -f
```

(les logs applicatifs detailles restent aussi ecrits dans `logs/*_stdout.log`,
comme avec `start_ids.sh`).

### Validation faite sur cet environnement (23-24/09/2026)

Testee par un redemarrage complet de la machine (`sudo reboot`) : les 4
services (Suricata + les 3 notres) redemarrent seuls, dans le bon ordre,
sans aucune intervention manuelle. Fichiers `logs/detections.csv` et
`data/incidents/incidents.db` restent bien possedes par l'utilisateur reel
apres redemarrage. `/api/status` reflete correctement l'etat reel du moteur
de detection.

## Pieges connus (rencontres et corriges pendant le deploiement systemd)

1. **Propriete des fichiers de logs perdue** : `fix_ownership_for_sudo_user()`
   (dans `live_detection.py`) se base sur la variable d'environnement
   `SUDO_USER`, presente uniquement quand un processus est lance via un vrai
   `sudo` interactif. Un service systemd qui tourne directement en `root`
   (sans passer par `sudo`) n'a pas cette variable par defaut : sans
   correction, `logs/detections.csv` et `data/incidents/incidents.db`
   resteraient `root:root`, illisibles par l'API. **Corrige** en ajoutant
   `Environment=SUDO_USER=<utilisateur>` dans `ai-hybrid-ids-detection.service`.
2. **`/api/status` affiche un faux "arrete"** : cet endpoint lit
   `logs/live_detection.pid`, un fichier qu'ecrivait auparavant uniquement
   `POST /api/start` (voir section suivante). Une fois le moteur gere par
   systemd, ce fichier restait perime. **Corrige** avec `ExecStartPost=`/
   `ExecStopPost=` dans le `.service`, qui interroge systemd lui-meme
   (`systemctl show --property=MainPID --value <service>`) pour ecrire le
   vrai PID a chaque demarrage/arret. Attention si ce fichier est retouche
   plus tard : la variable speciale `$MAINPID` n'est **pas** fiable dans
   `ExecStartPost=` (seulement garantie pour `ExecReload=`/`ExecStop=`/
   `ExecStopPost=`) — utiliser `systemctl show` plutot que `$MAINPID` a cet
   endroit.

## POST /api/start et POST /api/stop : obsoletes sous systemd

Ces deux endpoints (et les boutons du dashboard qui les appellent) lancent
`live_detection.py` via `sudo -n`, en s'appuyant sur une regle sudoers
dediee (voir plus bas). **Ne jamais les utiliser une fois les services
systemd actifs** : ca demarrerait un second moteur de detection en
parallele de celui deja gere par systemd, tous deux lisant le meme
`eve.json` en concurrence. Une fois systemd en place, le controle du
moteur de detection passe exclusivement par :

```bash
sudo systemctl start|stop|restart ai-hybrid-ids-detection.service
```

Ces endpoints restent utiles uniquement dans un scenario de developpement
sans systemd (machine de dev, tests ponctuels).

## Regle sudoers (pour POST /api/start uniquement, hors systemd)

Une regle sudoers dediee et limitee au script exact est necessaire pour le
demarrage depuis l'API (`sudo -n`) ; elle ne doit pas etre generee
automatiquement par l'application. Exemple (a adapter au chemin reel de
l'installation, jamais une regle generique) :

```
<utilisateur> ALL=(root) NOPASSWD: /chemin/vers/venv/bin/python3 /chemin/vers/src/detection/live_detection.py
```

## Methode alternative : start_ids.sh (developpement)

Lance les 3 composants en une seule commande, avec arret propre au Ctrl+C
(`flock` empeche un double lancement accidentel). Pratique pour du
developpement ou du debogage ponctuel, mais ne survit pas a un redemarrage
de la machine et ne redemarre pas automatiquement apres un crash —
contrairement aux services systemd, a reserver a la production.

```bash
./start_ids.sh
```

## Avant production (systemd ou start_ids.sh)

1. verifier les permissions de `logs/` et `data/incidents/` ;
2. verifier `/api/health` puis `/api/status` ;
3. verifier que les quatre artefacts de production existent
   (`/api/model_health` -> `artifacts_present: true`) ;
4. demarrer Suricata et confirmer la croissance d'EVE JSON ;
5. ne jamais exposer FastAPI ou Streamlit sur Internet sans reverse proxy,
   TLS et authentification adaptee.
