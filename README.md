# AI-HYBRID-IDS

IDS hybride local combinant Suricata, vote de trois modèles supervisés,
Isolation Forest, corrélation, moteur de décision, incidents SQLite, API
FastAPI et dashboard Streamlit.

## Architecture

```text
Suricata eve.json -> extraction -> RF/XGBoost/LightGBM
																	+ Isolation Forest
																	-> corrélation -> décision -> incidents
																	-> API FastAPI -> dashboard Streamlit
```

Le LLM Ollama ne prend aucune décision de sécurité. Il peut seulement rédiger
un rapport à partir d'un incident déjà établi.
Pour utiliser les rapports LLM, installer Ollama et le modèle `qwen2.5:3b`
comme décrit dans [docs/INSTALLATION.md](./docs/INSTALLATION.md), puis les
générer depuis la page Incidents.

## Pré-requis

- Linux, Python 3.10 ou plus récent
- Suricata installé et configuré
- Les artefacts présents dans `models/`
- Un environnement virtuel dans `venv/`
- Une configuration `.streamlit/secrets.toml` contenant `dashboard_password`

Installation des dépendances :

```bash
venv/bin/pip install -r requirements.txt
```

## Lancement

Depuis la racine du projet :

```bash
./start_ids.sh
```

Le dashboard est disponible sur `http://localhost:8501` et l'API sur
`http://localhost:8000/docs`. Le lanceur utilise son propre emplacement ; il
fonctionne donc même si le projet n'est pas sous `~/AI-HYBRID-IDS`.
Les pages Live Traffic et System Health se mettent a jour automatiquement,
respectivement toutes les 5 et 10 secondes, tant que la page reste ouverte.
Ollama est optionnel et sert uniquement a generer des rapports LLM.

Le moteur de détection peut aussi suivre un fichier précis :

```bash
sudo venv/bin/python src/detection/live_detection.py \
	--eve-json data/interim/replay_output/<replay>/eve.json \
	--from-start --once
```

Chaque flux persiste aussi le temps d'inférence de l'ensemble ML dans
`inference_time_ms`. Les anciens `detections.csv` sont migrés automatiquement
lors de la prochaine écriture.

## Vérifications rapides

```bash
PYTHONPYCACHEPREFIX=/tmp/ai-hybrid-ids-pycache venv/bin/python -m compileall -q app src llm replay
venv/bin/python -c "import sys; sys.path.insert(0, 'app'); import api; print(api.app.title)"
PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -v
```

## Limites connues

- Les coefficients du score de risque sont heuristiques et doivent être
	recalibrés sur un historique d'incidents étiquetés.
- Isolation Forest signale un écart à la distribution d'entraînement ; ce
	n'est pas une preuve de zero-day.
- Le mode live nécessite l'accès privilégié à `/var/log/suricata/eve.json`.
- Le lancement automatique via l'API nécessite une règle `sudoers` dédiée et
	explicite ; elle n'est jamais créée automatiquement.
- Les lignes de `detections.csv` dépassant `retention_days` sont purgées au
	démarrage du moteur ; les fichiers de logs système restent à gérer par
	`logrotate`.
