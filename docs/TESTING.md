# Testing

## Lancer la suite complete

```bash
source venv/bin/activate
python3 -m pytest tests/ -v
```

(`pytest` est desormais installe comme dependance du projet. L'ancienne
methode `unittest discover` fonctionne toujours - tous les tests sont ecrits
avec `unittest.TestCase`, compatible avec les deux lanceurs - mais `pytest`
donne un rapport plus lisible et est celui utilise pour valider chaque etape
du projet depuis le 22/09/2026.)

```bash
# methode alternative, equivalente
PYTHONDONTWRITEBYTECODE=1 venv/bin/python -m unittest discover -s tests -v
```

Verifications complementaires :

```bash
PYTHONPYCACHEPREFIX=/tmp/ai-hybrid-ids-pycache venv/bin/python -m compileall -q app src llm replay tests
bash -n start_ids.sh
```

## Fichiers de tests (9 fichiers, 79 tests au total)

| Fichier | Tests | Portee |
|---|---|---|
| `test_api.py` | 19 | Endpoints HTTP (TestClient FastAPI), isole des vraies donnees |
| `test_api_config.py` | 3 | `validate_config()` et `enrich_incident_context()` (fonctions isolees) |
| `test_decision_engine.py` | 7 | Formule du risk_score, statuts, ponderation des categories Suricata |
| `test_detection.py` | 6 | Pipeline complet `main()` bout en bout, isole des vraies donnees |
| `test_features.py` | 14 | Contrat de 12 features, cas limites Suricata (duree nulle, tcp absent...) |
| `test_incident_engine.py` | 5 | Correlation temporelle, groupement d'evenements, seuils scan/flood |
| `test_models.py` | 13 | Chargement des vrais artefacts .pkl, pipeline de vote, validation du feature vector |
| `test_report_generator.py` | 2 | Generation de rapport LLM, limites de prompt |
| `test_suricata.py` | 10 | Parsing d'alertes, lecture `eve.json` (modes replay et live) |

## Isolation des donnees (tests d'integration)

`test_models.py`, `test_detection.py` et une partie de `test_api.py` sont
des tests d'**integration** : ils chargent les vrais artefacts `.pkl`
entraines et/ou font tourner le pipeline complet. Deux precautions :

- Si les artefacts modeles (`models/**/*.pkl`) sont absents (ex: clone
  frais du depot sans avoir relance l'entrainement), les classes concernees
  sont automatiquement ignorees (`@unittest.skipUnless`) plutot que
  d'echouer.
- `test_detection.py` et `test_api.py` substituent temporairement les
  chemins internes des modules (`PROJECT_ROOT`, `DETECTIONS_CSV_PATH`,
  `INCIDENTS_DB_PATH`, etc.) vers des fichiers temporaires en `setUp`, et
  les restaurent systematiquement en `tearDown` - **aucun test n'ecrit
  jamais dans les vraies donnees du projet** (`logs/detections.csv`,
  `data/incidents/incidents.db`). Verifie explicitement lors de leur
  ecriture (horodatages de fichiers avant/apres, recherche de valeurs de
  test dans les vraies donnees).

## Hors perimetre des tests automatises (volontairement)

`POST /api/start` et `POST /api/stop` (dans `test_api.py`) ne sont **pas**
testes automatiquement : ces endpoints lancent reellement
`live_detection.py` via `sudo -n`. Les tester en conditions reelles
demarrerait un vrai processus de capture reseau sur la machine executant
les tests - inadapte a une suite automatisee, et desormais obsolete de
toute facon en presence des services systemd (voir DEPLOYMENT.md). Ces
deux endpoints restent couverts manuellement.

## Replay et tests live

Le replay doit etre execute uniquement avec un PCAP autorise et dans un
laboratoire controle. Les tests live necessitent une interface et un Suricata
reels ; leurs resultats doivent etre conserves dans `results/`.
