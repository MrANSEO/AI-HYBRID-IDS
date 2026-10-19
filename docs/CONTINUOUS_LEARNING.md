# Continuous Learning controle

Le projet n'utilise jamais ses propres predictions comme nouvelles verites.
Le flux attendu est :

```text
trafic -> stockage -> controle qualite -> labellisation humaine
       -> dataset candidat -> entrainement -> evaluation
       -> comparaison -> approbation humaine -> registre -> deploiement
```

`src/evaluation/check_data_drift.py` calcule un PSI et peut recommander un
retraining. Il ne lance aucun entrainement et ne remplace aucun modele.

`src/models/model_registry.py` enregistre manuellement les hashes SHA-256,
la version, le statut et les metriques disponibles :

```bash
venv/bin/python src/models/model_registry.py --version v1.0.0 --status CANDIDATE
```

Une version ne doit passer a `DEPLOYED` qu'apres revue humaine et validation
sur un jeu de test intact.