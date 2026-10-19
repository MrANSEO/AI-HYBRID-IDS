# Architecture

Le flux principal est :

```text
Suricata EVE -> Feature Contract -> RF/XGBoost/LightGBM
             -> Isolation Forest -> Correlation Engine
             -> Decision Engine -> Incident Engine -> SQLite/CSV
             -> FastAPI -> Streamlit
```

Le Decision Engine est la seule autorite pour le statut et le risque. Ollama
ne recoit que des faits deja etablis et ne peut pas modifier une decision.

Le dashboard ne lit pas directement les fichiers : il passe par FastAPI.

## Deploiement (Phase 22)

En production, les trois composants (moteur de detection, API, dashboard)
tournent comme services systemd independants, avec redemarrage automatique
en cas de crash et demarrage automatique au boot de la machine :

```text
suricata.service (root)
   -> ai-hybrid-ids-detection.service (root, lit eve.json)
        -> ai-hybrid-ids-api.service (utilisateur normal, sans privileges)
             -> ai-hybrid-ids-dashboard.service (utilisateur normal)
```

Le moteur de detection est le seul composant a tourner avec des privileges
eleves (lecture de `eve.json`, propriete root). L'API et le dashboard
tournent volontairement sans privileges (moindre privilege, section 53).
Voir DEPLOYMENT.md pour la procedure complete et les pieges rencontres.

Une methode alternative (`start_ids.sh`, lancement manuel en une commande)
reste disponible pour le developpement, mais ne doit jamais tourner en
parallele des services systemd (double lancement du moteur de detection sur
le meme fichier eve.json).

## Etat de conformite au cahier des charges

### Termine dans le MVP

- Suricata EVE, features reproductibles, trois modeles supervises.
- Isolation Forest, correlation temporelle, Decision Engine et incidents.
- FastAPI, dashboard Streamlit, authentification, rapports Ollama optionnels.
- Replay PCAP, mode live, tests automatises, validation de configuration.
- IOC observables, mappings MITRE prudents, drift non destructif et registry manuel.
- GeoIP (ip-api.com, cache local, filtrage strict des IP privees, carte
  Folium sur la page Network Map) - actif depuis le 22/09/2026, voir
  PROJECT_STATUS.md pour le detail de l'implementation.
- Deploiement en services systemd, valide par un redemarrage machine complet
  (voir DEPLOYMENT.md).

### A valider avec l'environnement reel

- Scenarios offline, replay et live avec resultats documentes.
- Faux positifs/faux negatifs de Suricata et evaluation hybride par scenario.
- Version exacte de Suricata, TShark, interface, HOME_NET et permissions.

### Limites restantes explicites

- Les metriques hybrides exigent des captures etiquetees et ne sont pas inventees.
- Le continuous learning reste manuel par conception (section 50-51) - le
  pipeline complet (collecte -> validation humaine -> reentrainement ->
  comparaison -> approbation -> registry -> deploiement) reste a construire
  au-dela du socle deja en place (model_registry.py).
- La rotation des fichiers stdout doit etre configuree avec logrotate (les
  services systemd centralisent deja une partie des logs via journalctl,
  mais les fichiers `logs/*_stdout.log` restants ne sont pas encore inclus
  dans une politique de rotation).
- La detection Suricata depend d'une configuration reseau correcte (chargement
  effectif des regles locales, verification des checksums adaptee au pilote
  reseau utilise) - voir SURICATA.md et TROUBLESHOOTING.md pour deux bugs de
  configuration reels rencontres et corriges sur cet environnement.
