# Etat de conformite au cahier des charges

## Termine dans le MVP

- Suricata EVE, features reproductibles, trois modeles supervises.
- Isolation Forest, correlation temporelle, Decision Engine et incidents.
- FastAPI, dashboard Streamlit, authentification, rapports Ollama optionnels.
- Replay PCAP, mode live, tests automatises, validation de configuration.
- IOC observables, mappings MITRE prudents, drift non destructif et registry manuel.
- GeoIP (ip-api.com, cache local, filtrage strict des IP privees, carte
  Folium sur la page Network Map) - actif depuis le 22/09/2026.
- Deploiement en services systemd (demarrage et redemarrage automatiques),
  valide par un redemarrage machine complet - voir DEPLOYMENT.md.
- Regle de detection de flood ICMP par seuil, avec ponderation dediee dans
  le Decision Engine (categorie "Attempted Denial of Service") - voir
  SURICATA.md et DECISION_ENGINE.md.

## A valider avec l'environnement reel

- Scenarios offline, replay et live avec resultats documentes.
- Faux positifs/faux negatifs de Suricata et evaluation hybride par scenario.
- Version exacte de Suricata, TShark, interface, HOME_NET et permissions.

## Limites restantes explicites

- Les metriques hybrides exigent des captures etiquetees et ne sont pas inventees.
- Le continuous learning reste manuel par conception (section 50-51) - le
  pipeline complet (collecte -> validation humaine -> reentrainement ->
  comparaison -> approbation -> registry -> deploiement) reste a construire
  au-dela du socle deja en place (model_registry.py).
- La rotation des fichiers stdout doit etre configuree avec logrotate (les
  services systemd centralisent une partie des logs via journalctl, mais
  les fichiers `logs/*_stdout.log` restants n'ont pas encore de politique
  de rotation).
- La detection Suricata depend d'une configuration reseau correcte
  (chargement effectif des regles locales, verification des checksums
  adaptee au pilote reseau utilise) - deux bugs de ce type ont ete
  rencontres et corriges sur cet environnement, voir SURICATA.md et
  TROUBLESHOOTING.md.
- Les listes de categories de repli du Decision Engine (benignes et
  avancees) restent partielles - voir DECISION_ENGINE.md.
