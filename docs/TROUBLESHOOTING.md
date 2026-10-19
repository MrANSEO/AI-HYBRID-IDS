# Troubleshooting

- API indisponible : verifier `logs/api_stdout.log` et `http://localhost:8000/api/health`.
- Moteur arrete : verifier `logs/live_detection_stdout.log`, les artefacts et les permissions EVE.
- Base absente : demarrer le moteur une fois pour initialiser SQLite.
- Aucun flow : verifier que Suricata produit des evenements `flow` et que le fichier EVE grandit.
- Rapport impossible : verifier Ollama, le modele configure et `ollama list`.
- Permission `__pycache__` : compiler avec `PYTHONPYCACHEPREFIX=/tmp/ai-hybrid-ids-pycache`.
- PID obsolete : `/api/status` le signale ; relancer le moteur ou supprimer uniquement le PID obsolete.
  Sous systemd, ce fichier est ecrit automatiquement par le service
  (`ExecStartPost`/`ExecStopPost` de `ai-hybrid-ids-detection.service`) - un
  PID incoherent avec `systemctl status` indique un souci avec ce mecanisme,
  pas avec le moteur de detection lui-meme (voir DEPLOYMENT.md).

## Un flow attendu (ping, scan...) n'apparait pas dans logs/detections.csv,
## alors que Wireshark le montre bien

Diagnostic dans l'ordre, sans supposer :

1. **Delai normal, pas un bug** : Suricata n'ecrit un evenement
   `event_type=flow` dans `eve.json` qu'une fois le flow considere termine
   (FIN/RST pour TCP, ou expiration d'un delai d'inactivite pour
   UDP/ICMP). Ce delai (`flow-timeouts` dans `suricata.yaml`) est par
   defaut de 300 secondes (5 minutes) pour ICMP "established". Un simple
   ping peut donc n'apparaitre dans les logs que plusieurs minutes apres
   avoir ete envoye. Verifier : `sudo grep -a "<IP>" /var/log/suricata/eve.json`
   apres avoir attendu ce delai.
2. **`local.rules` jamais charge** : si aucune alerte Suricata
   (`event_type=alert`) n'apparait jamais, meme pour des regles locales
   simples, verifier que `suricata-update` a bien une source active
   (`sudo suricata-update list-sources --enabled`) et que
   `default-rule-path` (`grep default-rule-path /etc/suricata/suricata.yaml`)
   correspond bien au dossier reellement charge. Un `local.rules` place
   dans `/etc/suricata/rules/` sans etre reference dans `rule-files:` de
   `suricata.yaml` est ignore silencieusement, sans aucune erreur au
   demarrage. Verifier avec `sudo suricata -T -c /etc/suricata/suricata.yaml -v`
   (regarder le nombre de `rules successfully loaded`).
3. **`checksum-checks: kernel` peu fiable sur certaines cartes Wi-Fi** :
   meme avec les regles bien chargees, une regle simple (`alert icmp any
   any -> any any (...)`) peut ne jamais se declencher en capture live
   alors qu'elle fonctionne parfaitement en relecture PCAP isolee
   (`suricata -r fichier.pcap -S local.rules -k none`). C'est un signe
   que le pilote reseau ne transmet pas fidelement l'indicateur de
   checksum au noyau pour les paquets SORTANTS, faisant que Suricata les
   traite comme invalides et les exclut de l'inspection. Corriger dans le
   bloc `af-packet` de l'interface concernee (`suricata.yaml`) :
   `checksum-checks: no` (au lieu de `kernel`, la valeur par defaut).
   Redemarrer Suricata (`sudo systemctl restart suricata`) apres ce
   changement.
4. **Methode de test isole recommandee** avant de suspecter le pipeline
   Python (feature extraction, ML, decision engine) : capturer quelques
   paquets isolement (`tcpdump -w test.pcap`), puis rejouer avec
   uniquement les regles locales et sans verification de checksum
   (`suricata -r test.pcap -S /etc/suricata/rules/local.rules -k none`).
   Si le comportement differe entre ce test isole et la capture live,
   le probleme est cote configuration Suricata/reseau, pas cote code
   du projet.

## Un flood ou une attaque volumineuse reste classee "NORMAL" ou "SUSPICIOUS"

- Verifier `has_suricata_alert` dans `logs/detections.csv` pour ce flow. Si
  `False` malgre un volume de trafic evident, Suricata n'a genere aucune
  alerte pour ce trafic - voir la section ci-dessus (regles non chargees ou
  checksum). Une alerte Suricata pese 40% du score de risque (voir
  DECISION_ENGINE.md) ; son absence peut a elle seule maintenir un flow
  a un statut trop bas malgre un score d'anomalie eleve.
- Les 3 modeles ML peuvent unanimement classer un flood comme "Normal
  Traffic" avec une confiance elevee (limite connue, documentee dans
  PROJECT_STATUS.md : CICIDS2017 ne represente pas bien les floods ICMP
  bruts). C'est attendu et rattrape par l'Isolation Forest et le
  Correlation Engine (architecture hybride) - ce n'est pas en soi un bug,
  mais un signal a alimenter dans le futur pipeline de Continuous
  Learning (section 50).
