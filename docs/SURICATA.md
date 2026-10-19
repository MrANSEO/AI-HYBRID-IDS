# Suricata

Le moteur live lit les evenements `flow` et `alert` du fichier EVE JSON.
Le chemin par defaut est `/var/log/suricata/eve.json`; un autre fichier peut
etre fourni avec `--eve-json`.

Pour un replay :

```bash
sudo venv/bin/python replay/traffic_replay.py --pcap data/raw/test_normal.pcap
sudo venv/bin/python src/detection/live_detection.py \
  --eve-json data/interim/replay_output/<replay>/eve.json --from-start --once
```

Les signatures Suricata ne sont jamais ignorees par le Decision Engine, meme
si le vote ML predit `Normal Traffic` (Regle 7) - voir DECISION_ENGINE.md
pour le detail du poids applique a chaque alerte selon sa gravite.

## Regles locales (`/etc/suricata/rules/local.rules`)

Trois regles locales, ajoutees et validees empiriquement sur cet
environnement (22-25/09/2026) :

```
alert icmp any any -> any any (msg:"[IDS HYBRIDE] Ping ICMP Detecte"; sid:1000001; rev:1;)
alert tcp any any -> any any (flags:S; msg:"[IDS HYBRIDE] Tentative de connexion SYN (Scan potentiel)"; sid:1000002; rev:1;)
alert icmp any any -> any any (msg:"[IDS HYBRIDE] Flood ICMP Detecte"; itype:8; threshold: type both, track by_src, count 100, seconds 10; classtype:attempted-dos; sid:1000003; rev:1;)
```

- `sid:1000001` / `sid:1000002` : detection simple, sans seuil, a but de
  demonstration/validation de la chaine complete.
- `sid:1000003` : detection de flood ICMP par seuil (`threshold`), plus de
  100 paquets ICMP type 8 (echo request) en 10 secondes depuis la meme
  source. Categorie `Attempted Denial of Service`, ponderee a 0.8 dans le
  Decision Engine (voir DECISION_ENGINE.md, `HIGH_SEVERITY_FALLBACK_CATEGORIES`).

Aucune de ces regles ne porte de metadata `signature_severity` (convention
ET Open) puisque ce sont des regles locales, pas des regles telechargees -
le Decision Engine retombe donc sur un repli par categorie (voir
DECISION_ENGINE.md).

## Deux bugs de configuration reels, decouverts et corriges (23/09/2026)

Ces deux bugs ne viennent pas du code Python du projet - ils sont
entierement dans la configuration Suricata/systeme. Details complets et
demarche de diagnostic dans TROUBLESHOOTING.md. Resume :

1. **Regles locales jamais chargees** : `suricata-update` sans source
   activee, et `local.rules` place dans un dossier different de
   `default-rule-path`. Corrige en ajoutant le chemin absolu de
   `local.rules` dans `rule-files:` de `suricata.yaml`. A verifier sur
   toute nouvelle installation :

   ```bash
   sudo suricata -T -c /etc/suricata/suricata.yaml -v
   # regarder "N rules successfully loaded" - doit inclure les regles locales
   ```

2. **`checksum-checks: kernel` peu fiable sur l'interface Wi-Fi utilisee** :
   les paquets sortants pouvaient etre exclus de l'inspection des regles en
   capture live (fonctionnaient pourtant parfaitement en relecture PCAP
   isolee). Corrige avec `checksum-checks: no` dans le bloc `af-packet` de
   l'interface concernee. A verifier si des regles simples (comme
   `sid:1000001`) ne se declenchent jamais malgre un trafic reel confirme.

## Latence normale des evenements `flow` (pas un bug)

Suricata n'ecrit un evenement `event_type=flow` qu'une fois le flow
considere termine (FIN/RST pour TCP, expiration d'un delai d'inactivite
pour UDP/ICMP - `flow-timeouts` dans `suricata.yaml`, par defaut 300
secondes pour ICMP "established"). Un flow ICMP simple peut donc
n'apparaitre dans `eve.json`, et donc dans `logs/detections.csv`, que
plusieurs minutes apres avoir ete emis - meme si Wireshark le montre
instantanement (capture brute, pas d'attente de fin de flow). Ce n'est pas
un defaut du pipeline de detection, c'est le comportement normal de
Suricata. Les evenements `alert` (declenches par une regle), eux, sont
ecrits immediatement - c'est pourquoi les regles locales ci-dessus sont
utiles pour une demonstration ou un test reactif.
