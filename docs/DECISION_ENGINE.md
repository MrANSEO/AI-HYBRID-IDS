# DECISION ENGINE — Justification des coefficients (Phase 13)

## Avertissement méthodologique (à respecter dans le rapport de stage)

Les coefficients ci-dessous constituent une **heuristique initiale raisonnée**,
dérivée explicitement des résultats empiriques mesurés aux Phases 4 à 8.
Ce n'est **pas** une calibration statistique (qui nécessiterait un corpus
d'incidents réels étiquetés — voir section 51, Continuous Learning, pour la
démarche future). Chaque coefficient est justifié individuellement ci-dessous ;
aucun n'est choisi au hasard, mais aucun n'est non plus "prouvé optimal".

## Formule du risk_score

```
risk_score =
    0.40 × suricata_evidence
  + 0.25 × ml_confidence_ajustee
  + 0.10 × model_agreement_score
  + 0.10 × anomaly_component
  + 0.15 × correlation_signal_score
```

Score borné dans [0, 1].

## Justification de chaque terme

### suricata_evidence (poids 0.40 — le plus fort)
Valeur : **pondérée par la sévérité de l'alerte**, pas binaire (révisé le 06/09/2026
suite à un test réel en Phase 13 ayant révélé une escalade abusive).

Logique exacte implémentée (`compute_suricata_severity_weight`, fichier
`decision_engine.py` — cette section doit rester synchronisée avec le code) :

```
1. Si metadata.signature_severity est presente (convention ET Open) :
     "Critical"       -> poids 1.0
     "Major"          -> poids 0.8
     "Minor"          -> poids 0.5
     "Informational"  -> poids 0.3

2. Sinon (alerte moteur interne sans cette metadata, ex: STREAM gid=1,
   ou regle locale sans metadata ET Open), repli par categorie :

   a) Categories connues comme BENIGNES (LOW_SEVERITY_FALLBACK_CATEGORIES,
      poids 0.3) - LISTE PARTIELLE, a enrichir avec l'usage reel :
        "Generic Protocol Command Decode" -> poids 0.3

   b) Categories connues comme AVANCEES/CONFIRMEES (HIGH_SEVERITY_FALLBACK_CATEGORIES,
      poids 0.8, ajoute le 25/09/2026) - LISTE PARTIELLE :
        "Attempted Denial of Service" -> poids 0.8

3. Sinon (categorie inconnue, jamais observee) -> poids 0.6 par defaut
   (prudence : jamais 0 - Regle 7 - mais pas 1.0 non plus sur l'inconnu)

4. Aucune alerte -> poids 0.0
```

**Historique de la découverte (poids par défaut initial)** : lors d'un test live
du 06/09/2026, une alerte `SURICATA STREAM ESTABLISHED packet out of window`
(simple anomalie de décodage protocolaire, probablement du réordonnancement
de paquets WiFi, pas une attaque) a fait passer un flow directement au statut
`ATTACK` (risk=0.5) avec l'ancienne formule binaire (poids fixe 1.0 dès
qu'une alerte existe, quelle que soit sa nature). C'était un défaut de
conception concret : le système ne distinguait pas une alerte
informationnelle bénigne d'une signature de menace critique. Après
correction, ce même scénario donne `SUSPICIOUS` (risk=0.22, poids sévérité
0.3) — vérifié empiriquement.

**Historique de la découverte (HIGH_SEVERITY_FALLBACK_CATEGORIES, 25/09/2026)** :
suite à l'ajout d'une règle locale de détection de flood ICMP
(`sid:1000003`, catégorie `Attempted Denial of Service`, sans metadata
`signature_severity` puisque c'est une règle locale et non une règle ET
Open), un flood réel testé le 23/09/2026 (`ping -f`, ~500 paquets) tombait
sur le poids neutre par défaut (0.6), donnant `risk_score=0.59` (statut
`ATTACK`, seuil 0.45 dépassé mais score sous-évalué par rapport à la
gravité réelle de l'événement). Ajout de `HIGH_SEVERITY_FALLBACK_CATEGORIES`
avec `"attempted denial of service"` à 0.8 (aligné sur le poids "Major" de
`SEVERITY_TEXT_WEIGHTS`, pas une valeur inventée). **Revalidé empiriquement
le 25/09/2026** avec un nouveau flood identique : `risk_score=0.67`
(0.8×0.40 + 1.0×0.10 + 1.0×0.10 + 1.0×0.15), calcul exact confirmé contre
le résultat observé dans `logs/detections.csv`. Toujours `ATTACK` (le
score n'atteint pas le seuil `CRITICAL` de 0.75 à lui seul), mais
désormais correctement pondéré.

**Justification du choix des poids** : on avait déjà noté en Phase 12 que le
champ numérique brut `severity` de Suricata n'est **pas fiable** comme échelle
universelle (ex: une alerte "Informational" documentée peut porter
`severity: 1`, contredisant l'intuition "1 = grave"). On se base donc sur le
champ texte `metadata.signature_severity` (convention ET Open : Informational/
Minor/Major/Critical), plus interprétable. Quand ce champ est absent, on
retombe sur un repli par catégorie — bénigne (0.3) ou avancée/confirmée
(0.8) selon les cas déjà observés empiriquement — puis sur un poids neutre
(0.6) pour tout le reste — ni nul (Règle 7), ni maximal sans preuve.

**Règle 7 toujours respectée** : même avec un poids réduit (0.3 minimum pour
"Informational" ou catégorie bénigne connue), l'override absolu garantit
qu'une alerte, quelle qu'elle soit, ne peut jamais aboutir à un statut
NORMAL — juste que son poids dans le score composite reflète mieux sa gravité
réelle.

⚠️ **Limite explicite** : les deux listes de catégories (bénignes et
avancées) restent **partielles** (une seule catégorie observée dans chacune
à ce stade du projet). Elles devront être enrichies au fur et à mesure des
alertes réelles rencontrées, notamment une fois le laboratoire de test
(section 26) opérationnel avec du vrai trafic offensif varié.

### ml_confidence_ajustee (poids 0.25)
Valeur : confiance moyenne du vote majoritaire (section 7), **pondérée à la
baisse pour les classes dont la Phase 8 a mesuré une fiabilité réelle faible**,
et **nulle si la classe majoritaire prédite est "Normal Traffic"** (verifie
dans le code : `compute_ml_confidence_adjusted` retourne 0.0 pour cette
classe — logique, ce terme mesure la confiance dans une prediction
D'ATTAQUE, pas la confiance generale du vote) :
- `Normal Traffic` : facteur ×0.0 (le terme ne doit pas augmenter le risque
  quand le ML est confiant qu'il n'y a PAS d'attaque)
- `Web Attacks` : facteur ×0.3 (precision mesurée 0.12-0.22 sur les 3 modèles)
- `Bots` : facteur ×0.5 (precision mesurée 0.30-0.46 sur les 3 modèles)
- autres classes d'attaque : facteur ×1.0 (F1 ≥ 0.98 mesuré, Phase 8)

**Justification** : une confiance de 97% affichée par le modèle sur "Web
Attacks" ne doit PAS être traitée comme aussi fiable qu'une confiance de 97%
sur "DDoS" — on a nous-mêmes prouvé (Phase 8, tableau comparatif) que cette
classe est peu fiable en réalité. Ignorer ce fait serait malhonnête.

### model_agreement_score (poids 0.10)
Valeur : 1.0 si 3/3 modèles d'accord, 0.5 si 2/3, 0.0 si 1/3 (désaccord total).
Ce score mesure l'accord inter-modèles en général (peu importe la classe sur
laquelle ils s'accordent) — signal de certitude, pas de dangerosité en soi.
**Justification** : observé concrètement en Phase 11 (test réel du 06/09) sur
des flows ICMPv6 ambigus où l'accord est tombé à 2/3 — le désaccord inter-
modèles est un signal réel d'incertitude, pas juste théorique.

### anomaly_component (poids 0.10 — volontairement faible)
Valeur : 1.0 si Isolation Forest signale une anomalie (contamination=0.05,
seuil déjà calibré en Phase 7), 0.0 sinon.
**Justification** : Phase 7-8 a démontré empiriquement qu'Isolation Forest,
seul, a un taux de détection moyen proche de son taux de faux positifs
(~10% vs ~5%) et n'apporte aucune valeur ajoutée mesurable sur Bots/Web
Attacks/Brute Force. Lui donner un poids fort serait contredire nos propres
résultats documentés. On utilise le flag binaire déjà calibré (pas de score
continu réinterprété arbitrairement).
**Validation empirique supplémentaire (23/09/2026)** : lors du premier test
de flood ICMP massif (avant même la correction des règles Suricata),
l'Isolation Forest a été le signal qui a permis de faire monter un flow de
`NORMAL` implicite à `SUSPICIOUS` malgré un ML unanimement confiant sur
"Normal" et une absence totale d'alerte Suricata — preuve concrète que ce
terme, même à poids faible, joue son rôle de filet de sécurité de
l'architecture hybride.

### correlation_signal_score (poids 0.15)
Valeur : 1.0 si un signal fort du Correlation Engine (Phase 12) est actif
(`REPEATED_ML_ATTACK_PREDICTION`, `POSSIBLE_SCAN`, ou `SURICATA_ML_CONVERGENCE`),
0.0 sinon.
**Justification** : plusieurs événements cohérents dans une fenêtre de 60s
sont plus fiables qu'un flow isolé (section 28) — le poids est significatif
mais reste inférieur à celui de Suricata (fait déterministe) et du ML ajusté.

## Seuils de statut

```
risk_score >= 0.75           -> CRITICAL
risk_score >= 0.45           -> ATTACK
risk_score >= 0.20           -> SUSPICIOUS
risk_score <  0.20           -> NORMAL
```

## Règles absolues (overrides, appliquées après le calcul du score)

1. **Une alerte Suricata ne peut jamais aboutir à un statut NORMAL** (Règle 7,
   section 9) : dès qu'une alerte existe (quel que soit son poids de sévérité
   calculé, même 0.3), si le score composite donne NORMAL, le statut est
   forcé à SUSPICIOUS minimum.
2. **UNKNOWN** : si l'accord inter-modèles est 1/3 (désaccord total) ET
   qu'aucune alerte Suricata ni signal de corrélation fort n'est présent, le
   statut devient UNKNOWN plutôt qu'un score peu fiable — conforme à la
   section 10 ("UNKNOWN sera utilisé lorsqu'il n'y a pas suffisamment de
   confiance pour prendre une décision fiable").

## Limites explicites (à mentionner section 64 du rapport)

- Coefficients non calibrés statistiquement (corpus d'incidents réels
  insuffisant à ce stade du projet).
- Les facteurs de pondération des classes peu fiables (Web Attacks ×0.3,
  Bots ×0.5, Normal Traffic ×0.0) sont des estimations grossières basées sur
  l'écart de precision observé, pas une fonction continue calibrée.
- Les listes de catégories de repli (bénignes et avancées) restent partielles
  (une seule entrée dans chacune à ce stade) — voir la section
  `suricata_evidence` ci-dessus.
- Cette heuristique devra être révisée après la mise en place du Continuous
  Learning contrôlé (section 50-51) une fois un historique d'incidents réels
  disponible.
