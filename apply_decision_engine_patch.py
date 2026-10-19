"""
apply_decision_engine_patch.py
Applique une modification ciblee et verifiee a src/detection/decision_engine.py :
ajoute la categorie "attempted denial of service" avec un poids de 0.8
(aligne sur SEVERITY_TEXT_WEIGHTS["major"]), au lieu du poids neutre 0.6
par defaut actuellement applique.

Usage: python3 apply_decision_engine_patch.py
Fait une sauvegarde .bak avant toute modification. Ne modifie rien si le
texte attendu n'est pas trouve EXACTEMENT une fois (securite anti-erreur).
"""

import sys
from pathlib import Path

TARGET = Path("src/detection/decision_engine.py")

OLD_BLOCK = '''LOW_SEVERITY_FALLBACK_CATEGORIES = {
    "generic protocol command decode",
}

DEFAULT_SEVERITY_WEIGHT_UNKNOWN = 0.6  # jamais 0 (Regle 7) mais pas non plus 1.0 par defaut


def compute_suricata_severity_weight(signature_severity_text, category):
    """
    Calcule un poids de gravite [0,1] pour une alerte Suricata, en utilisant
    en priorite le texte metadata.signature_severity, puis un repli par
    categorie pour les alertes moteur interne qui n'ont pas cette metadata.
    """
    if signature_severity_text:
        key = signature_severity_text.strip().lower()
        if key in SEVERITY_TEXT_WEIGHTS:
            return SEVERITY_TEXT_WEIGHTS[key]

    if category:
        key = category.strip().lower()
        if key in LOW_SEVERITY_FALLBACK_CATEGORIES:
            return 0.3

    return DEFAULT_SEVERITY_WEIGHT_UNKNOWN'''

NEW_BLOCK = '''LOW_SEVERITY_FALLBACK_CATEGORIES = {
    "generic protocol command decode",
}

# Categories observees empiriquement (23/09/2026, test reel d'un flood ICMP
# via la regle locale sid:1000003) comme correspondant a des menaces avancees
# confirmees par seuil (pas juste une anomalie protocolaire benigne), quand
# aucun texte signature_severity n'est fourni par la regle. Poids aligne sur
# SEVERITY_TEXT_WEIGHTS["major"] (0.8), pas invente arbitrairement.
# LISTE PARTIELLE - a enrichir au fur et a mesure des alertes reelles
# observees (Phase 26, laboratoire de test).
HIGH_SEVERITY_FALLBACK_CATEGORIES = {
    "attempted denial of service",
}

DEFAULT_SEVERITY_WEIGHT_UNKNOWN = 0.6  # jamais 0 (Regle 7) mais pas non plus 1.0 par defaut


def compute_suricata_severity_weight(signature_severity_text, category):
    """
    Calcule un poids de gravite [0,1] pour une alerte Suricata, en utilisant
    en priorite le texte metadata.signature_severity, puis un repli par
    categorie pour les alertes moteur interne qui n'ont pas cette metadata.
    """
    if signature_severity_text:
        key = signature_severity_text.strip().lower()
        if key in SEVERITY_TEXT_WEIGHTS:
            return SEVERITY_TEXT_WEIGHTS[key]

    if category:
        key = category.strip().lower()
        if key in LOW_SEVERITY_FALLBACK_CATEGORIES:
            return 0.3
        if key in HIGH_SEVERITY_FALLBACK_CATEGORIES:
            return 0.8

    return DEFAULT_SEVERITY_WEIGHT_UNKNOWN'''


def main():
    if not TARGET.exists():
        print(f"ERREUR: {TARGET} introuvable. Lance ce script depuis la racine du projet.")
        sys.exit(1)

    content = TARGET.read_text()
    count = content.count(OLD_BLOCK)

    if count == 0:
        print("ERREUR: le bloc attendu n'a pas ete trouve tel quel dans le fichier.")
        print("Aucune modification effectuee. Le fichier a peut-etre deja ete modifie,")
        print("ou differe de ce qui etait attendu - verifier manuellement avant de reessayer.")
        sys.exit(1)
    if count > 1:
        print(f"ERREUR: le bloc attendu apparait {count} fois (attendu: 1 seule).")
        print("Aucune modification effectuee par securite.")
        sys.exit(1)

    backup_path = TARGET.with_suffix(".py.bak")
    backup_path.write_text(content)
    print(f"Sauvegarde ecrite: {backup_path}")

    new_content = content.replace(OLD_BLOCK, NEW_BLOCK)
    TARGET.write_text(new_content)
    print(f"Modification appliquee avec succes: {TARGET}")


if __name__ == "__main__":
    main()
