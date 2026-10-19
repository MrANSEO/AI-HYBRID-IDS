"""
paths_utils.py
AI-HYBRID-IDS - Utilitaire partage

Resolution correcte des chemins utilisateur, meme lorsque le script tourne
sous sudo (necessaire pour lire eve.json ou la config Suricata).
"""

import os
import pwd


def get_real_home():
    """
    Resout le VRAI home de l'utilisateur, meme sous sudo.
    os.path.expanduser('~') se resoudrait sinon vers /root quand le script
    est execute via 'sudo python3 script.py', ce qui casse tous les chemins
    relatifs au projet (~/AI-HYBRID-IDS/...).
    """
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user:
        try:
            return pwd.getpwnam(sudo_user).pw_dir
        except KeyError:
            pass
    return os.path.expanduser("~")


def get_project_root():
    """Retourne la racine du projet, avec surcharge possible au deploiement."""
    configured_root = os.environ.get("IDS_PROJECT_ROOT")
    if configured_root:
        return os.path.abspath(os.path.expanduser(configured_root))

    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
