# Installation

## Prerequis

- Linux et Python 3.10+
- Suricata installe et configure
- Un environnement virtuel `venv/`
- Les artefacts dans `models/`
- Ollama et le modele `qwen2.5:3b` pour generer les rapports d'incident LLM

## Installation

### Dependances Python

```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
mkdir -p app/.streamlit
printf 'dashboard_password = "CHANGER_CE_SECRET"\n' > app/.streamlit/secrets.toml
chmod 600 app/.streamlit/secrets.toml
```

Ne jamais versionner `secrets.toml`.

### Ollama et modele LLM

Ollama tourne comme service local et ne participe pas aux decisions de
detection. Il est utilise pour rediger les rapports depuis la page Incidents.
Installer Ollama avec la commande officielle, puis telecharger le modele
configure dans `config/config.yaml` :

```bash
sudo apt update
sudo apt install -y curl
curl -fsSL https://ollama.com/install.sh | sh
sudo systemctl enable --now ollama
ollama pull qwen2.5:3b
```

Verifier que le modele est present et que l'API locale repond :

```bash
ollama list
curl -fsS http://localhost:11434/api/tags
```

Dans le dashboard, ouvrir **Incidents**, choisir un incident puis cliquer sur
**Generer le rapport LLM**. Le premier rapport peut prendre plusieurs minutes
sur un processeur sans GPU. Si le projet est lance par `start_ids.sh`, Ollama
est gere separement par systemd et demarre automatiquement au demarrage de la
machine. En cas d'erreur, consulter `systemctl status ollama` et
`sudo journalctl -u ollama -n 50 --no-pager`.

## Demarrage

Deux methodes disponibles - **ne jamais les faire tourner en meme temps**
(double lancement du moteur de detection sur le meme fichier eve.json) :

- **Developpement / tests ponctuels** :

  ```bash
  ./start_ids.sh
  ```

  Le script demande les privileges uniquement pour le moteur qui lit EVE JSON.

- **Production** : services systemd (demarrage automatique au boot,
  redemarrage automatique en cas de crash). Voir DEPLOYMENT.md pour la
  procedure complete d'installation et les pieges connus.
