# Guide d'installation — N.A.P.T

**Nawres Autonomous Pentest Tool** — plateforme de test d'intrusion automatisée.

Ce guide permet d'installer et de lancer N.A.P.T sur une machine vierge, en quelques minutes.

---

## 1. Prérequis

| Élément | Détail |
|---|---|
| Système | Linux ou **WSL2 (Ubuntu)** sous Windows |
| Accès | Compte avec droits **sudo** |
| Réseau | **Connexion internet** (IA Gemma + téléchargement du modèle RAG) |
| Clé API | Une **clé OpenRouter** (pour l'IA Gemma) |

> ℹ️ **Aucun serveur de base de données à installer.** N.A.P.T utilise SQLite (fichier) et Qdrant en mode embarqué. Pas besoin de PostgreSQL ni de Docker pour faire tourner la plateforme.

---

## 2. Installation (automatique)

Cloner les **deux dépôts côte à côte** (backend + frontend), puis lancer le script d'installation :

```bash
# Dossier de travail
mkdir napt && cd napt

# Cloner les 2 dépôts
git clone https://github.com/Nawresbouali/napt.git
git clone https://github.com/Nawresbouali/napt-frontend.git

# Lancer l'installation automatique
cd napt
chmod +x install.sh start.sh
./install.sh
```

Le script `install.sh` installe **tout seul** :
- les outils système : **Nmap, Metasploit, Node.js**
- l'environnement **Python** (venv + dépendances)
- l'**index RAG** (base de CVE vectorisée)
- les dépendances du **frontend**

> ⏱️ Durée : ~5 à 15 min selon la machine (Metasploit et le modèle RAG sont les plus longs).

---

## 3. Configuration (1 seul réglage)

À la fin de l'installation, un fichier `.env` est créé. Il faut y mettre **ta clé OpenRouter** :

```bash
nano .env
```

Remplacer la ligne :

```
OPENROUTER_API_KEY=METS_TA_CLE_OPENROUTER_ICI
```

par ta vraie clé, puis enregistrer (`Ctrl+O`, `Entrée`, `Ctrl+X`).

---

## 4. Démarrage

```bash
cd napt
./start.sh
```

La plateforme démarre sur :
- **Backend** : http://localhost:8000
- **Frontend** : http://localhost:5173

Ouvrir **http://localhost:5173** dans le navigateur et se connecter avec son compte administrateur.

> Pour arrêter : `Ctrl + C` dans le terminal.

---

## 5. Environnement de test (pour la démo d'exploitation)

Pour lancer un scan qui **exploite réellement** une cible, il faut une **machine vulnérable**.
On utilise les conteneurs **Vulhub** (Docker). Exemple avec Samba :

```bash
# Démarrer Docker (si WSL)
sudo dockerd > /tmp/dockerd.log 2>&1 &

# Lancer une cible vulnérable (exemple : Samba CVE-2017-7494)
cd ~/vulhub/samba/CVE-2017-7494 && sudo docker-compose up -d
```

Puis, dans N.A.P.T → **Scans** → lancer un scan sur l'IP de la cible (ex. `127.0.0.1`).

> ℹ️ Docker sert **uniquement aux cibles de test**, pas à N.A.P.T.

---

## 6. Dépannage

| Problème | Cause | Solution |
|---|---|---|
| `Release file ... is not valid yet` à l'install | Horloge WSL déréglée (en retard) | `sudo date -s "AAAA-MM-JJ HH:MM:SS"` puis relancer |
| `address already in use` (port 8000) | Un backend tourne déjà | `pkill -9 -f uvicorn` puis relancer |
| L'IA ne répond pas | Clé OpenRouter manquante/invalide, ou horloge fausse | Vérifier `.env` et l'heure (`date`) |
| Frontend introuvable au démarrage | Le dépôt `napt-frontend` n'est pas à côté de `napt` | Cloner les 2 dépôts dans le même dossier parent |

---

## 7. Architecture (rappel)

| Composant | Technologie |
|---|---|
| Backend | FastAPI (Python) — port 8000 |
| Frontend | React + Vite + Tailwind — port 5173 |
| Base de données | SQLite |
| Recherche vulnérabilités (RAG) | Qdrant embarqué + fastembed (768-dim) |
| IA / analyse | Gemma via OpenRouter |
| Exploitation | Metasploit |
| Reconnaissance | Nmap (sortie XML) |

**Pipeline en 5 étapes :** Reconnaissance → Recherche CVE → Analyse (CVSS) → Exploitation → Rapport.
