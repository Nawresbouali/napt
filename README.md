# N.A.P.T — Nawres Autonomous Pentest Tool

Plateforme web d'automatisation des tests d'intrusion assistée par intelligence
artificielle. Un scan enchaîne automatiquement cinq agents : reconnaissance
réseau (Nmap), recherche de vulnérabilités (RAG / Qdrant), évaluation du risque
CVSS par le modèle Gemma, exploitation réelle (Metasploit) et génération du
rapport.

## Prérequis

- Linux (Ubuntu 22.04+ ou WSL2)
- Accès `sudo` (pour installer les outils système)
- Une clé API **OpenRouter** (gratuite sur https://openrouter.ai) pour le
  modèle Gemma
- **Docker** (optionnel) pour déployer des cibles vulnérables de test (Vulhub)

Le script d'installation installe automatiquement : Python, Node.js, Nmap et
Metasploit s'ils sont absents.

## Installation

```bash
git clone <repo-backend> napt_api_test
git clone <repo-frontend> napt_frontend_test
cd napt_api_test
./install.sh
```

Le script met en place l'environnement Python, les dépendances, l'index RAG et
le frontend.

## Configuration

Éditer le fichier `.env` (créé par le script) et renseigner la clé OpenRouter :

```
OPENROUTER_API_KEY=sk-or-v1-....
JWT_SECRET=napt_secret_key
DATABASE_URL=sqlite:///./napt.db
```

## Lancement

```bash
./start.sh
```

- Backend (API) : http://localhost:8000 — documentation sur `/docs`
- Frontend : http://localhost:5173

Compte administrateur par défaut : **nawres / pfe2026**

## Tester l'exploitation (environnement de test)

Déployer une cible vulnérable avec Docker / Vulhub, par exemple Samba
(CVE-2017-7494) :

```bash
cd vulhub/samba/CVE-2017-7494
sudo docker-compose up -d
```

Puis lancer un scan sur `127.0.0.1` depuis l'interface.

> Remarque : l'exploit SambaCry peut déstabiliser le service après plusieurs
> tentatives. Recréer le conteneur (`docker-compose down && up -d`) avant chaque
> démonstration.

## Architecture

- **Backend** : FastAPI (Python), authentification JWT, base SQLite/PostgreSQL
- **IA** : Gemma 4 26B via l'API OpenRouter
- **RAG** : Qdrant (base vectorielle) + fastembed (embeddings 768 dimensions)
- **Exploitation** : Metasploit Framework
- **Frontend** : React (Vite + Tailwind CSS)
