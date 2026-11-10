#!/bin/bash
set -e
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "=== Installation automatique de N.A.P.T ==="

echo "[0/5] Outils systeme (nmap, curl, python3)..."
sudo apt-get update -qq
sudo apt-get install -y -qq python3 python3-venv python3-pip nmap curl >/dev/null

if ! command -v msfconsole >/dev/null 2>&1; then
  echo "      Installation de Metasploit (quelques minutes)..."
  curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall
  chmod 755 /tmp/msfinstall
  sudo /tmp/msfinstall >/dev/null
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "      Installation de Node.js..."
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - >/dev/null
  sudo apt-get install -y -qq nodejs >/dev/null
fi

echo "[1/5] Environnement Python + dependances..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip -q
pip install -r requirements.txt -q

if [ ! -f .env ]; then
  echo "[2/5] Creation du fichier .env..."
  cat > .env << 'ENVEOF'
OPENROUTER_API_KEY=METS_TA_CLE_OPENROUTER_ICI
JWT_SECRET=napt_secret_key
DATABASE_URL=sqlite:///./napt.db
ENVEOF
  echo "      -> IMPORTANT : edite .env et mets ta cle OpenRouter."
else
  echo "[2/5] .env deja present, conserve."
fi

echo "[3/5] Construction de l'index RAG (telecharge le modele, patienter)..."
( cd rag && python indexer.py )

echo "[4/5] Dependances frontend..."
for d in "../napt_frontend_test" "../napt-frontend" "../napt_frontend"; do
  if [ -d "$d" ]; then ( cd "$d" && npm install ); break; fi
done

echo ""
echo "[5/5] Installation terminee !"
echo "      1) Edite .env et mets ta cle OpenRouter"
echo "      2) Lance la plateforme : ./start.sh"
