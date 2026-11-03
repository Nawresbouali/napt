#!/bin/bash
set +e
echo "=== N.A.P.T Installation ==="

# 1. System dependencies
echo "[1/6] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y python3 python3-venv python3-pip nmap wget curl git

# Node.js via nodesource (evite conflit npm/nodejs)
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
  sudo apt-get install -y nodejs
fi

# 2. Backend
echo "[2/6] Setting up backend..."
SCRIPT_DIR=$(cd $(dirname $0) && pwd)
cd "$SCRIPT_DIR"
python3 -m venv venv
source venv/bin/activate
pip install -q -r requirements.txt

# 3. .env
echo "[3/6] Configuring environment..."
if [ ! -f .env ]; then
  echo "OPENROUTER_API_KEY=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" > .env
  echo "SECRET_KEY=napt_secret_key" >> .env
fi

# 4. Qdrant
echo "[4/6] Installing Qdrant..."
mkdir -p /tmp/qdrant 2>/dev/null; true
if [ ! -f /tmp/qdrant/qdrant ]; then
  wget -q https://github.com/qdrant/qdrant/releases/download/v1.9.0/qdrant-x86_64-unknown-linux-musl.tar.gz -O /tmp/qdrant.tar.gz
  tar -xzf /tmp/qdrant.tar.gz -C /tmp/qdrant
fi
pkill qdrant 2>/dev/null || true
/tmp/qdrant/qdrant --disable-telemetry &
sleep 3

# 5. Index CVEs
echo "[5/6] Indexing CVE database..."
python3 index_cves.py

# 6. Frontend
echo "[6/6] Setting up frontend..."
if [ ! -d "$SCRIPT_DIR/../napt_frontend" ]; then
  git clone https://github.com/Nawresbouali/napt-frontend.git "$SCRIPT_DIR/../napt_frontend"
fi
cd "$SCRIPT_DIR/../napt_frontend"
npm install --silent
npm run build

echo ""
echo "=============================="
echo "  Installation complete!"
echo "  Run: bash start.sh"
echo "=============================="
