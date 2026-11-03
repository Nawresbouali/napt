#!/bin/bash
echo "=== N.A.P.T Installation ==="

SCRIPT_DIR=$(cd $(dirname $0) && pwd)

# 1. System dependencies
echo "[1/6] Installing system dependencies..."
sudo apt-get update -qq
sudo apt-get install -y python3 python3-venv python3-pip nmap wget curl git 2>/dev/null || true
if ! command -v node &>/dev/null; then
  curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash - 2>/dev/null
  sudo apt-get install -y nodejs 2>/dev/null || true
fi

# 2. Backend
echo "[2/6] Setting up backend..."
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
rm -rf /tmp/qdrant
mkdir -p /tmp/qdrant
wget -q https://github.com/qdrant/qdrant/releases/download/v1.9.0/qdrant-x86_64-unknown-linux-musl.tar.gz -O /tmp/qdrant.tar.gz
tar -xzf /tmp/qdrant.tar.gz -C /tmp/qdrant
pkill qdrant 2>/dev/null || true
sleep 1
/tmp/qdrant/qdrant --disable-telemetry > /tmp/qdrant.log 2>&1 &
sleep 4

# 5. Index CVEs
echo "[5/6] Indexing CVE database..."
cd "$SCRIPT_DIR"
"$SCRIPT_DIR/venv/bin/python3" index_cves.py

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
echo "  Run: bash $SCRIPT_DIR/start.sh"
echo "=============================="
