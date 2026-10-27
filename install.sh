#!/bin/bash
set -e
echo "=== N.A.P.T Installation ==="

# Backend
cd $(dirname $0)
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# .env
if [ ! -f .env ]; then
  echo "OPENROUTER_API_KEY=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" > .env
  echo "SECRET_KEY=napt_secret_key" >> .env
fi

# Qdrant
mkdir -p /tmp/qdrant
if [ ! -f /tmp/qdrant/qdrant ]; then
  wget -q https://github.com/qdrant/qdrant/releases/download/v1.9.0/qdrant-x86_64-unknown-linux-musl.tar.gz -O /tmp/qdrant.tar.gz
  tar -xzf /tmp/qdrant.tar.gz -C /tmp/qdrant
fi
/tmp/qdrant/qdrant --disable-telemetry &
sleep 3

# Index CVEs
python3 index_cves.py

# Frontend
cd ../napt_frontend 2>/dev/null || git clone https://github.com/Nawresbouali/napt-frontend.git ../napt_frontend && cd ../napt_frontend
npm install
npm run build

echo ""
echo "=== Installation terminee ==="
echo "Pour lancer: bash start.sh"
