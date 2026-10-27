#!/bin/bash
echo "=== Demarrage N.A.P.T ==="

# Qdrant
/tmp/qdrant/qdrant --disable-telemetry &
sleep 2

# Backend
cd /home/motez/napt_api
source venv/bin/activate
uvicorn main:app --host 0.0.0.0 --port 8000 &

# Frontend
cd /home/motez/napt_frontend
npm run dev &

echo "Backend: http://localhost:8000"
echo "Frontend: http://localhost:5173"
