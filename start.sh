#!/bin/bash
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
source venv/bin/activate

echo "=== N.A.P.T ==="
echo "Backend  : http://localhost:8000"
echo "Frontend : http://localhost:5173"

uvicorn main:app --host 0.0.0.0 --port 8000 > /tmp/napt_backend.log 2>&1 &
BACK_PID=$!
sleep 3

FRONT=""
for d in "../napt_frontend_test" "../napt-frontend" "../napt_frontend"; do
  if [ -d "$d" ]; then FRONT="$d"; break; fi
done

if [ -n "$FRONT" ]; then
  trap "kill $BACK_PID 2>/dev/null" EXIT
  ( cd "$FRONT" && npm run dev )
else
  echo "Frontend non trouve. Backend seul."
  wait $BACK_PID
fi
