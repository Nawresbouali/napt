#!/bin/bash
# =========================================================
#  N.A.P.T — Démarrage de l'environnement de test (lab)
#  À lancer après chaque redémarrage de WSL : ./lab.sh
# =========================================================

echo "=== N.A.P.T — Démarrage du lab ==="

# --- 0. Vérification de l'horloge (bug récurrent de WSL) ---
echo ""
echo "[0] Date système : $(date)"
echo "    ⚠️  Si la date est FAUSSE (ex. coincée dans le passé), corrige-la :"
echo "        sudo date -s \"2026-11-11 12:00:00\""
echo "    (une mauvaise heure casse le RAG / l'IA)"

# --- 1. Démon Docker ---
echo ""
if sudo docker info >/dev/null 2>&1; then
  echo "[1] Docker déjà lancé ✓"
else
  echo "[1] Démarrage de Docker..."
  sudo dockerd > /tmp/dockerd.log 2>&1 &
  sleep 6
fi

# --- 2. Cible Metasploitable 2 (vsftpd, UnrealIRCd, Samba 3.0.20...) ---
echo ""
echo "[2] Démarrage de Metasploitable 2..."
if sudo docker ps -a --format '{{.Names}}' | grep -q '^metasploitable2$'; then
  sudo docker start metasploitable2 >/dev/null
else
  sudo docker run -d --name metasploitable2 tleemcjr/metasploitable2 \
    sh -c "/bin/services.sh; tail -f /dev/null" >/dev/null
fi
sleep 6
MIP=$(sudo docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' metasploitable2 2>/dev/null)

# --- 3. Cibles Vulhub optionnelles (si présentes) ---
echo ""
echo "[3] Cibles Vulhub (optionnel)..."
start_vulhub () {
  local dir="$1" nom="$2"
  if [ -d "$dir" ]; then
    ( cd "$dir" && sudo docker-compose up -d >/dev/null 2>&1 ) && echo "    - $nom démarré (localhost)"
  fi
}
start_vulhub "$HOME/vulhub/samba/CVE-2017-7494" "Samba CVE-2017-7494"
start_vulhub "$HOME/vulhub/redis/CVE-2022-0543" "Redis CVE-2022-0543"

# --- Récap ---
echo ""
echo "=========================================="
echo "  ✅ Lab prêt !"
echo "  Metasploitable 2  →  IP : ${MIP:-non trouvée}"
echo "  Vulhub (si démarré) → 127.0.0.1"
echo "=========================================="
echo ""
echo "Vérification rapide des services Metasploitable 2 :"
if [ -n "$MIP" ]; then
  nmap -Pn -p 21,139,445,6667 "$MIP" 2>/dev/null | grep -E "^[0-9]" || echo "  (services en cours de démarrage, réessaie dans 10s)"
fi
echo ""
echo "→ Lance maintenant un scan N.A.P.T sur l'IP ci-dessus."
