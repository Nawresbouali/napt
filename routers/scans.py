import uuid, asyncio, json, os, requests as req
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from database import get_db
from models import Scan, AuditLog, Notification, RemediationLog, ChatMessage
from schemas import LaunchScanRequest, ScanOut, UpdateRemediation, ChatRequest
from auth import get_current_user, decode_token

router = APIRouter(prefix="/api/scans", tags=["scans"])

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
LLM_MODEL      = "google/gemma-4-26b-a4b-it:free"
try:
    from dotenv import dotenv_values as _dv
    _env = _dv("/home/motez/napt_api/.env")
    OPENROUTER_KEY = _env.get("OPENROUTER_API_KEY", "").strip()
except Exception:
    OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()

def log(db, event, actor, detail=None, success=True):
    db.add(AuditLog(event_type=event, actor_username=actor, detail=detail, success=success))
    db.commit()

_ws_connections: dict = {}
_scan_events: dict = {}

def emit_event(scan_id: str, event_type: str, agent: str = None, data: dict = None, output: str = None):
    event = {
        "type": event_type,
        "agent": agent,
        "data": data or {},
        "output": output,
        "ts": datetime.utcnow().isoformat()
    }
    if scan_id not in _scan_events:
        _scan_events[scan_id] = []
    _scan_events[scan_id].append(event)

def llm_call(system: str, user_msg: str) -> str:
    try:
        resp = req.post(
            OPENROUTER_URL,
            headers={
                "Authorization": f"Bearer {OPENROUTER_KEY}",
                "Content-Type": "application/json",
                "HTTP-Referer": "http://localhost:5173",
                "X-Title": "N.A.P.T"
            },
            json={
                "model": LLM_MODEL,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user_msg}
                ]
            },
            timeout=60, verify=False
        )
        result = resp.json()
        if "error" in result:
            raise Exception(result["error"].get("message", "OpenRouter error"))
        return result["choices"][0]["message"]["content"]
    except Exception as e:
        return f"[LLM indisponible: {e}]"

@router.get("", response_model=list[ScanOut])
def list_scans(db: Session = Depends(get_db), user=Depends(get_current_user)):
    if user.role == "admin":
        return db.query(Scan).order_by(Scan.started_at.desc()).all()
    return db.query(Scan).filter(Scan.started_by_id == user.id).order_by(Scan.started_at.desc()).all()

@router.post("")
def launch_scan(data: LaunchScanRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    scan_id = str(uuid.uuid4())
    scan = Scan(id=scan_id, target=data.target, target_type=data.target_type,
                status="running", started_by_id=user.id)
    db.add(scan); db.commit()
    log(db, "scan_launched", user.username, f"Target: {data.target}")
    db.add(Notification(user_id=user.id, title="Scan lance",
        message=f"Scan de {data.target} en cours...", type="info", scan_id=scan_id))
    db.commit()
    _scan_events[scan_id] = []

    import threading, subprocess, re, sys

    def run_scan(sid, target):
        if target.startswith("http://") or target.startswith("https://"):
            from urllib.parse import urlparse
            parsed = urlparse(target)
            host = parsed.hostname or target
            port = parsed.port
        else:
            parts = target.split(":")
            host = parts[0]
            port = int(parts[1]) if len(parts) > 1 else None

        from database import SessionLocal
        db2 = SessionLocal()

        cve_id, severity, cvss, summary = None, "low", "0.0", ""
        ports = []
        full_output = ""
        llm_analysis = ""
        exploit_result = ""

        try:
            # AGENT 1 : RECONNAISSANCE (Nmap)
            emit_event(sid, "agent_start", "reconnaissance", {"label": "Reconnaissance", "target": host, "port": port})
            nmap_cmd = ["nmap", "-sV", "--top-ports", "50", "--host-timeout", "60s", host]
            if port:
                nmap_cmd = ["nmap", "-sV", "-p", str(port), "--host-timeout", "60s", host]
            emit_event(sid, "agent_output", "reconnaissance", output=f"[NAPT_0]$ {' '.join(nmap_cmd)}")
            proc = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            nmap_lines = []
            for line in proc.stdout:
                line = line.rstrip()
                nmap_lines.append(line)
                emit_event(sid, "agent_output", "reconnaissance", output=line)
            proc.wait()
            full_output = "\n".join(nmap_lines)
            for line in nmap_lines:
                m = re.match(r"\s*(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
                if m:
                    ports.append({"port": m.group(1), "proto": m.group(2), "service": m.group(3), "version": m.group(4).strip()})
            latency = None
            for line in nmap_lines:
                lm = re.search(r"\((\d+\.\d+s) latency\)", line)
                if lm:
                    latency = lm.group(1)
            emit_event(sid, "agent_result", "reconnaissance", {"host": host, "latency": latency, "ports": ports, "ports_count": len(ports)})
            emit_event(sid, "agent_complete", "reconnaissance")

            # AGENT 2 : RAG CVE SEARCH (Qdrant)
            emit_event(sid, "agent_start", "rag_lookup", {"label": "Recherche CVE"})
            if ports:
                emit_event(sid, "agent_output", "rag_lookup", output="+ Recherche CVE dans la base Qdrant...")
                try:
                    from qdrant_client import QdrantClient
                    from fastembed import TextEmbedding
                    qclient = QdrantClient("localhost", port=6333)
                    embedder = TextEmbedding()
                    services_str = " ".join([f"{p['service']} {p['version']}" for p in ports])
                    query_vec = list(embedder.embed([services_str]))[0].tolist()
                    results = qclient.search(collection_name="cve_collection", query_vector=query_vec, limit=3)
                    if results:
                        best = results[0].payload
                        cve_id   = best.get("cve_id")
                        cvss     = str(best.get("cvss", "0.0"))
                        severity = best.get("severity", "low")
                        summary  = best.get("description", "")
                        svc_name = best.get("service", "")
                        emit_event(sid, "agent_output", "rag_lookup", output=f"+ CVE trouvee: {cve_id} (score: {results[0].score:.2f})")
                        emit_event(sid, "agent_result", "rag_lookup", {
                            "cve_id": cve_id, "cvss": cvss, "severity": severity,
                            "service": svc_name, "version": ""
                        })
                        emit_event(sid, "agent_output", "rag_lookup", output=f"CVE: {cve_id} CVSS:{cvss} ({severity.upper()})")
                    else:
                        emit_event(sid, "agent_output", "rag_lookup", output="Aucune CVE trouvee dans Qdrant")
                except Exception as rag_err:
                    emit_event(sid, "agent_output", "rag_lookup", output=f"Erreur RAG: {rag_err}")
            else:
                emit_event(sid, "agent_output", "rag_lookup", output="Aucun port ouvert detecte")
            emit_event(sid, "agent_complete", "rag_lookup")

            # AGENT 3 : ANALYSE DE VULNERABILITES (Gemma)
            emit_event(sid, "agent_start", "vulnerability_analysis", {"label": "Analyse de vulnerabilites"})
            if cve_id:
                emit_event(sid, "agent_output", "vulnerability_analysis", output=f"+ Gemma analyse: {cve_id} sur {host}")
                system_prompt = (
                    "Tu es N.A.P.T, expert en cybersecurite. Analyse la vulnerabilite et fournis: "
                    "1) Vecteur d attaque 2) Impact potentiel 3) Niveau de risque 4) Recommandations de remediation. "
                    "Sois concis et precis. Reponds en francais."
                )
                user_prompt = (
                    f"Cible: {host}\n"
                    f"Ports: {', '.join(p['port']+'/'+p['service'] for p in ports)}\n"
                    f"CVE: {cve_id}\nCVSS: {cvss} ({severity.upper()})\n"
                    f"Description: {summary[:400]}\n\nAnalyse de risque:"
                )
                llm_analysis = llm_call(system_prompt, user_prompt)
                for line in llm_analysis.split("\n"):
                    if line.strip():
                        emit_event(sid, "agent_output", "vulnerability_analysis", output=line)
                emit_event(sid, "agent_result", "vulnerability_analysis", {
                    "cve_id": cve_id, "cvss": cvss, "severity": severity, "analysis": llm_analysis[:500]
                })
            else:
                emit_event(sid, "agent_output", "vulnerability_analysis", output="Pas de CVE a analyser - hote semble securise")
                emit_event(sid, "agent_result", "vulnerability_analysis", {
                    "cve_id": None, "cvss": "0.0", "severity": "none", "analysis": "Aucune vulnerabilite critique."
                })
            emit_event(sid, "agent_complete", "vulnerability_analysis")

            # AGENT 4 : SUGGESTION D'EXPLOITATION (Gemma)
            emit_event(sid, "agent_start", "exploitation", {"label": "Exploitation"})
            if cve_id:
                emit_event(sid, "agent_output", "exploitation", output=f"+ Gemma analyse le vecteur d exploitation pour {cve_id}...")
                exploit_suggestion = llm_call(
                    "Tu es N.A.P.T, expert en cybersecurite offensif. Reponds en francais.",
                    f"CVE: {cve_id} (CVSS: {cvss}, {severity.upper()})\n"
                    f"Cible: {host}\n"
                    f"Services: {', '.join(p['port']+'/'+p['service'] for p in ports)}\n\n"
                    "Donne: 1) Le module Metasploit recommande 2) La commande d exploitation 3) L impact potentiel. Sois concis."
                )
                for line in exploit_suggestion.split("\n"):
                    if line.strip():
                        emit_event(sid, "agent_output", "exploitation", output=line)
                exploit_result = exploit_suggestion
                emit_event(sid, "agent_result", "exploitation", {
                    "module": f"Gemma suggestion pour {cve_id}",
                    "target": host,
                    "success": not exploit_suggestion.startswith("[LLM indisponible"),
                    "output": exploit_suggestion[:300]
                })
            else:
                emit_event(sid, "agent_output", "exploitation", output="Pas de CVE - exploitation ignoree")
                emit_event(sid, "agent_result", "exploitation", {"module": None, "target": host, "success": False, "output": ""})
            emit_event(sid, "agent_complete", "exploitation")

            # AGENT 5 : RAPPORT
            emit_event(sid, "agent_start", "report", {"label": "Generation du rapport"})
            emit_event(sid, "agent_output", "report", output="+ Consolidation du rapport...")
            if cve_id:
                emit_event(sid, "agent_output", "report", output=f"+ CVE: {cve_id}  CVSS: {cvss}  Severite: {severity.upper()}")
            emit_event(sid, "agent_output", "report", output="+ Enregistrement en base PostgreSQL...")
            s = db2.query(Scan).filter(Scan.id == sid).first()
            if s:
                s.status    = "completed"
                s.finished_at = datetime.utcnow()
                s.cve_id    = cve_id
                s.severity  = severity
                s.cvss_score = cvss
                s.client_summary = summary
                s.raw_output = (
                    full_output +
                    "\n\n=== GEMMA CVE IDENTIFICATION ===\n" + (summary or "N/A") +
                    "\n\n=== GEMMA ANALYSIS ===\n" + llm_analysis +
                    "\n\n=== EXPLOIT ===\n" + exploit_result
                )
                db2.commit()
            emit_event(sid, "agent_output", "report", output="Rapport enregistre avec succes")
            emit_event(sid, "agent_complete", "report")
            emit_event(sid, "scan_complete", data={"cve_id": cve_id, "severity": severity, "cvss": cvss})

        except Exception as e:
            import traceback
            emit_event(sid, "agent_error", "report", data={"message": str(e)})
            s = db2.query(Scan).filter(Scan.id == sid).first()
            if s:
                s.status = "failed"
                s.raw_output = traceback.format_exc()
                db2.commit()
        finally:
            db2.close()

    threading.Thread(target=run_scan, args=(scan_id, data.target), daemon=True).start()
    return {"id": scan_id, "target": data.target, "status": "running", "started_at": scan.started_at.isoformat()}


@router.post("/{scan_id}/stop")
def stop_scan(scan_id: str, db: Session = Depends(get_db), user=Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan introuvable")
    scan.status = "stopped"
    scan.finished_at = datetime.utcnow()
    db.commit()
    log(db, "scan_stopped", user.username, f"{scan.target} - manually stopped")
    emit_event(scan_id, "stopped")
    return {"success": True}

@router.get("/nmap-network")
def scan_network(user=Depends(get_current_user)):
    import subprocess, re
    try:
        result = subprocess.run(["nmap", "-sn", "172.22.64.0/20", "--host-timeout", "10s"], capture_output=True, text=True, timeout=60)
        hosts = []
        for line in result.stdout.splitlines():
            ip_match = re.search(r"Nmap scan report for (.+)", line)
            if ip_match:
                hosts.append({"host": ip_match.group(1), "status": "up"})
        return {"network": "172.22.64.0/20", "hosts_found": len(hosts), "hosts": hosts, "raw": result.stdout}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/nmap-target")
def scan_target(host: str, user=Depends(get_current_user)):
    import subprocess, re
    if not re.match(r'^[\w\.\-]+$', host):
        raise HTTPException(status_code=400, detail="Cible invalide")
    try:
        result = subprocess.run(["nmap", "-sV", "--top-ports", "100", "--host-timeout", "30s", host], capture_output=True, text=True, timeout=120)
        ports = []
        for line in result.stdout.splitlines():
            m = re.match(r'\s*(\d+/\w+)\s+(\w+)\s+(\S+)\s*(.*)', line)
            if m:
                ports.append({"port": m.group(1), "state": m.group(2), "service": m.group(3), "version": m.group(4).strip()})
        return {"target": host, "ports": ports, "raw": result.stdout}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, db: Session = Depends(get_db), _=Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan introuvable")
    return scan

@router.patch("/{scan_id}/remediation")
def update_remediation(scan_id: str, data: UpdateRemediation, db: Session = Depends(get_db), user=Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan introuvable")
    old = scan.remediation_status
    scan.remediation_status = data.status
    db.commit()
    db.add(RemediationLog(scan_id=scan_id, old_status=old, new_status=data.status, changed_by=user.username, note=data.note))
    db.commit()
    log(db, "remediation_status_changed", user.username, f"Scan {scan.target} ({scan.cve_id or '?'}): {old} -> {data.status}")
    return {"success": True}

@router.post("/{scan_id}/chat")
def chat(scan_id: str, data: ChatRequest, db: Session = Depends(get_db), user=Depends(get_current_user)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404)
    db.add(ChatMessage(scan_id=scan_id, role="user", content=data.message))
    db.commit()
    reply = generate_reply(data.message, scan)
    db.add(ChatMessage(scan_id=scan_id, role="assistant", content=reply))
    db.commit()
    return {"reply": reply}

def generate_reply(question: str, scan) -> str:
    try:
        return llm_call(
            "Tu es N.A.P.T, expert en cybersecurite. Reponds en francais de facon concise.",
            f"Contexte du scan - Cible: {scan.target}, CVE: {scan.cve_id or 'inconnue'}, "
            f"Severite: {scan.severity or 'N/A'}.\nQuestion: {question}"
        )
    except Exception:
        return f"Concernant {scan.cve_id or 'cette vulnerabilite'} sur {scan.target}: Appliquer les patches de securite."

@router.websocket("/{scan_id}/live")
async def ws_live(websocket: WebSocket, scan_id: str):
    token = websocket.query_params.get("token", "")
    payload = decode_token(token)
    if not payload.get("sub"):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    if scan_id not in _ws_connections:
        _ws_connections[scan_id] = []
    _ws_connections[scan_id].append(websocket)
    sent_index = 0
    try:
        while True:
            events = _scan_events.get(scan_id, [])
            while sent_index < len(events):
                await websocket.send_text(json.dumps(events[sent_index]))
                sent_index += 1
            last_types = [e["type"] for e in events[-3:]] if events else []
            if any(t in last_types for t in ["scan_complete", "scan_failed", "stopped"]):
                break
            await asyncio.sleep(0.3)
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        if scan_id in _ws_connections and websocket in _ws_connections[scan_id]:
            _ws_connections[scan_id].remove(websocket)
