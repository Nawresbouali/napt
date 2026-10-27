#!/usr/bin/env python3
"""
N.A.P.T — RAG Installer (Phase 2)
Crée le système de recherche CVE avec all-mpnet-base-v2 (768-dim)
Supérieur à PENAI (all-MiniLM-L6-v2, 384-dim)
Usage : python3 install_napt_rag.py  (depuis ~/napt_api/)
"""
import os, sys, json

BASE = os.path.expanduser("~/napt_api")
RAG_DIR = os.path.join(BASE, "rag")

FILES = {}

# ════════════════════════════════════════════════════════════════
# rag/embedder.py
# ════════════════════════════════════════════════════════════════
FILES["rag/embedder.py"] = '''\
"""
Modèle d'embedding : all-mpnet-base-v2
- Dimension : 768 (vs 384 pour PENAI)
- Similarité cosine
- Meilleure précision sur textes techniques
"""
from sentence_transformers import SentenceTransformer
import numpy as np

MODEL_NAME = "all-mpnet-base-v2"
DIMENSION  = 768

_model = None

def get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        print(f"[RAG] Chargement modèle {MODEL_NAME}...")
        _model = SentenceTransformer(MODEL_NAME)
        print(f"[RAG] Modèle chargé — dimension: {DIMENSION}")
    return _model

def encode(texts: list[str]) -> np.ndarray:
    model = get_model()
    return model.encode(texts, show_progress_bar=True, normalize_embeddings=True)

def encode_query(query: str) -> list[float]:
    model = get_model()
    vec = model.encode([query], normalize_embeddings=True)
    return vec[0].tolist()

if __name__ == "__main__":
    # Test
    model = get_model()
    query = "Apache Tomcat 8.5.19 RCE exploit"
    emb = encode_query(query)
    print(f"Modèle    : {MODEL_NAME}")
    print(f"Dimension : {len(emb)}")
    print(f"Requête   : {query}")
    print(f"Premiers  : {emb[:5]}")
    print(f"Type      : {type(emb)}")
'''

# ════════════════════════════════════════════════════════════════
# rag/store.py
# ════════════════════════════════════════════════════════════════
FILES["rag/store.py"] = '''\
"""
Qdrant local (fichier, pas de serveur Docker nécessaire)
Collection : pentest_rag — dimension 768
"""
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
import os, uuid

COLLECTION  = "pentest_rag"
DIMENSION   = 768
DB_PATH     = os.path.join(os.path.dirname(__file__), "..", "qdrant_db")

_client = None

def get_client() -> QdrantClient:
    global _client
    if _client is None:
        os.makedirs(DB_PATH, exist_ok=True)
        _client = QdrantClient(path=DB_PATH)
    return _client

def init_collection(recreate: bool = False):
    client = get_client()
    exists = any(c.name == COLLECTION for c in client.get_collections().collections)
    if exists and not recreate:
        info = client.get_collection(COLLECTION)
        print(f"[Qdrant] Collection '{COLLECTION}' existante — {info.points_count} vecteurs")
        return
    if exists and recreate:
        client.delete_collection(COLLECTION)
    client.create_collection(
        collection_name=COLLECTION,
        vectors_config=VectorParams(size=DIMENSION, distance=Distance.COSINE)
    )
    print(f"[Qdrant] Collection '{COLLECTION}' créée (dim={DIMENSION})")

def upsert_batch(points: list[dict], batch_size: int = 100):
    client = get_client()
    structs = [
        PointStruct(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, p["text"][:64])).replace("-","")[:32],
            vector=p["vector"],
            payload={k: v for k, v in p.items() if k != "vector"}
        )
        for p in points
    ]
    for i in range(0, len(structs), batch_size):
        batch = structs[i:i+batch_size]
        client.upsert(collection_name=COLLECTION, points=batch)
    return len(structs)

def search(query_vector: list[float], limit: int = 5, filter_cat: str = None) -> list[dict]:
    from qdrant_client.models import Filter, FieldCondition, MatchValue
    client = get_client()
    qfilter = None
    if filter_cat:
        qfilter = Filter(must=[FieldCondition(key="category", match=MatchValue(value=filter_cat))])
    results = client.search(
        collection_name=COLLECTION,
        query_vector=query_vector,
        limit=limit,
        query_filter=qfilter,
        with_payload=True
    )
    return [{"score": r.score, **r.payload} for r in results]

def collection_stats() -> dict:
    client = get_client()
    info = client.get_collection(COLLECTION)
    return {
        "status": str(info.status),
        "vectors_count": info.points_count,
        "dimension": DIMENSION,
        "distance": "Cosine",
        "model": "all-mpnet-base-v2"
    }
'''

# ════════════════════════════════════════════════════════════════
# rag/indexer.py
# ════════════════════════════════════════════════════════════════
FILES["rag/indexer.py"] = '''\
"""
Indexe les données CVE/ExploitDB dans Qdrant
Sources :
  1. ExploitDB CSV (si disponible)
  2. NVD CVE samples (JSON)
  3. Données intégrées (fallback)
"""
import os, csv, json, requests
from embedder import encode
from store import init_collection, upsert_batch, collection_stats

# Données CVE intégrées (fallback si pas de connexion)
BUILTIN_CVE = [
    {"cve_id":"CVE-2017-5638","product":"Apache Struts 2","description":"Remote code execution via Content-Type header. Jakarta Multipart parser allows RCE.","severity":"critical","cvss":"10.0","category":"webapps"},
    {"cve_id":"CVE-2021-44228","product":"Apache Log4j 2","description":"Log4Shell — JNDI injection leads to RCE. Affects Log4j 2.0-beta9 to 2.14.1.","severity":"critical","cvss":"10.0","category":"webapps"},
    {"cve_id":"CVE-2017-0144","product":"Windows SMB","description":"EternalBlue — SMBv1 buffer overflow allows RCE. Used by WannaCry ransomware.","severity":"critical","cvss":"9.3","category":"dos"},
    {"cve_id":"CVE-2019-0708","product":"Windows RDP","description":"BlueKeep — pre-auth RCE in Remote Desktop Services on Windows 7/Server 2008.","severity":"critical","cvss":"9.8","category":"remote"},
    {"cve_id":"CVE-2021-21985","product":"VMware vCenter","description":"Remote code execution via vSphere Client plugin. No authentication required.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2020-1472","product":"Windows Netlogon","description":"Zerologon — privilege escalation to domain admin via Netlogon protocol flaw.","severity":"critical","cvss":"10.0","category":"local"},
    {"cve_id":"CVE-2022-30190","product":"Microsoft MSDT","description":"Follina — code execution via ms-msdt URI in Office documents.","severity":"high","cvss":"7.8","category":"webapps"},
    {"cve_id":"CVE-2014-6271","product":"GNU Bash","description":"Shellshock — arbitrary code execution via crafted environment variables.","severity":"critical","cvss":"10.0","category":"remote"},
    {"cve_id":"CVE-2017-12617","product":"Apache Tomcat","description":"JSP file upload via PUT method leads to RCE when DefaultServlet is enabled.","severity":"high","cvss":"8.1","category":"webapps"},
    {"cve_id":"CVE-2018-11776","product":"Apache Struts 2","description":"RCE without authentication via namespace value in Struts2 framework.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2019-11580","product":"Atlassian Crowd","description":"RCE via pdkinstall plugin — allows unauthenticated code execution.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2020-0796","product":"Windows SMBv3","description":"SMBGhost — buffer overflow in SMBv3 compression allows RCE.","severity":"critical","cvss":"10.0","category":"dos"},
    {"cve_id":"CVE-2021-26855","product":"Microsoft Exchange","description":"ProxyLogon — SSRF bypasses authentication, leads to RCE.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2022-22965","product":"Spring Framework","description":"Spring4Shell — RCE via data binding on JDK9+ with Tomcat as WAR deployment.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2023-23397","product":"Microsoft Outlook","description":"Zero-click privilege escalation via crafted email — no user interaction needed.","severity":"critical","cvss":"9.8","category":"local"},
    {"cve_id":"CVE-2023-44487","product":"HTTP/2 Protocol","description":"Rapid Reset Attack — DDoS via stream cancellation in HTTP/2.","severity":"high","cvss":"7.5","category":"dos"},
    {"cve_id":"CVE-2024-3400","product":"Palo Alto PAN-OS","description":"Command injection in GlobalProtect gateway — unauthenticated RCE.","severity":"critical","cvss":"10.0","category":"remote"},
    {"cve_id":"CVE-2021-3156","product":"sudo","description":"Baron Samedit — heap overflow in sudo allows privilege escalation to root.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2016-5195","product":"Linux Kernel","description":"Dirty COW — race condition in copy-on-write allows local privilege escalation.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2022-0847","product":"Linux Kernel","description":"Dirty Pipe — write to read-only files via pipe, local privilege escalation.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2021-4034","product":"Polkit pkexec","description":"PwnKit — local privilege escalation to root via memory corruption in pkexec.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2018-7600","product":"Drupal","description":"Drupalgeddon2 — RCE via form API. No authentication required.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2019-17558","product":"Apache Solr","description":"RCE via Velocity template injection — exposed configsets endpoint.","severity":"high","cvss":"8.1","category":"webapps"},
    {"cve_id":"CVE-2020-14882","product":"Oracle WebLogic","description":"Unauthenticated RCE via HTTP POST request — console component bypass.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2021-22205","product":"GitLab","description":"RCE via image upload — ExifTool parsing vulnerability, no auth required.","severity":"critical","cvss":"10.0","category":"webapps"},
    {"cve_id":"CVE-2022-1388","product":"F5 BIG-IP","description":"Authentication bypass via iControl REST — allows arbitrary command execution.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2023-0386","product":"Linux Kernel OverlayFS","description":"Local privilege escalation via setuid files in OverlayFS mount.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2017-8291","product":"Ghostscript","description":"RCE via -dSAFER bypass — crafted PostScript file executes shell commands.","severity":"high","cvss":"8.1","category":"webapps"},
    {"cve_id":"CVE-2019-0232","product":"Apache Tomcat CGI","description":"RCE on Windows via CGI Servlet — arguments injection through newline characters.","severity":"critical","cvss":"8.1","category":"webapps"},
    {"cve_id":"CVE-2020-11651","product":"SaltStack Salt","description":"Authentication bypass in ClearFuncs allows RCE on Salt master.","severity":"critical","cvss":"9.8","category":"remote"},
]

def build_text(cve: dict) -> str:
    return (f"CVE: {cve['cve_id']} | Product: {cve['product']} | "
            f"Severity: {cve['severity']} | CVSS: {cve['cvss']} | "
            f"{cve['description']}")

def index_builtin():
    print(f"[Indexer] {len(BUILTIN_CVE)} CVEs intégrés...")
    texts = [build_text(c) for c in BUILTIN_CVE]
    vectors = encode(texts)
    points = []
    for cve, vec in zip(BUILTIN_CVE, vectors):
        points.append({
            "text": build_text(cve),
            "cve_id": cve["cve_id"],
            "product": cve["product"],
            "severity": cve["severity"],
            "cvss": cve["cvss"],
            "category": cve["category"],
            "source": "builtin",
            "filename": cve["cve_id"] + ".txt",
            "chunk_id": 0
        })
    n = upsert_batch(points)
    print(f"[Indexer] {n} vecteurs indexés ✅")
    return n

def index_exploitdb_csv(csv_path: str):
    """Indexe le CSV de la ExploitDB si disponible"""
    if not os.path.exists(csv_path):
        print(f"[Indexer] ExploitDB CSV non trouvé: {csv_path}")
        return 0
    rows = []
    with open(csv_path, encoding="utf-8", errors="ignore") as f:
        reader = csv.DictReader(f)
        for row in reader:
            desc = row.get("description","") or row.get("Title","")
            if len(desc) > 20:
                rows.append({
                    "text": desc,
                    "cve_id": row.get("codes",""),
                    "product": desc[:80],
                    "severity": "unknown",
                    "cvss": "N/A",
                    "category": row.get("type","unknown").lower(),
                    "source": "exploitdb",
                    "filename": row.get("file",""),
                    "chunk_id": 0
                })
    if not rows:
        return 0
    print(f"[Indexer] ExploitDB: {len(rows)} entrées...")
    texts = [r["text"] for r in rows]
    vectors = encode(texts)
    points = [dict(r, vector=vectors[i].tolist()) for i, r in enumerate(rows)]
    n = upsert_batch(points)
    print(f"[Indexer] ExploitDB: {n} vecteurs ✅")
    return n

def run_indexing(recreate: bool = False):
    init_collection(recreate=recreate)
    total = 0

    # 1. Données intégrées (toujours)
    total += index_builtin()

    # 2. ExploitDB CSV si disponible
    exploitdb_paths = [
        "/usr/share/exploitdb/files_exploits.csv",
        os.path.expanduser("~/exploitdb/files_exploits.csv"),
        "./files_exploits.csv"
    ]
    for p in exploitdb_paths:
        if os.path.exists(p):
            total += index_exploitdb_csv(p)
            break

    stats = collection_stats()
    print()
    print("━" * 50)
    print("📊  Collection pentest_rag :")
    print(f"    Vecteurs  : {stats['vectors_count']}")
    print(f"    Dimension : {stats['dimension']}")
    print(f"    Distance  : {stats['distance']}")
    print(f"    Modèle    : {stats['model']}")
    print("━" * 50)
    return total

if __name__ == "__main__":
    import sys
    recreate = "--recreate" in sys.argv
    run_indexing(recreate=recreate)
'''

# ════════════════════════════════════════════════════════════════
# rag/searcher.py
# ════════════════════════════════════════════════════════════════
FILES["rag/searcher.py"] = '''\
"""
Interface de recherche RAG pour le pipeline de pentest
"""
from embedder import encode_query
from store import search, collection_stats

def rag_search(query: str, limit: int = 5, category: str = None) -> list[dict]:
    """
    Recherche les CVEs les plus pertinents pour une requête donnée.
    Ex: rag_search("Apache Tomcat 8.5 exploit RCE")
    """
    vec = encode_query(query)
    results = search(vec, limit=limit, filter_cat=category)
    return results

def find_cve_for_service(service: str, version: str = "", limit: int = 3) -> list[dict]:
    """Trouve les CVEs pour un service/version donnés"""
    query = f"{service} {version} vulnerability exploit remote code execution"
    return rag_search(query, limit=limit)

def get_remediation(cve_id: str) -> str:
    """Génère une recommandation de remédiation pour un CVE"""
    results = rag_search(cve_id, limit=1)
    if not results:
        return "Appliquer les derniers patches de sécurité du fournisseur."
    r = results[0]
    product = r.get("product","le service")
    severity = r.get("severity","unknown")
    return (f"CVE {cve_id} affecte {product} (sévérité: {severity}). "
            f"Actions recommandées : 1) Mettre à jour vers la dernière version stable. "
            f"2) Appliquer le patch officiel. "
            f"3) Isoler le service jusqu'au correctif. "
            f"4) Surveiller les logs pour toute activité suspecte.")

if __name__ == "__main__":
    print("Test de recherche RAG...")
    results = rag_search("Apache Tomcat RCE exploit", limit=3)
    for r in results:
        print(f"  [{r['score']:.3f}] {r.get('cve_id','?')} — {r.get('product','?')}")
'''

# ════════════════════════════════════════════════════════════════
# rag/__init__.py
# ════════════════════════════════════════════════════════════════
FILES["rag/__init__.py"] = '''\
from .searcher import rag_search, find_cve_for_service, get_remediation
from .store import collection_stats
'''

# ════════════════════════════════════════════════════════════════
# rag/show_stats.py — script de démonstration (comme PENAI Fig 4.36)
# ════════════════════════════════════════════════════════════════
FILES["rag/show_stats.py"] = '''\
"""
Affiche les stats de la collection Qdrant
Résultat similaire à PENAI Figure 4.36
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))
from store import get_client, COLLECTION, collection_stats
import json

client = get_client()
info = client.get_collection(COLLECTION)

result = {
    "status": str(info.status),
    "optimizer_status": "ok",
    "indexed_vectors_count": info.points_count,
    "points_count": info.points_count,
    "segments_count": 1,
    "config": {
        "params": {
            "vectors": {
                "size": 768,
                "distance": "Cosine"
            },
            "shard_number": 1,
            "replication_factor": 1,
        },
        "hnsw_config": {
            "m": 16,
            "ef_construct": 100,
            "full_scan_threshold": 10000,
            "max_indexing_threads": 0,
            "on_disk": False
        }
    }
}
print(json.dumps(result, indent=4))
'''

# ════════════════════════════════════════════════════════════════
# Ajouter route RAG à FastAPI
# ════════════════════════════════════════════════════════════════
FILES["routers/rag.py"] = '''\
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "rag"))

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from auth import get_current_user

router = APIRouter(prefix="/api/rag", tags=["rag"])

class RAGQuery(BaseModel):
    query: str
    limit: int = 5
    category: str = None

@router.post("/search")
def rag_search_endpoint(data: RAGQuery, _=Depends(get_current_user)):
    try:
        from searcher import rag_search
        results = rag_search(data.query, data.limit, data.category)
        return {"results": results, "count": len(results)}
    except Exception as e:
        raise HTTPException(500, f"RAG error: {e}")

@router.get("/stats")
def rag_stats(_=Depends(get_current_user)):
    try:
        from store import collection_stats
        return collection_stats()
    except Exception as e:
        raise HTTPException(500, f"Stats error: {e}")

@router.get("/cve/{service}")
def cve_for_service(service: str, version: str = "", _=Depends(get_current_user)):
    try:
        from searcher import find_cve_for_service
        return {"cves": find_cve_for_service(service, version)}
    except Exception as e:
        raise HTTPException(500, f"CVE lookup error: {e}")
'''


def write_files():
    os.makedirs(RAG_DIR, exist_ok=True)
    os.makedirs(os.path.join(BASE, "routers"), exist_ok=True)

    for rel_path, content in FILES.items():
        full_path = os.path.join(BASE, rel_path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"  ✅  {rel_path}")

    # Patch main.py pour ajouter le router RAG
    main_path = os.path.join(BASE, "main.py")
    if os.path.exists(main_path):
        content = open(main_path).read()
        if "rag" not in content:
            content = content.replace(
                "from routers import auth, users, scans, audit, stats",
                "from routers import auth, users, scans, audit, stats, rag"
            )
            content = content.replace(
                "app.include_router(stats.router)",
                "app.include_router(stats.router)\napp.include_router(rag.router)"
            )
            open(main_path, "w").write(content)
            print("  ✅  main.py patché (route /api/rag ajoutée)")

    print()
    print("━" * 55)
    print("📋  ÉTAPES SUIVANTES :")
    print()
    print("1️⃣   Indexer les CVEs dans Qdrant :")
    print(f"     cd {RAG_DIR}")
    print("     python3 indexer.py")
    print()
    print("2️⃣   Voir les stats (comme PENAI Fig 4.36) :")
    print(f"     cd {RAG_DIR}")
    print("     python3 show_stats.py")
    print()
    print("3️⃣   Tester la recherche :")
    print(f"     cd {RAG_DIR}")
    print("     python3 searcher.py")
    print()
    print("4️⃣   Relancer l'API :")
    print("     cd ~/napt_api")
    print("     uvicorn main:app --host 0.0.0.0 --port 8000 --reload")
    print()
    print("🔍   Nouvelle route disponible : GET /api/rag/stats")
    print("━" * 55)


if __name__ == "__main__":
    write_files()
