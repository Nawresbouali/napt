"""
fetch_nvd.py - Alimente la base vectorielle Qdrant depuis la vraie base
mondiale des vulnerabilites NVD (NIST), via son API officielle.

Remplace l'approche "CVE codes en dur" par une alimentation depuis la
source officielle (reponse au reproche #3 de l'evaluation).

Usage :
    python fetch_nvd.py            # recupere 400 CVE critiques
    python fetch_nvd.py 800        # recupere 800 CVE critiques
"""
import sys, os, time, requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from embedder import encode
from store import init_collection, upsert_batch, collection_stats

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "NAPT-Scanner/2.0"}


def fetch_nvd(total=400, per_page=200, severity="CRITICAL"):
    """Recupere des CVE reels depuis l'API NVD (pagination + rate limit)."""
    collected = []
    start = 0
    while len(collected) < total:
        params = {"resultsPerPage": per_page, "startIndex": start,
                  "cvssV3Severity": severity}
        try:
            r = requests.get(NVD_URL, params=params, headers=HEADERS, timeout=60)
            data = r.json()
        except Exception as e:
            print(f"[NVD] Erreur requete : {e}")
            break

        vulns = data.get("vulnerabilities", [])
        if not vulns:
            break

        for v in vulns:
            c = v.get("cve", {})
            cid = c.get("id", "")
            desc = ""
            for d in c.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break
            score, sev = 0.0, severity.lower()
            metrics = c.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30"):
                arr = metrics.get(key) or []
                if arr:
                    cd = arr[0].get("cvssData", {})
                    score = cd.get("baseScore", 0.0)
                    sev = cd.get("baseSeverity", severity).lower()
                    break
            if cid and desc:
                collected.append({
                    "cve_id": cid,
                    "product": "",
                    "description": desc[:400],
                    "severity": sev,
                    "cvss": str(score),
                    "category": "nvd",
                })

        print(f"[NVD] {len(collected)} CVE recuperes...")
        start += per_page
        if start >= data.get("totalResults", 0):
            break
        time.sleep(6)  # respect du rate limit NVD (sans cle API)

    return collected[:total]


def build_text(cve):
    return (f"CVE: {cve['cve_id']} | Severity: {cve['severity']} | "
            f"CVSS: {cve['cvss']} | {cve['description']}")


def index_nvd(cves):
    if not cves:
        print("[NVD] Aucun CVE a indexer.")
        return 0
    print(f"[NVD] Encodage de {len(cves)} CVE (peut prendre un moment)...")
    texts = [build_text(c) for c in cves]
    vectors = encode(texts)
    points = []
    for cve, vec in zip(cves, vectors):
        v = vec.tolist() if hasattr(vec, "tolist") else list(vec)
        points.append({
            "vector": v,
            "text": build_text(cve),
            "cve_id": cve["cve_id"],
            "product": cve["product"],
            "severity": cve["severity"],
            "cvss": cve["cvss"],
            "category": "nvd",
            "source": "nvd",
            "filename": cve["cve_id"] + ".txt",
            "chunk_id": 0,
        })
    n = upsert_batch(points)
    print(f"[NVD] {n} CVE reels indexes depuis NVD")
    return n


if __name__ == "__main__":
    nb = int(sys.argv[1]) if len(sys.argv) > 1 else 400
    init_collection(recreate=False)  # garde les CVE existants, ajoute les nouveaux
    print(f"[NVD] Recuperation de {nb} CVE critiques depuis l'API NVD...")
    cves = fetch_nvd(total=nb)
    index_nvd(cves)
    stats = collection_stats()
    print("=" * 50)
    print(f"[NVD] Total dans la base : {stats['vectors_count']} vecteurs reels")
    print("=" * 50)
