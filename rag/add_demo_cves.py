"""
add_demo_cves.py - Ajoute a la base RAG les CVE des cibles de validation
(services detectables par Nmap), avec des descriptions calibrees sur les
bannieres reseau reelles pour une detection fiable.

Usage :
    python add_demo_cves.py
"""
import sys, os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from embedder import encode
from store import init_collection, upsert_batch, collection_stats

DEMO_CVES = [
    {
        "cve_id": "CVE-2022-0543", "product": "redis",
        "severity": "critical", "cvss": "10.0",
        "description": ("Redis Lua sandbox escape leading to remote code "
                        "execution. Debian/Ubuntu packaging flaw in the Lua "
                        "scripting engine of the Redis key-value store server "
                        "allows an unauthenticated attacker to run commands."),
    },
    {
        "cve_id": "CVE-2011-2523", "product": "vsftpd",
        "severity": "critical", "cvss": "10.0",
        "description": ("vsftpd 2.3.4 backdoor command execution. A malicious "
                        "backdoor in the vsftpd FTP server version 2.3.4 opens "
                        "a root command shell on the target."),
    },
    {
        "cve_id": "CVE-2010-2075", "product": "unrealircd",
        "severity": "critical", "cvss": "10.0",
        "description": ("UnrealIRCd 3.2.8.1 backdoor remote code execution. The "
                        "UnrealIRCd 3.2.8.1 IRC server was distributed with a "
                        "trojan allowing arbitrary command execution."),
    },
    {
        "cve_id": "CVE-2007-2447", "product": "samba",
        "severity": "critical", "cvss": "9.8",
        "description": ("Samba 3.0.x username map script command injection. "
                        "Remote command execution via shell metacharacters in "
                        "the username field of smbd (MS-RPC)."),
    },
]


def build_text(cve):
    return (f"CVE: {cve['cve_id']} | Severity: {cve['severity']} | "
            f"CVSS: {cve['cvss']} | {cve['product']} | {cve['description']}")


def main():
    init_collection(recreate=False)  # garde la base existante, ajoute ces CVE
    print(f"[DEMO] Indexation de {len(DEMO_CVES)} CVE de validation...")
    texts = [build_text(c) for c in DEMO_CVES]
    vectors = encode(texts)
    points = []
    for cve, vec in zip(DEMO_CVES, vectors):
        v = vec.tolist() if hasattr(vec, "tolist") else list(vec)
        points.append({
            "vector": v,
            "text": build_text(cve),
            "cve_id": cve["cve_id"],
            "product": cve["product"],
            "severity": cve["severity"],
            "cvss": cve["cvss"],
            "category": "demo",
            "source": "curated",
            "filename": cve["cve_id"] + ".txt",
            "chunk_id": 0,
        })
    n = upsert_batch(points)
    stats = collection_stats()
    print(f"[DEMO] {n} CVE de validation indexes")
    print(f"[DEMO] Total dans la base : {stats['vectors_count']} vecteurs")


if __name__ == "__main__":
    main()
