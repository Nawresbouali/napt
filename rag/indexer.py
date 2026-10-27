import os, csv
from embedder import encode
from store import init_collection, upsert_batch, collection_stats

BUILTIN_CVE = [
    {"cve_id":"CVE-2017-5638","product":"Apache Struts 2","description":"RCE via Content-Type header Jakarta Multipart parser.","severity":"critical","cvss":"10.0","category":"webapps"},
    {"cve_id":"CVE-2021-44228","product":"Apache Log4j 2","description":"Log4Shell JNDI injection leads to RCE. Affects Log4j 2.0-beta9 to 2.14.1.","severity":"critical","cvss":"10.0","category":"webapps"},
    {"cve_id":"CVE-2017-0144","product":"Windows SMB","description":"EternalBlue SMBv1 buffer overflow allows RCE. Used by WannaCry.","severity":"critical","cvss":"9.3","category":"dos"},
    {"cve_id":"CVE-2019-0708","product":"Windows RDP","description":"BlueKeep pre-auth RCE in Remote Desktop Services Windows 7/2008.","severity":"critical","cvss":"9.8","category":"remote"},
    {"cve_id":"CVE-2020-1472","product":"Windows Netlogon","description":"Zerologon privilege escalation to domain admin via Netlogon flaw.","severity":"critical","cvss":"10.0","category":"local"},
    {"cve_id":"CVE-2022-30190","product":"Microsoft MSDT","description":"Follina code execution via ms-msdt URI in Office documents.","severity":"high","cvss":"7.8","category":"webapps"},
    {"cve_id":"CVE-2014-6271","product":"GNU Bash","description":"Shellshock arbitrary code execution via environment variables.","severity":"critical","cvss":"10.0","category":"remote"},
    {"cve_id":"CVE-2017-12617","product":"Apache Tomcat","description":"JSP file upload via PUT method leads to RCE.","severity":"high","cvss":"8.1","category":"webapps"},
    {"cve_id":"CVE-2018-11776","product":"Apache Struts 2","description":"RCE without authentication via namespace value.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2020-0796","product":"Windows SMBv3","description":"SMBGhost buffer overflow in SMBv3 compression allows RCE.","severity":"critical","cvss":"10.0","category":"dos"},
    {"cve_id":"CVE-2021-26855","product":"Microsoft Exchange","description":"ProxyLogon SSRF bypasses authentication leads to RCE.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2022-22965","product":"Spring Framework","description":"Spring4Shell RCE via data binding on JDK9+ Tomcat deployment.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2021-21985","product":"VMware vCenter","description":"RCE via vSphere Client plugin, no authentication required.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2022-1388","product":"F5 BIG-IP","description":"Authentication bypass via iControl REST allows command execution.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2021-22205","product":"GitLab","description":"RCE via image upload ExifTool parsing, no auth required.","severity":"critical","cvss":"10.0","category":"webapps"},
    {"cve_id":"CVE-2021-3156","product":"sudo","description":"Baron Samedit heap overflow in sudo allows privilege escalation to root.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2016-5195","product":"Linux Kernel","description":"Dirty COW race condition allows local privilege escalation.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2022-0847","product":"Linux Kernel","description":"Dirty Pipe write to read-only files via pipe escalation.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2021-4034","product":"Polkit pkexec","description":"PwnKit local privilege escalation to root via memory corruption.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2018-7600","product":"Drupal","description":"Drupalgeddon2 RCE via form API, no authentication required.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2020-14882","product":"Oracle WebLogic","description":"Unauthenticated RCE via HTTP POST console component bypass.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2023-44487","product":"HTTP/2 Protocol","description":"Rapid Reset Attack DDoS via stream cancellation.","severity":"high","cvss":"7.5","category":"dos"},
    {"cve_id":"CVE-2024-3400","product":"Palo Alto PAN-OS","description":"Command injection in GlobalProtect unauthenticated RCE.","severity":"critical","cvss":"10.0","category":"remote"},
    {"cve_id":"CVE-2023-23397","product":"Microsoft Outlook","description":"Zero-click privilege escalation via crafted email.","severity":"critical","cvss":"9.8","category":"local"},
    {"cve_id":"CVE-2019-11580","product":"Atlassian Crowd","description":"RCE via pdkinstall plugin unauthenticated code execution.","severity":"critical","cvss":"9.8","category":"webapps"},
    {"cve_id":"CVE-2020-11651","product":"SaltStack Salt","description":"Authentication bypass in ClearFuncs allows RCE on Salt master.","severity":"critical","cvss":"9.8","category":"remote"},
    {"cve_id":"CVE-2019-17558","product":"Apache Solr","description":"RCE via Velocity template injection exposed configsets endpoint.","severity":"high","cvss":"8.1","category":"webapps"},
    {"cve_id":"CVE-2017-8291","product":"Ghostscript","description":"RCE via -dSAFER bypass crafted PostScript executes shell commands.","severity":"high","cvss":"8.1","category":"webapps"},
    {"cve_id":"CVE-2023-0386","product":"Linux Kernel OverlayFS","description":"Local privilege escalation via setuid files in OverlayFS mount.","severity":"high","cvss":"7.8","category":"local"},
    {"cve_id":"CVE-2019-0232","product":"Apache Tomcat CGI","description":"RCE on Windows via CGI Servlet arguments injection.","severity":"critical","cvss":"8.1","category":"webapps"},
]

def build_text(cve):
    return (f"CVE: {cve['cve_id']} | Product: {cve['product']} | "
            f"Severity: {cve['severity']} | CVSS: {cve['cvss']} | "
            f"{cve['description']}")

def index_builtin():
    print(f"[Indexer] {len(BUILTIN_CVE)} CVEs intégrés...")
    texts = [build_text(c) for c in BUILTIN_CVE]
    vectors = encode(texts)
    points = []
    for cve, vec in zip(BUILTIN_CVE, vectors):
        v = vec.tolist() if hasattr(vec, 'tolist') else list(vec)
        points.append({
            "vector": v,
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

def run_indexing(recreate=False):
    init_collection(recreate=recreate)
    total = index_builtin()
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
    run_indexing(recreate="--recreate" in sys.argv)
