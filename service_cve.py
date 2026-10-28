# Correspondance deterministe service -> CVE (empreinte de service).
# Approche type Nessus / OpenVAS : pour les services connus exploitables, on
# selectionne la CVE directement a partir de la banniere Nmap, sans dependre
# du seuil de similarite vectorielle. Le RAG flou reste utilise en second
# recours pour les services inconnus.

SERVICE_CVE = [
    # (mot-cle cherche dans la banniere "service version", infos CVE)
    ("redis", {
        "cve_id": "CVE-2022-0543", "cvss": "10.0", "severity": "critical",
        "text": "Redis key-value store Lua sandbox escape remote code execution (CVE-2022-0543).",
    }),
    ("vsftpd 2.3.4", {
        "cve_id": "CVE-2011-2523", "cvss": "10.0", "severity": "critical",
        "text": "vsftpd 2.3.4 backdoor command execution, root shell (CVE-2011-2523).",
    }),
    ("unreal", {
        "cve_id": "CVE-2010-2075", "cvss": "10.0", "severity": "critical",
        "text": "UnrealIRCd 3.2.8.1 backdoor remote code execution (CVE-2010-2075).",
    }),
    ("smbd 3.0", {
        "cve_id": "CVE-2007-2447", "cvss": "9.8", "severity": "critical",
        "text": "Samba 3.0.x username map script command injection (CVE-2007-2447).",
    }),
]


def match_service_cve(service, version):
    """Retourne la CVE connue si la banniere contient une empreinte de service
    connue, sinon None (on retombe alors sur le RAG vectoriel)."""
    banner = f"{service} {version}".lower()
    for keyword, info in SERVICE_CVE:
        if keyword in banner:
            return info
    return None
