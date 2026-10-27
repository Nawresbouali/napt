from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from fastembed import TextEmbedding
import uuid

client = QdrantClient("localhost", port=6333)
embedder = TextEmbedding()

cves = [
    {"id": "CVE-2017-0144", "desc": "SMB EternalBlue RCE Windows", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2017-0145", "desc": "SMB EternalRomance RCE Windows", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2008-4250", "desc": "SMB MS08-067 RCE Windows XP", "cvss": 10.0, "severity": "critique"},
    {"id": "CVE-2020-0796", "desc": "SMBGhost SMB v3 RCE Windows 10", "cvss": 10.0, "severity": "critique"},
    {"id": "CVE-2019-0708", "desc": "BlueKeep RDP RCE Windows", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2016-0778", "desc": "OpenSSH buffer overflow RCE", "cvss": 8.1, "severity": "elevee"},
    {"id": "CVE-2016-6210", "desc": "OpenSSH user enumeration timing attack", "cvss": 5.9, "severity": "moyenne"},
    {"id": "CVE-2018-15473", "desc": "OpenSSH username enumeration", "cvss": 5.3, "severity": "moyenne"},
    {"id": "CVE-2017-7679", "desc": "Apache httpd mod_mime buffer overflow", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2017-9798", "desc": "Apache Optionsbleed memory leak", "cvss": 7.5, "severity": "elevee"},
    {"id": "CVE-2021-41773", "desc": "Apache path traversal RCE 2.4.49", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2021-42013", "desc": "Apache path traversal RCE 2.4.50", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2014-0160", "desc": "OpenSSL Heartbleed memory disclosure", "cvss": 7.5, "severity": "elevee"},
    {"id": "CVE-2016-2107", "desc": "OpenSSL AES-NI padding oracle", "cvss": 5.9, "severity": "moyenne"},
    {"id": "CVE-2014-6271", "desc": "Bash Shellshock RCE CGI", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2015-5477", "desc": "BIND9 DNS TKEY assertion DoS", "cvss": 7.5, "severity": "elevee"},
    {"id": "CVE-2012-1823", "desc": "PHP-CGI RCE argument injection", "cvss": 7.5, "severity": "elevee"},
    {"id": "CVE-2019-11043", "desc": "PHP-FPM nginx RCE", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2017-5638", "desc": "Apache Struts2 RCE Content-Type", "cvss": 10.0, "severity": "critique"},
    {"id": "CVE-2018-11776", "desc": "Apache Struts2 namespace RCE", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2010-0738", "desc": "JBoss authentication bypass RCE", "cvss": 7.5, "severity": "elevee"},
    {"id": "CVE-2020-1938", "desc": "Apache Tomcat Ghostcat AJP RCE", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2019-0232", "desc": "Apache Tomcat CGI RCE Windows", "cvss": 8.1, "severity": "elevee"},
    {"id": "CVE-2021-21985", "desc": "VMware vCenter RCE plugin", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2021-26084", "desc": "Confluence OGNL injection RCE", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2022-22965", "desc": "Spring4Shell Spring Framework RCE", "cvss": 9.8, "severity": "critique"},
    {"id": "CVE-2021-44228", "desc": "Log4Shell Log4j JNDI RCE", "cvss": 10.0, "severity": "critique"},
    {"id": "CVE-2022-0847", "desc": "Linux Dirty Pipe kernel privilege escalation", "cvss": 7.8, "severity": "elevee"},
    {"id": "CVE-2021-3156", "desc": "sudo Baron Samedit privilege escalation", "cvss": 7.8, "severity": "elevee"},
    {"id": "CVE-2016-5195", "desc": "Linux Dirty COW kernel privilege escalation", "cvss": 7.8, "severity": "elevee"},
]

# Create collection
try:
    client.recreate_collection(
        collection_name="cve_collection",
        vectors_config=VectorParams(size=384, distance=Distance.COSINE)
    )
    print("Collection créée")
except:
    client.create_collection(
        collection_name="cve_collection",
        vectors_config=VectorParams(size=384, distance=Distance.COSINE)
    )

points = []
for i, cve in enumerate(cves):
    vec = list(embedder.embed([cve["desc"]]))[0].tolist()
    points.append(PointStruct(
        id=i+1,
        vector=vec,
        payload={"cve_id": cve["id"], "description": cve["desc"], "cvss": cve["cvss"], "severity": cve["severity"]}
    ))

client.upsert(collection_name="cve_collection", points=points)
print(f"✅ {len(cves)} CVEs indexées dans Qdrant")
