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
