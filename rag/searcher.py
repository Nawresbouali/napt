from fastembed import TextEmbedding

_embedder = None
def get_embedder():
    global _embedder
    if _embedder is None:
        _embedder = TextEmbedding()
    return _embedder

def rag_search(query: str, limit: int = 5, category: str = None) -> list[dict]:
    embedder = get_embedder()
    vec = list(embedder.embed([query]))[0].tolist()
    from qdrant_client import QdrantClient
    client = QdrantClient("localhost", port=6333)
    results = client.search(
        collection_name="cve_collection",
        query_vector=vec,
        limit=limit,
        with_payload=True
    )
    return [{"score": r.score, "cve_id": r.payload.get("cve_id",""), "description": r.payload.get("description",""), "cvss": r.payload.get("cvss",0), "severity": r.payload.get("severity","")} for r in results]

def find_cve_for_service(service: str, version: str = "", limit: int = 3) -> list[dict]:
    return rag_search(f"{service} {version} exploit vulnerability", limit=limit)

def collection_stats():
    return {}
