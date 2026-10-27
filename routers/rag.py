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
        import requests
        r = requests.get("http://localhost:6333/collections/cve_collection", timeout=5)
        data = r.json()
        count = data.get("result", {}).get("points_count", 0)
        return {"status": "ok", "collection": "cve_collection", "vectors_count": count, "points_count": count, "dimension": 384, "distance": "Cosine", "model": "BAAI/bge-small-en-v1.5"}
    except Exception as e:
        raise HTTPException(500, f"Stats error: {e}")

@router.get("/cve/{service}")
def cve_for_service(service: str, version: str = "", _=Depends(get_current_user)):
    try:
        from searcher import find_cve_for_service
        return {"cves": find_cve_for_service(service, version)}
    except Exception as e:
        raise HTTPException(500, f"CVE lookup error: {e}")
