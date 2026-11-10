from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue
import os, uuid

COLLECTION = "pentest_rag"
DIMENSION  = 768
DB_PATH    = os.path.join(os.path.dirname(__file__), "..", "qdrant_db")

import threading
_client = None
_client_lock = threading.Lock()

def get_client():
    global _client
    with _client_lock:
        if _client is None:
            os.makedirs(DB_PATH, exist_ok=True)
            _client = QdrantClient(path=DB_PATH)
        return _client

def init_collection(recreate=False):
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

def upsert_batch(points, batch_size=100):
    client = get_client()
    structs = [
        PointStruct(
            id=str(uuid.uuid5(uuid.NAMESPACE_DNS, p["text"][:64])),
            vector=p["vector"],
            payload={k: v for k, v in p.items() if k != "vector"}
        )
        for p in points
    ]
    for i in range(0, len(structs), batch_size):
        client.upsert(collection_name=COLLECTION, points=structs[i:i+batch_size])
    return len(structs)

def search(query_vector, limit=5, filter_cat=None):
    from qdrant_client.models import QueryRequest
    client = get_client()
    qfilter = None
    if filter_cat:
        qfilter = Filter(must=[FieldCondition(key="category", match=MatchValue(value=filter_cat))])
    results = client.query_points(
        collection_name=COLLECTION,
        query=query_vector,
        limit=limit,
        query_filter=qfilter,
        with_payload=True
    ).points
    return [{"score": r.score, **r.payload} for r in results]

def collection_stats():
    client = get_client()
    info = client.get_collection(COLLECTION)
    return {
        "status": str(info.status),
        "vectors_count": info.points_count,
        "dimension": DIMENSION,
        "distance": "Cosine",
        "model": "all-mpnet-base-v2"
    }
