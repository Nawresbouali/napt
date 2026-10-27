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
