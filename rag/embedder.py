from fastembed import TextEmbedding
import numpy as np

# Modèle supporté par fastembed avec dimension 768
MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"
DIMENSION  = 768

_model = None

def get_model():
    global _model
    if _model is None:
        # Lister les modèles disponibles pour debug
        models = TextEmbedding.list_supported_models()
        mpnet = [m for m in models if "mpnet" in m.get("model","").lower()]
        if mpnet:
            name = mpnet[0]["model"]
        else:
            # Fallback : BAAI/bge-base-en-v1.5 (768-dim aussi)
            name = "BAAI/bge-base-en-v1.5"
        print(f"[RAG] Chargement {name}...")
        _model = TextEmbedding(name)
        global MODEL_NAME
        MODEL_NAME = name
        print(f"[RAG] Modèle chargé — dim={DIMENSION}")
    return _model

def encode(texts: list) -> list:
    model = get_model()
    return list(model.embed(texts))

def encode_query(query: str) -> list:
    model = get_model()
    return list(model.embed([query]))[0].tolist()

if __name__ == "__main__":
    print("Modèles 768-dim disponibles:")
    for m in TextEmbedding.list_supported_models():
        if m.get("dim", 0) == 768:
            print(f"  - {m['model']} (dim={m['dim']})")
