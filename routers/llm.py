import httpx, os
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from auth import get_current_user

router = APIRouter(prefix="/api/llm", tags=["llm"])

OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
MODEL = "meta-llama/llama-3.1-8b-instruct:free"
API_KEY = os.getenv("OPENROUTER_API_KEY", "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").strip()

HEADERS = {
    "Authorization": f"Bearer {API_KEY}",
    "Content-Type": "application/json",
    "HTTP-Referer": "http://localhost:5173",
    "X-Title": "N.A.P.T"
}

class LLMRequest(BaseModel):
    prompt: str
    cve_id: str = ""

async def call_gemma(system: str, user_msg: str) -> str:
    async with httpx.AsyncClient(timeout=60, verify=False) as client:
        resp = await client.post(OPENROUTER_URL, headers=HEADERS, json={
            "model": MODEL,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user_msg}
            ]
        })
        result = resp.json()
        if "error" in result:
            raise Exception(result["error"].get("message", "OpenRouter error"))
        return result["choices"][0]["message"]["content"]

@router.post("/analyze")
async def analyze_cve(data: LLMRequest, _=Depends(get_current_user)):
    system = (
        "You are N.A.P.T, an autonomous penetration testing AI assistant. "
        "Analyze CVEs and provide: 1) Attack vector 2) Impact 3) Remediation steps. "
        "Be concise and technical."
    )
    user_msg = f"CVE: {data.cve_id}\n{data.prompt}"
    try:
        response = await call_gemma(system, user_msg)
        return {"model": "gemma-4-31b", "cve_id": data.cve_id, "response": response, "done": True}
    except Exception as e:
        raise HTTPException(500, f"Gemma error: {e}")

@router.get("/models")
async def list_models(_=Depends(get_current_user)):
    return {"models": [{"name": "gemma-4-31b", "provider": "OpenRouter"}]}

@router.post("/chat")
async def chat(data: dict, _=Depends(get_current_user)):
    message = data.get("message", "")
    system = (
        "You are N.A.P.T, an AI assistant specialized in cybersecurity. "
        "Answer questions about vulnerabilities, CVEs, penetration testing, and security best practices. "
        "Be concise, technical, and helpful. Respond in the same language as the user."
    )
    try:
        response = await call_gemma(system, message)
        return {"response": response}
    except Exception as e:
        raise HTTPException(500, f"Gemma error: {e}")
