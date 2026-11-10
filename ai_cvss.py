import json, re


def evaluate_cvss(llm_call, host, ports, cve_id, summary, fallback_cvss, fallback_sev):
    """Fait evaluer le CVSS v3.1 par Gemma (repond au reproche #1 de l'encadreur)."""
    svc_str = ", ".join(p["service"] + " " + p["version"] for p in ports) if ports else "inconnu"
    system = (
        "Tu es un expert CVSS v3.1. Evalue toi-meme la vulnerabilite et calcule un score "
        "CVSS v3.1. Reponds UNIQUEMENT en JSON valide, sans markdown, avec exactement ces "
        "cles: cvss_vector, cvss_score (nombre 0 a 10), severity "
        "(none/low/medium/high/critical), vecteur_attaque, impact, justification, "
        "remediation. Les valeurs texte en francais."
    )
    user = (
        f"Service detecte: {svc_str}\n"
        f"CVE associee: {cve_id}\n"
        f"Description: {summary[:400]}\n"
        f"Cible: {host}\n\n"
        "Donne ton evaluation CVSS v3.1 au format JSON."
    )
    raw = llm_call(system, user)
    result = {"cvss": fallback_cvss, "severity": fallback_sev, "cvss_vector": "",
              "analysis": raw, "parsed": False}
    try:
        clean = raw.strip().replace("```json", "").replace("```", "")
        m = re.search(r"\{.*\}", clean, re.DOTALL)
        if m:
            d = json.loads(m.group(0))
            result["cvss"] = str(d.get("cvss_score", fallback_cvss))
            result["severity"] = str(d.get("severity", fallback_sev)).lower()
            result["cvss_vector"] = d.get("cvss_vector", "")
            result["parsed"] = True
            result["analysis"] = (
                f"CVSS evalue par Gemma : {result['cvss']} ({result['severity'].upper()})\n"
                f"Vecteur CVSS : {result['cvss_vector']}\n"
                f"Vecteur d'attaque : {d.get('vecteur_attaque', '')}\n"
                f"Impact : {d.get('impact', '')}\n"
                f"Justification : {d.get('justification', '')}\n"
                f"Remediation : {d.get('remediation', '')}"
            )
    except Exception as e:
        result["analysis"] = raw + f"\n(JSON non parse : {e})"
    return result
