# Mapping deterministe CVE -> module Metasploit (exploitation fiable, reproche #2)
CVE_TO_MSF = {
    "CVE-2017-7494": {"module": "exploit/linux/samba/is_known_pipename", "rport": 445},
    "CVE-2014-6271": {"module": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "rport": 80},
    "CVE-2017-5638": {"module": "exploit/multi/http/struts2_content_type_ognl", "rport": 8080},
    "CVE-2018-7600": {"module": "exploit/unix/webapp/drupal_drupalgeddon2", "rport": 80},
    "CVE-2021-44228": {"module": "exploit/multi/http/log4shell_header_injection", "rport": 8080},
    "CVE-2017-0144": {"module": "exploit/windows/smb/ms17_010_eternalblue", "rport": 445},
    "CVE-2019-0708": {"module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "rport": 3389},
}


def get_msf_module(cve_id, llm_call=None, context=""):
    """Choisit le module Metasploit : 1) mapping fiable, 2) sinon suggestion LLM validee."""
    if cve_id in CVE_TO_MSF:
        return CVE_TO_MSF[cve_id]["module"], CVE_TO_MSF[cve_id].get("rport"), "mapping"
    if llm_call:
        raw = llm_call(
            "You are a Metasploit expert. Reply with ONLY the module path, nothing else.",
            f"CVE: {cve_id}. {context}. Give the best Metasploit module path.",
        ).strip().split("\n")[0].strip().replace("`", "").replace('"', "")
        if raw.startswith("exploit/") or raw.startswith("auxiliary/"):
            return raw, None, "llm"
    return None, None, "none"
