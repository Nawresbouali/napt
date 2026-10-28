# Mapping deterministe CVE -> module Metasploit (exploitation fiable, reproche #2)
CVE_TO_MSF = {
    "CVE-2017-7494": {"module": "exploit/linux/samba/is_known_pipename", "rport": 445},
    "CVE-2014-6271": {"module": "exploit/multi/http/apache_mod_cgi_bash_env_exec", "rport": 80},
    "CVE-2017-5638": {"module": "exploit/multi/http/struts2_content_type_ognl", "rport": 8080},
    "CVE-2018-7600": {"module": "exploit/unix/webapp/drupal_drupalgeddon2", "rport": 80},
    "CVE-2021-44228": {"module": "exploit/multi/http/log4shell_header_injection", "rport": 8080},
    "CVE-2017-0144": {"module": "exploit/windows/smb/ms17_010_eternalblue", "rport": 445},
    "CVE-2019-0708": {"module": "exploit/windows/rdp/cve_2019_0708_bluekeep_rce", "rport": 3389},

    # --- Cibles de validation supplementaires (plan de test PFE) ---
    # Redis (Vulhub CVE-2022-0543) : evasion du bac a sable Lua -> RCE
    "CVE-2022-0543": {"module": "exploit/linux/redis/redis_debian_sandbox_escape", "rport": 6379},
    # Metasploitable 2 : vsftpd 2.3.4 (backdoor auto, shell root sans payload)
    "CVE-2011-2523": {"module": "exploit/unix/ftp/vsftpd_234_backdoor", "rport": 21},
    # Metasploitable 2 : UnrealIRCd 3.2.8.1 (backdoor)
    "CVE-2010-2075": {"module": "exploit/unix/irc/unreal_ircd_3281_backdoor", "rport": 6667,
                      "payload": "cmd/unix/bind_perl"},
    # Metasploitable 2 : Samba 3.0.20 "username map script"
    "CVE-2007-2447": {"module": "exploit/multi/samba/usermap_script", "rport": 139,
                      "payload": "cmd/unix/bind_netcat"},
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


def get_msf_payload(cve_id):
    """Payload specifique a definir pour ce module (None = payload par defaut du module)."""
    entry = CVE_TO_MSF.get(cve_id)
    return entry.get("payload") if entry else None
