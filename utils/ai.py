"""
cyberm4fia-scanner — AI/LLM Integration (NVIDIA NIM)

NVIDIA NIM-based vulnerability analysis using high-performance Llama 3.3 70B.
Default model: meta/llama-3.3-70b-instruct

Features:
    - Vulnerability analysis & exploit scenario generation
    - False positive detection with confidence scoring
    - Remediation recommendations (developer-friendly)
    - Smart WAF bypass payload generation
    - Executive scan summary

Usage:
    python3 scanner.py -u https://target.com --all --ai
    python3 scanner.py -u https://target.com --all --ai --ai-model mistral
"""

import json
import os
import re
import httpx
from typing import Optional
from utils.colors import log_info, log_success, log_warning, log_error
from utils.request import ScanExceptions
from utils.payload_memory import get_memory

def _extract_json(text: str, expect_array: bool = False):
    """Extract JSON from LLM response that may contain markdown/code blocks."""
    if not text:
        return None

    # Strip markdown code fences (```json ... ``` or ```javascript ... ```)
    cleaned = re.sub(r"```\w*\n?", "", text).strip()
    cleaned = cleaned.strip("`").strip()

    # Try 1: Direct JSON parse
    target = "[" if expect_array else "{"
    end_target = "]" if expect_array else "}"
    start = cleaned.find(target)
    end = cleaned.rfind(end_target)
    if start >= 0 and end > start:
        try:
            return json.loads(cleaned[start : end + 1])
        except json.JSONDecodeError:
            pass

    # Try 2: Extract quoted strings from code (for arrays in JS/Python code)
    if expect_array:
        strings = re.findall(r'"([^"]+)"', cleaned)
        if strings:
            return strings

    return None


# ─── NVIDIA AI Client ───────────────────────────────────────────────────────

def resolve_nvidia_api_key(explicit_key: str | None = None) -> str | None:
    """Resolve NVIDIA API key from explicit value or environment."""
    key = explicit_key or os.environ.get("NVIDIA_API_KEY")
    if key:
        return key.strip()
    return None

def resolve_nvidia_base() -> str:
    """Return the NVIDIA NIM API base URL."""
    return os.environ.get("NVIDIA_API_URL", "https://integrate.api.nvidia.com/v1")

DEFAULT_MODEL = "meta/llama-3.3-70b-instruct"
CODER_MODEL = "meta/llama-3.3-70b-instruct" # Using 70B for both as it is high performance

# Model roles — which model to use for which task
MODEL_ROLES = {
    "exploit": DEFAULT_MODEL,  # payload crafting, WAF bypass, exploit strategy
    "analysis": DEFAULT_MODEL,  # vuln analysis, false positive detection
    "code": CODER_MODEL,  # PoC script generation, code analysis
    "remediation": CODER_MODEL,  # code fix generation, secure code examples
    "summary": DEFAULT_MODEL,  # executive summary, reporting
}

class NvidiaApiClient:
    """Client for NVIDIA NIM (OpenAI-compatible) API."""

    def __init__(self, model: Optional[str] = None, api_key: Optional[str] = None, quiet: bool = False):
        self.model = model or DEFAULT_MODEL
        self.api_key = resolve_nvidia_api_key(api_key)
        self.base_url = resolve_nvidia_base()
        self.quiet = quiet
        self.available = False
        self._check_connection()

    def _check_connection(self):
        """Check if API key is present and reachable."""
        if not self.api_key:
            if not getattr(self, "quiet", False):
                log_warning("NVIDIA_API_KEY not set. AI features disabled.")
            self.available = False
            return

        try:
            # Simple list models check to verify connectivity/auth
            resp = httpx.get(
                f"{self.base_url}/models",
                headers={"Authorization": f"Bearer {self.api_key}"},
                timeout=5
            )
            if resp.status_code == 200:
                self.available = True
                if not getattr(self, "quiet", False):
                    log_success(f"AI Engine: NVIDIA NIM ({self.model}) ✓")
            else:
                log_warning(f"NVIDIA API auth failed (status {resp.status_code})")
                self.available = False
        except Exception:
            self.available = False
            if not getattr(self, "quiet", False):
                log_warning("NVIDIA API not reachable. Check your connection.")

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3,
                  model_role: str = "") -> str:
        """Generate a response from NVIDIA NIM using Chat Completions API."""
        if not self.available or not self.api_key:
            return ""

        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "messages": messages,
                "temperature": temperature,
                "top_p": 1,
                "max_tokens": 4096,
                "stream": False
            }

            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                headers={"Authorization": f"Bearer {self.api_key}"},
                json=payload,
                timeout=180,
            )

            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"].strip()
                return content
            else:
                log_error(f"NVIDIA API error: {resp.status_code} - {resp.text}")
                return ""
        except httpx.TimeoutException:
            log_warning("AI response timed out (180s)")
            return ""
        except Exception as e:
            log_warning(f"AI error: {e}")
            return ""

# ─── Dual-Model AI System ──────────────────────────────────────────────────

class DualModelAI:
    """Dual-model AI system using NVIDIA NIM.
    
    Even if using the same model, we can split them into separate clients 
    for better logical routing and potential future model variations.
    """

    def __init__(self, api_key: str = None):
        self.api_key = resolve_nvidia_api_key(api_key)
        self.exploit_client: NvidiaApiClient | None = None
        self.coder_client: NvidiaApiClient | None = None
        self._init_models()

    def _init_models(self):
        """Initialize both model clients."""
        if not self.api_key:
            return

        self.exploit_client = NvidiaApiClient(
            model=DEFAULT_MODEL, api_key=self.api_key, quiet=True
        )
        self.coder_client = NvidiaApiClient(
            model=CODER_MODEL, api_key=self.api_key, quiet=True
        )

        if self.available:
            log_success(f"Dual AI: NVIDIA Llama-3.1-70B (Exploit + Code)")

    @property
    def available(self) -> bool:
        """True if at least one client is available."""
        return bool(
            (self.exploit_client and self.exploit_client.available)
            or (self.coder_client and self.coder_client.available)
        )

    def get_client_for_role(self, role: str) -> NvidiaApiClient | None:
        """Get the client for a given role."""
        if role in ["code", "remediation"]:
            return self.coder_client or self.exploit_client
        return self.exploit_client or self.coder_client

    def generate(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        model_role: str = "exploit",
    ) -> str:
        """Generate using the appropriate model for the role."""
        client = self.get_client_for_role(model_role)
        if not client:
            return ""
        return client.generate(prompt, system=system, temperature=temperature)

# ─── Security Analysis Prompts ──────────────────────────────────────────────

SECURITY_SYSTEM_PROMPT = """You are a senior penetration tester and cybersecurity expert.
You analyze vulnerability scan results with precision and provide actionable insights.
Be concise, technical, and direct. Use bullet points.
Always respond in the language of the user's input."""

def _load_skill_for_vuln(vuln_type: str) -> str:
    """Load Claude-Red skill instructions based on vulnerability type."""
    if not vuln_type:
        return ""
        
    vuln_type_lower = vuln_type.lower()
    
    # Mapping vulnerability types to Claude-Red skill folder names
    mapping = {
        "sqli": "offensive-sqli",
        "sql_injection": "offensive-sqli",
        "sql": "offensive-sqli",
        "xss": "offensive-xss",
        "cross_site_scripting": "offensive-xss",
        "ssrf": "offensive-ssrf",
        "lfi": "offensive-rce",
        "local_file_inclusion": "offensive-rce",
        "cmdi": "offensive-rce",
        "command_injection": "offensive-rce",
        "rce": "offensive-rce",
        "jwt": "offensive-jwt",
        "xxe": "offensive-xxe",
        "ssti": "offensive-ssti",
        "idor": "offensive-idor",
        "open_redirect": "offensive-open-redirect",
        "smuggling": "offensive-request-smuggling",
        "request_smuggling": "offensive-request-smuggling",
        "waf": "offensive-waf-bypass",
    }
    
    skill_folder = None
    for key, folder in mapping.items():
        if key in vuln_type_lower:
            skill_folder = folder
            break
            
    if not skill_folder:
        return ""
        
    try:
        skill_path = os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "core", "ai_skills", skill_folder, "SKILL.md"
        )
        if os.path.exists(skill_path):
            with open(skill_path, "r", encoding="utf-8") as f:
                content = f.read()
                return f"\n\n--- EXPERT SKILL KNOWLEDGE BASE ---\n{content}\n--- END SKILL KNOWLEDGE BASE ---\n"
    except Exception:
        pass
        
    return ""

def analyze_vulnerability(client: NvidiaApiClient, vuln: dict) -> dict:
    """Analyze a single vulnerability finding with AI."""
    if not client.available:
        return {}

    vuln_type = vuln.get("type", "Unknown")
    payload = vuln.get("payload", "N/A")
    url = vuln.get("url", "N/A")
    field = vuln.get("field", vuln.get("param", "N/A"))

    prompt = f"""Analyze this vulnerability finding:

Type: {vuln_type}
URL: {url}
Parameter/Field: {field}
Payload: {payload}"""

    # Add payload memory context if applicable
    memory = get_memory()
    mem_ctx = memory.get_context_for_ai(vuln_type=vuln_type, max_entries=3)
    if mem_ctx:
        prompt += f"\n\nContext based on past success for this vuln type:\n{mem_ctx}"

    prompt += """

Provide:
1. **Risk Assessment**: How critical is this? (Critical/High/Medium/Low)
2. **Attack Scenario**: How can an attacker exploit this? (2-3 sentences)
3. **False Positive Check**: Is this likely a real vulnerability or false positive? (confidence %)
4. **Remediation**: How to fix this? (specific code-level fix)
5. **CVSS Justification**: Why this severity rating?

Respond in JSON format:
{{"risk": "...", "scenario": "...", "confidence": 85, "remediation": "...", "cvss_note": "..."}}"""

    # Inject Red Team Skill context if available
    system_prompt = SECURITY_SYSTEM_PROMPT + _load_skill_for_vuln(vuln_type)

    response = client.generate(prompt, system=system_prompt, model_role="analysis")

    result = _extract_json(response, expect_array=False)
    if result and isinstance(result, dict):
        return result

    return {"raw_analysis": response}

def detect_false_positives(client: NvidiaApiClient, vulns: list) -> list:
    """Filter likely false positives from vulnerability list."""
    if not client.available or not vulns:
        return vulns

    log_info(
        f"AI analyzing {len(vulns)} findings for false positives "
        f"(filtering Low/Info issues)..."
    )

    verified = []

    # We don't need AI to verify missing headers or debug info over and over
    skip_types = ["Missing_Security_Header", "Debug_Info", "Tech_Fingerprint", "Recon"]

    for vuln in vulns:
        vuln_type = vuln.get("type", "")
        payload = vuln.get("payload", "")
        url = vuln.get("url", "")
        severity = str(vuln.get("severity", "")).strip().lower()

        if vuln_type in skip_types or severity in {"low", "info"}:
            verified.append(vuln)
            continue

        prompt = f"""Is this a real vulnerability or likely a false positive?

Type: {vuln_type}
URL: {url}
Payload: {payload}

Answer ONLY with a JSON: {{"real": true/false, "confidence": 0-100, "reason": "..."}}"""

        response = client.generate(
            prompt, system=SECURITY_SYSTEM_PROMPT, temperature=0.1,
            model_role="analysis",
        )

        result = _extract_json(response, expect_array=False)
        if result and isinstance(result, dict):
            vuln["ai_verified"] = result.get("real", True)
            vuln["ai_confidence"] = result.get("confidence", 50)
            vuln["ai_reason"] = result.get("reason", "")

            if result.get("real", True):
                verified.append(vuln)
            else:
                log_info(
                    f"  ⚠ Filtered: {vuln_type} "
                    f"(confidence: {result.get('confidence', '?')}% — "
                    f"{result.get('reason', 'N/A')})"
                )
            continue

        # If AI can't decide, keep the finding
        verified.append(vuln)

    removed = len(vulns) - len(verified)
    if removed:
        log_success(f"AI removed {removed} likely false positive(s)")

    return verified

def generate_remediation(client: NvidiaApiClient, vulns: list) -> list:
    """Generate remediation recommendations for each vulnerability."""
    if not client.available or not vulns:
        return []

    # Use coder model for remediation if available (better code generation)
    dual = get_dual_ai()
    if dual and dual.available:
        coder = dual.get_client_for_role("remediation")
        if coder and coder.available:
            client = coder

    # We don't need AI to verify missing headers or debug info over and over
    skip_types = ["Missing_Security_Header", "Debug_Info", "Tech_Fingerprint", "Recon"]
    filtered_vulns = [
        v
        for v in vulns
        if v.get("type") not in skip_types
        and v.get("severity", "Info") not in ["Low", "Info"]
    ]

    if not filtered_vulns:
        return []

    log_info(
        f"AI generating remediation recommendations for {len(filtered_vulns)} findings..."
    )

    remediations = []
    # Group by vulnerability type to avoid redundant AI calls and timeouts
    vulns_by_type = {}
    for vuln in filtered_vulns:
        v_type = vuln.get("type", "Unknown")
        if v_type not in vulns_by_type:
            vulns_by_type[v_type] = []
        vulns_by_type[v_type].append(vuln)

    for vuln_type, type_vulns in vulns_by_type.items():
        # Use the first one as representative
        rep_vuln = type_vulns[0]
        url = rep_vuln.get("url", "N/A")
        payload = rep_vuln.get("payload", "N/A")

        prompt = f"""Generate a specific remediation for this vulnerability:

Type: {vuln_type}
Example URL: {url}
Example Payload used: {payload}

Provide:
1. **Quick Fix**: Immediate mitigation (1 line)
2. **Code Fix**: Example secure code snippet
3. **Best Practice**: Long-term architectural recommendation

Be specific and developer-friendly. Include code examples."""

        response = client.generate(prompt, system=SECURITY_SYSTEM_PROMPT,
                                    model_role="remediation")
        
        # Apply the same remediation to all vulnerabilities of this type
        for v in type_vulns:
            remediations.append(
                {
                    "vuln_type": vuln_type,
                    "url": v.get("url", "N/A"),
                    "remediation": response,
                }
            )

    return remediations

def generate_smart_payloads(
    client: NvidiaApiClient, vuln_type: str, context: str = ""
) -> list:
    """Generate smart WAF bypass payloads using AI."""
    if not client.available:
        return []

    prompt = f"""Generate 5 advanced WAF bypass payloads for {vuln_type}.

Context: {context or "Standard web application with WAF"}

Requirements:
- Each payload must be unique and creative
- Use encoding tricks, case manipulation, comment injection
- Target common WAF bypass techniques
- Return ONLY a JSON array of payload strings

Example format: ["payload1", "payload2", "payload3"]"""

    system_prompt = SECURITY_SYSTEM_PROMPT + _load_skill_for_vuln("waf") + _load_skill_for_vuln(vuln_type)

    response = client.generate(prompt, system=system_prompt, temperature=0.7,
                                model_role="exploit")

    result = _extract_json(response, expect_array=True)
    if result and isinstance(result, list):
        return [str(p) for p in result[:10]]

    return []

class EvolvingWAFBypassEngine:
    """Stateful AI Mutation Engine for bypassing advanced HTTP WAFs."""

    def __init__(self, client: NvidiaApiClient, waf_name: str, vuln_type: str):
        self.client = client
        self.waf_name = waf_name
        self.vuln_type = vuln_type
        self.failed_attempts = []
        self.known_bad_tokens = set()

    def tokenize_payload(self, payload: str) -> list:
        """Splits an injection payload into logical semantic tokens."""
        # Split on common SQL/XSS delimiters (spaces, tags, quotes)
        tokens = re.split(r"(<[^>]+>|[\'\"(\s)])", payload)
        return [t.strip() for t in tokens if t and t.strip()]

    def analyze_failure(self, failed_payload: str):
        """Records a failure and deduces the exact WAF regex signature."""
        self.failed_attempts.append(failed_payload)
        tokens = self.tokenize_payload(failed_payload)

        # If a single keyword is always present in failures, mark it bad
        for token in set(tokens):
            if len(token) > 3 and token.lower() in failed_payload.lower():
                self.known_bad_tokens.add(token.lower())

    def mutate(self, blocked_payload: str, iteration: int = 1) -> list:
        """Generates pinpoint AI variations based on exact failure context."""
        if not self.client or not self.client.available:
            return []

        context = f"A strict {self.waf_name} firewall repeatedly blocked this {self.vuln_type} payload: `{blocked_payload}`\n"

        if self.failed_attempts and iteration > 1:
            context += "\nPrevious failed bypasses:\n" + "\n".join(
                f"- {p}" for p in self.failed_attempts[-3:]
            )
            if self.known_bad_tokens:
                context += f"\n\nThe WAF seems to be specifically filtering these tokens: {list(self.known_bad_tokens)[-5:]}\n"
                context += "DO NOT use these exact tokens. Use semantic alternatives (e.g. svg instead of script, HEX instead of CHAR)."

        prompt = f"""{context}
Generate exactly 5 advanced, highly mutated alternative payloads that bypass {self.waf_name}.

Required techniques:
- String assembly (e.g. 'se'+'lect', CHAR() encoding)
- Obscure functions or tags (e.g. HANDLER, JSON_KEYS, <math>, <svg>)
- Comment injection breaking (e.g. /*!50000SELECT*/, /**/)
- Encoding boundaries (e.g. URL, HEX, Unicode)

Return ONLY a valid JSON array of 5 payload strings. No explanation, no markdown.
Example: ["bypass1", "bypass2", "bypass3", "bypass4", "bypass5"]"""

        try:
            system_prompt = "You are an expert WAF mutation engine. Generate only working payloads. Return raw JSON arrays only."
            system_prompt += _load_skill_for_vuln("waf") + _load_skill_for_vuln(self.vuln_type)
            
            response = self.client.generate(
                prompt,
                system=system_prompt,
                temperature=0.7 + (iteration * 0.1),  # Increase creativity if stuck
            )
            result = _extract_json(response, expect_array=True)
            if result and isinstance(result, list):
                payloads = [str(p).strip() for p in result if p and str(p).strip()]
                return payloads[:5]
        except ScanExceptions:
            pass

        return []

def generate_waf_bypass(
    client: NvidiaApiClient,
    waf_name: str,
    blocked_payload: str,
    vuln_type: str,
    param_name: str = "",
) -> list:
    """Helper wrapper around Evolutionary Engine for single-shot generation."""
    engine = EvolvingWAFBypassEngine(client, waf_name, vuln_type)
    return engine.mutate(blocked_payload, iteration=1)

def generate_scan_summary(
    client: NvidiaApiClient, vulns: list, target: str, stats: dict
) -> str:
    """Generate an executive summary of scan results."""
    if not client.available:
        return ""

    # Categorize findings
    severity_counts = {}
    type_counts = {}
    for v in vulns:
        sev = v.get("severity", "unknown")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        vtype = v.get("type", "Unknown")
        type_counts[vtype] = type_counts.get(vtype, 0) + 1

    prompt = f"""Generate a professional executive summary for this security scan:

Target: {target}
Total Findings: {len(vulns)}
Severity Distribution: {json.dumps(severity_counts)}
Vulnerability Types: {json.dumps(type_counts)}
Requests Made: {stats.get("requests", 0)}
WAF Blocks: {stats.get("waf", 0)}

Write a 3-paragraph executive summary:
1. **Overview**: What was scanned and key findings
2. **Critical Issues**: Most dangerous vulnerabilities and their impact
3. **Recommendations**: Top 3 priority actions

Keep it professional and suitable for a C-level audience."""

    return client.generate(prompt, system=SECURITY_SYSTEM_PROMPT, model_role="summary")

# ─── Global Clients ─────────────────────────────────────────────────────────

_ai_client = None
_dual_ai = None

def init_ai(
    model: Optional[str] = None,
    api_key: Optional[str] = None,
) -> NvidiaApiClient:
    """Initialize the primary AI client."""
    global _ai_client
    _ai_client = NvidiaApiClient(model=model, api_key=api_key)
    return _ai_client

def get_ai(api_key: Optional[str] = None) -> NvidiaApiClient:
    """Get the current primary AI client (or create one)."""
    global _ai_client
    if _ai_client is None:
        _ai_client = NvidiaApiClient(api_key=api_key)
    return _ai_client

def init_dual_ai(api_key: Optional[str] = None) -> DualModelAI:
    """Initialize the dual-model AI system."""
    global _dual_ai
    _dual_ai = DualModelAI(api_key=api_key)
    return _dual_ai

def get_dual_ai() -> DualModelAI | None:
    """Get the dual-model AI system (if initialized)."""
    return _dual_ai
