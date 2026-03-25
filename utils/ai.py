"""
cyberm4fia-scanner — AI/LLM Integration (Ollama)

Ollama-based vulnerability analysis using local LLM models.
Default model: whiterabbitneo (purpose-built for cybersecurity & pentesting)

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


# ─── Ollama Client ──────────────────────────────────────────────────────────


def resolve_ollama_base(explicit_url: str | None = None) -> str:
    """Resolve Ollama base URL from explicit value or environment."""
    raw = (
        explicit_url
        or os.environ.get("OLLAMA_URL")
        or os.environ.get("OLLAMA_HOST")
        or "http://127.0.0.1:11434"
    )
    raw = str(raw).strip()
    if not raw:
        return "http://127.0.0.1:11434"
    if raw.startswith(("http://", "https://")):
        return raw.rstrip("/")
    return f"http://{raw.rstrip('/')}"


# Backward-compatible snapshot used by tests and older imports.
OLLAMA_BASE = resolve_ollama_base()
DEFAULT_MODEL = "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"
CODER_MODEL = "qwen3.5:35b"

# Model roles — which model to use for which task
MODEL_ROLES = {
    "exploit": DEFAULT_MODEL,  # payload crafting, WAF bypass, exploit strategy
    "analysis": DEFAULT_MODEL,  # vuln analysis, false positive detection
    "code": CODER_MODEL,  # PoC script generation, code analysis
    "remediation": CODER_MODEL,  # code fix generation, secure code examples
    "summary": DEFAULT_MODEL,  # executive summary, reporting
}


class OllamaClient:
    """Client for Ollama local LLM API."""

    def __init__(self, model: Optional[str] = None, base_url: Optional[str] = None, quiet: bool = False):
        self.model = model or DEFAULT_MODEL
        self.base_url = resolve_ollama_base(base_url)
        self.quiet = quiet
        self.available = False
        self._check_connection()

    def _check_connection(self):
        """Check if Ollama is running and model is available."""
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = [m["name"] for m in resp.json().get("models", [])]
                if any(self.model in m for m in models):
                    self.available = True
                    if not getattr(self, "quiet", False):
                        log_success(f"AI Engine: Ollama ({self.model}) ✓")
                else:
                    self.available = False
                    available_str = ", ".join(models[:5]) if models else "none"
                    log_warning(
                        f"Model '{self.model}' not found. "
                        f"Available: {available_str}. "
                        f"Install: ollama pull {self.model}"
                    )
            else:
                log_warning(f"Ollama API not responding at {self.base_url}")
        except ScanExceptions:
            self.available = False
            log_warning(
                f"Ollama not reachable at {self.base_url}. "
                "If Ollama runs on another machine, set OLLAMA_URL=http://HOST:11434"
            )

    def _prompt_ollama(
        self,
        model: str,
        prompt: str,
        system: str = "",
        base_url: Optional[str] = None,
        expect_json: bool = False,
        temperature: float = 0.3,
    ) -> Optional[dict]:
        """Generate a response from the LLM using chat API."""
        if not self.available:
            return None

        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": 4096,
                },
            }

            resp = httpx.post(
                f"{base_url or self.base_url}/api/chat",
                json=payload,
                timeout=300,
            )

            if resp.status_code == 200:
                content = resp.json().get("message", {}).get("content", "").strip()
                if expect_json:
                    return _extract_json(content)
                return content
            else:
                log_error(f"Ollama error: {resp.status_code}")
                return None
        except httpx.TimeoutException:
            log_warning("AI response timed out (300s)")
            return None
        except ScanExceptions as e:
            log_warning(f"AI error: {e}")
            return None

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3,
                  model_role: str = "") -> str:
        """Generate a response from the LLM using chat API.

        Args:
            prompt: User prompt.
            system: System prompt.
            temperature: Sampling temperature.
            model_role: Optional role hint (ignored by single-model client,
                        used by DualModelAI to route to the right model).
        """
        if not getattr(self, "available", False):
            return ""

        response = self._prompt_ollama(
            getattr(self, "model", DEFAULT_MODEL),
            prompt,
            system,
            getattr(self, "base_url", resolve_ollama_base()),
            False,
            temperature,
        )
        return str(response) if response is not None else ""


# ─── Dual-Model AI System ──────────────────────────────────────────────────


class DualModelAI:
    """Dual-model AI system using WhiteRabbitNeo + Qwen3-Coder.

    WhiteRabbitNeo: Exploit strategy, payload generation, WAF bypass
    Qwen3-Coder:   Code generation, PoC scripting, remediation code

    Falls back gracefully if one model is unavailable.
    """

    def __init__(self, base_url: str = None):
        self.base_url = resolve_ollama_base(base_url)
        self.exploit_client: OllamaClient | None = None
        self.coder_client: OllamaClient | None = None
        self._available_models: list[str] = []
        self._init_models()

    def _init_models(self):
        """Initialize both model clients."""
        # Check which models are available
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                self._available_models = [
                    m["name"] for m in resp.json().get("models", [])
                ]
        except ScanExceptions:
            self._available_models = []

        # Init WhiteRabbitNeo (exploit/strategy)
        has_wrn = any(DEFAULT_MODEL in m for m in self._available_models)
        if has_wrn:
            self.exploit_client = OllamaClient(
                model=DEFAULT_MODEL, base_url=self.base_url, quiet=True
            )

        # Init Qwen3-Coder (code generation)
        has_qwen = any(CODER_MODEL in m for m in self._available_models)
        if has_qwen:
            self.coder_client = OllamaClient(model=CODER_MODEL, base_url=self.base_url)

        # Log status
        models_active = []
        if self.exploit_client and self.exploit_client.available:
            models_active.append("🐇 WhiteRabbitNeo (exploit)")
        if self.coder_client and self.coder_client.available:
            models_active.append("🧠 Qwen 3.5 (code)")

        if models_active:
            log_success(f"Dual AI: {' + '.join(models_active)}")
        elif self._available_models:
            log_warning(
                f"Neither {DEFAULT_MODEL} nor {CODER_MODEL} found. "
                f"Available: {', '.join(self._available_models[:5])}"
            )

    @property
    def available(self) -> bool:
        """True if at least one model is available."""
        return bool(
            (self.exploit_client and self.exploit_client.available)
            or (self.coder_client and self.coder_client.available)
        )

    def get_client_for_role(self, role: str) -> OllamaClient | None:
        """Get the best client for a given role.

        Roles: 'exploit', 'analysis', 'code', 'remediation', 'summary'
        Falls back to whichever model is available.
        """
        preferred_model = MODEL_ROLES.get(role, DEFAULT_MODEL)

        # Try preferred model first
        if preferred_model == CODER_MODEL:
            if self.coder_client and self.coder_client.available:
                return self.coder_client
            # Fallback to exploit model
            if self.exploit_client and self.exploit_client.available:
                return self.exploit_client
        else:
            if self.exploit_client and self.exploit_client.available:
                return self.exploit_client
            # Fallback to coder model
            if self.coder_client and self.coder_client.available:
                return self.coder_client

        return None

    def generate(
        self,
        prompt: str,
        system: str = "",
        temperature: float = 0.3,
        model_role: str = "exploit",
    ) -> str:
        """Generate using the appropriate model for the role.

        Routes to WhiteRabbitNeo for exploit/analysis/summary tasks,
        and to Qwen3.5 for code/remediation tasks.
        """
        client = self.get_client_for_role(model_role)
        if not client:
            return ""
        return client.generate(prompt, system=system, temperature=temperature)


# ─── Security Analysis Prompts ──────────────────────────────────────────────

SECURITY_SYSTEM_PROMPT = """You are a senior penetration tester and cybersecurity expert.
You analyze vulnerability scan results with precision and provide actionable insights.
Be concise, technical, and direct. Use bullet points.
Always respond in the language of the user's input."""


def analyze_vulnerability(client: OllamaClient, vuln: dict) -> dict:
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

    response = client.generate(prompt, system=SECURITY_SYSTEM_PROMPT, model_role="analysis")

    result = _extract_json(response, expect_array=False)
    if result and isinstance(result, dict):
        return result

    return {"raw_analysis": response}


def detect_false_positives(client: OllamaClient, vulns: list) -> list:
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


def generate_remediation(client: OllamaClient, vulns: list) -> list:
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
    for vuln in filtered_vulns:
        vuln_type = vuln.get("type", "Unknown")
        url = vuln.get("url", "N/A")
        payload = vuln.get("payload", "N/A")

        prompt = f"""Generate a specific remediation for this vulnerability:

Type: {vuln_type}
URL: {url}
Payload used: {payload}

Provide:
1. **Quick Fix**: Immediate mitigation (1 line)
2. **Code Fix**: Example secure code snippet
3. **Best Practice**: Long-term architectural recommendation

Be specific and developer-friendly. Include code examples."""

        response = client.generate(prompt, system=SECURITY_SYSTEM_PROMPT,
                                    model_role="remediation")
        remediations.append(
            {
                "vuln_type": vuln_type,
                "url": url,
                "remediation": response,
            }
        )

    return remediations


def generate_smart_payloads(
    client: OllamaClient, vuln_type: str, context: str = ""
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

    response = client.generate(prompt, system=SECURITY_SYSTEM_PROMPT, temperature=0.7,
                                model_role="exploit")

    result = _extract_json(response, expect_array=True)
    if result and isinstance(result, list):
        return [str(p) for p in result[:10]]

    return []


class EvolvingWAFBypassEngine:
    """Stateful AI Mutation Engine for bypassing advanced HTTP WAFs."""

    def __init__(self, client: OllamaClient, waf_name: str, vuln_type: str):
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
            response = self.client.generate(
                prompt,
                system="You are an expert WAF mutation engine. Generate only working payloads. Return raw JSON arrays only.",
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
    client: OllamaClient,
    waf_name: str,
    blocked_payload: str,
    vuln_type: str,
    param_name: str = "",
) -> list:
    """Helper wrapper around Evolutionary Engine for single-shot generation."""
    engine = EvolvingWAFBypassEngine(client, waf_name, vuln_type)
    return engine.mutate(blocked_payload, iteration=1)


def generate_scan_summary(
    client: OllamaClient, vulns: list, target: str, stats: dict
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
    base_url: Optional[str] = None,
) -> OllamaClient:
    """Initialize the primary AI client."""
    global _ai_client
    _ai_client = OllamaClient(model=model, base_url=base_url)
    return _ai_client


def get_ai(base_url: Optional[str] = None) -> OllamaClient:
    """Get the current primary AI client (or create one)."""
    global _ai_client
    if _ai_client is None:
        _ai_client = OllamaClient(base_url=base_url)
    return _ai_client


def init_dual_ai(base_url: Optional[str] = None) -> DualModelAI:
    """Initialize the dual-model AI system."""
    global _dual_ai
    _dual_ai = DualModelAI(base_url=base_url)
    return _dual_ai


def get_dual_ai() -> DualModelAI | None:
    """Get the dual-model AI system (if initialized)."""
    return _dual_ai
