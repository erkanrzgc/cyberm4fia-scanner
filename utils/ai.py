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
import re
import httpx
from utils.colors import log_info, log_success, log_warning, log_error


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

OLLAMA_BASE = "http://192.168.6.1:11434"
DEFAULT_MODEL = "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"


class OllamaClient:
    """Client for Ollama local LLM API."""

    def __init__(self, model: str = None, base_url: str = None):
        self.model = model or DEFAULT_MODEL
        self.base_url = (base_url or OLLAMA_BASE).rstrip("/")
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
                log_warning("Ollama API not responding")
        except Exception:
            self.available = False
            log_warning(
                "Ollama not running. Install: "
                "curl -fsSL https://ollama.ai/install.sh | sh"
            )

    def generate(self, prompt: str, system: str = "", temperature: float = 0.3) -> str:
        """Generate a response from the LLM using chat API."""
        if not self.available:
            return ""

        try:
            messages = []
            if system:
                messages.append({"role": "system", "content": system})
            messages.append({"role": "user", "content": prompt})

            payload = {
                "model": self.model,
                "messages": messages,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": 1024,
                },
            }

            resp = httpx.post(
                f"{self.base_url}/api/chat",
                json=payload,
                timeout=300,
            )

            if resp.status_code == 200:
                return resp.json().get("message", {}).get("content", "").strip()
            else:
                log_error(f"Ollama error: {resp.status_code}")
                return ""
        except httpx.TimeoutException:
            log_warning("AI response timed out (300s)")
            return ""
        except Exception as e:
            log_warning(f"AI error: {e}")
            return ""


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
Payload: {payload}

Provide:
1. **Risk Assessment**: How critical is this? (Critical/High/Medium/Low)
2. **Attack Scenario**: How can an attacker exploit this? (2-3 sentences)
3. **False Positive Check**: Is this likely a real vulnerability or false positive? (confidence %)
4. **Remediation**: How to fix this? (specific code-level fix)
5. **CVSS Justification**: Why this severity rating?

Respond in JSON format:
{{"risk": "...", "scenario": "...", "confidence": 85, "remediation": "...", "cvss_note": "..."}}"""

    response = client.generate(prompt, system=SECURITY_SYSTEM_PROMPT)

    result = _extract_json(response, expect_array=False)
    if result and isinstance(result, dict):
        return result

    return {"raw_analysis": response}


def detect_false_positives(client: OllamaClient, vulns: list) -> list:
    """Filter likely false positives from vulnerability list."""
    if not client.available or not vulns:
        return vulns

    log_info(f"AI analyzing {len(vulns)} findings for false positives...")

    verified = []
    for vuln in vulns:
        vuln_type = vuln.get("type", "")
        payload = vuln.get("payload", "")
        url = vuln.get("url", "")

        prompt = f"""Is this a real vulnerability or likely a false positive?

Type: {vuln_type}
URL: {url}
Payload: {payload}

Answer ONLY with a JSON: {{"real": true/false, "confidence": 0-100, "reason": "..."}}"""

        response = client.generate(
            prompt, system=SECURITY_SYSTEM_PROMPT, temperature=0.1
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

    log_info("AI generating remediation recommendations...")

    remediations = []
    for vuln in vulns:
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

        response = client.generate(prompt, system=SECURITY_SYSTEM_PROMPT)
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

    response = client.generate(prompt, system=SECURITY_SYSTEM_PROMPT, temperature=0.7)

    result = _extract_json(response, expect_array=True)
    if result and isinstance(result, list):
        return [str(p) for p in result[:10]]

    return []


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

    return client.generate(prompt, system=SECURITY_SYSTEM_PROMPT)


# ─── Global Client ───────────────────────────────────────────────────────────

_ai_client = None


def init_ai(model: str = None) -> OllamaClient:
    """Initialize the AI client."""
    global _ai_client
    _ai_client = OllamaClient(model=model)
    return _ai_client


def get_ai() -> OllamaClient:
    """Get the current AI client (or create one)."""
    global _ai_client
    if _ai_client is None:
        _ai_client = OllamaClient()
    return _ai_client
