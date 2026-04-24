"""
cyberm4fia-scanner - AI WAF Evasion Agent
Real-time AI-powered WAF bypass mutation loop using WhiteRabbitNeo.
"""

import re
from dataclasses import dataclass, field
from typing import List

from utils.colors import Colors, log_info, log_success, log_warning
from utils.request import smart_request
from utils.request import ScanExceptions


@dataclass
class EvadeResult:
    """Result of a WAF evasion attempt."""
    success: bool = False
    final_payload: str = ""
    original_payload: str = ""
    iterations: int = 0
    technique: str = ""
    response_code: int = 0
    evidence: str = ""
    mutations: List[str] = field(default_factory=list)


# ── WAF Block Indicators ────────────────────────────────────────────────
WAF_BLOCK_INDICATORS = [
    # Status codes
    403, 406, 429, 503,
]

WAF_BLOCK_KEYWORDS = [
    "access denied",
    "blocked",
    "forbidden",
    "waf",
    "firewall",
    "security policy",
    "mod_security",
    "request rejected",
    "web application firewall",
    "cloudflare",
    "akamai",
    "imperva",
    "incapsula",
    "sucuri",
    "aws waf",
    "f5 big-ip",
    "barracuda",
    "fortiweb",
    "challenge-platform",
    "attention required",
    "checking your browser",
    "ray id",
    "cf-ray",
]


class AIWafEvader:
    """
    AI-powered WAF Evasion Agent.
    Uses WhiteRabbitNeo to generate mutated payloads that bypass WAF protections.
    """

    # Prompts for different vuln types
    SYSTEM_PROMPT = (
        "You are an expert penetration tester and WAF bypass specialist. "
        "Your task is to mutate blocked payloads to bypass Web Application Firewalls. "
        "You must provide ONLY the mutated payload, nothing else. No explanations. "
        "Use advanced evasion techniques: encoding, case manipulation, "
        "comment insertion, string concatenation, alternative functions, "
        "Unicode normalization, null bytes, and protocol-level tricks."
    )

    VULN_HINTS = {
        "XSS": (
            "The payload is an XSS vector. Use techniques like: "
            "HTML entity encoding, JavaScript protocol alternatives, event handler mutation, "
            "SVG/MathML injection, template literal abuse, DOM clobbering vectors."
        ),
        "SQLi": (
            "The payload is a SQL injection. Use techniques like: "
            "inline comments (/*!*/), double URL encoding, hex encoding, "
            "CONCAT/CHR alternatives, scientific notation, JSON extraction operators."
        ),
        "CMDi": (
            "The payload is a command injection. Use techniques like: "
            "$() substitution, backtick execution, IFS variable abuse, "
            "brace expansion, wildcard globbing (/???/??t /???/p??s?d), "
            "environment variable injection."
        ),
        "LFI": (
            "The payload is a Local File Inclusion. Use techniques like: "
            "double encoding, null byte injection (%00), PHP wrappers, "
            "path truncation, dot-dot-slash variations (..\\\\, ..%2f, %2e%2e/)."
        ),
        "SSRF": (
            "The payload is a Server-Side Request Forgery. Use techniques like: "
            "IP address encoding (decimal, octal, hex), DNS rebinding, "
            "URL parser confusion, redirect chains, protocol smuggling."
        ),
    }

    def __init__(self, ai_client=None, waf_name=""):
        """
        Initialize the WAF Evasion Agent.

        Args:
            ai_client: NvidiaApiClient instance (or DualModelAI).
            waf_name: Detected WAF name (e.g., 'Cloudflare', 'ModSecurity').
        """
        self.ai = ai_client
        self.waf_name = waf_name
        self.available = bool(ai_client and getattr(ai_client, "available", False))

    def _is_blocked(self, response):
        """Determine if a response indicates WAF blocking."""
        if response is None:
            return True

        # Check status code
        if response.status_code in WAF_BLOCK_INDICATORS:
            return True

        # Check response body for WAF keywords
        body_lower = response.text.lower()
        for keyword in WAF_BLOCK_KEYWORDS:
            if keyword in body_lower:
                return True

        return False

    def _build_prompt(self, payload, vuln_type, blocked_response=None, iteration=1):
        """Build the AI prompt for payload mutation."""
        waf_info = f"The WAF is: {self.waf_name}. " if self.waf_name else ""
        type_hint = self.VULN_HINTS.get(vuln_type, "")

        blocked_info = ""
        if blocked_response:
            status = getattr(blocked_response, "status_code", "unknown")
            body_snippet = getattr(blocked_response, "text", "")[:300]
            blocked_info = (
                f"\nThe WAF returned status {status}. "
                f"Response snippet: {body_snippet[:200]}"
            )

        prompt = (
            f"ITERATION {iteration}: The following {vuln_type} payload was BLOCKED by a WAF.\n"
            f"{waf_info}{type_hint}\n\n"
            f"BLOCKED PAYLOAD:\n{payload}\n"
            f"{blocked_info}\n\n"
            f"Generate a SINGLE mutated payload that bypasses this WAF. "
            f"Use a DIFFERENT evasion technique than previous attempts. "
            f"Output ONLY the raw payload, no explanation, no markdown, no quotes."
        )
        return prompt

    def _extract_payload(self, ai_response):
        """Extract the payload from AI response, stripping explanations."""
        if not ai_response:
            return None

        text = ai_response.strip()

        # Remove markdown code blocks if present
        text = re.sub(r"```[a-zA-Z]*\n?", "", text)
        text = text.strip("`").strip()

        # If multiple lines, take the longest line (likely the payload)
        lines = [l.strip() for l in text.split("\n") if l.strip()]
        if not lines:
            return None

        # Filter out explanation lines
        payload_lines = [
            l for l in lines
            if not l.startswith(("Here", "This", "The", "I ", "Note", "Explanation", "#", "//"))
        ]

        if payload_lines:
            # Return the longest line as it's most likely the full payload
            return max(payload_lines, key=len)

        return lines[0] if lines else None

    def evade(self, original_payload, vuln_type, test_url, param,
              method="get", form_data=None, max_rounds=5, validation_fn=None):
        """
        Main evasion loop: mutate payload until it bypasses the WAF.

        Args:
            original_payload: The payload that was blocked.
            vuln_type: Type of vulnerability (XSS, SQLi, CMDi, LFI, SSRF).
            test_url: URL to test the payload against.
            param: Parameter name to inject into.
            method: HTTP method (get/post).
            form_data: Form data for POST requests.
            max_rounds: Maximum mutation attempts.
            validation_fn: Optional function(response) -> bool to check if exploitation succeeded.

        Returns:
            EvadeResult with success status and final payload.
        """
        if not self.available:
            return EvadeResult(original_payload=original_payload)

        result = EvadeResult(original_payload=original_payload)
        current_payload = original_payload
        blocked_response = None

        print(
            f"\n{Colors.BOLD}{Colors.YELLOW}"
            f"[🤖] AI WAF Evasion Agent — {vuln_type} bypass loop"
            f"{Colors.END}"
        )
        log_info(f"WAF: {self.waf_name or 'Unknown'} | Max rounds: {max_rounds}")

        for i in range(1, max_rounds + 1):
            # Step 1: Generate mutated payload via AI
            prompt = self._build_prompt(
                current_payload, vuln_type,
                blocked_response=blocked_response, iteration=i
            )

            try:
                # Use the AI client to generate mutated payload
                if hasattr(self.ai, "generate"):
                    ai_text = self.ai.generate(prompt, system=self.SYSTEM_PROMPT)
                elif hasattr(self.ai, "exploit_client"):
                    # DualModelAI
                    ai_text = self.ai.exploit_client.generate(
                        prompt, system=self.SYSTEM_PROMPT
                    )
                else:
                    log_warning("AI client has no generate method.")
                    break

                mutated = self._extract_payload(ai_text)
                if not mutated or mutated == current_payload:
                    log_warning(f"  Round {i}: AI returned empty or duplicate payload. Skipping.")
                    continue

                result.mutations.append(mutated)
                log_info(
                    f"  Round {i}: Trying mutated payload "
                    f"({len(mutated)} chars)..."
                )

            except ScanExceptions as e:
                log_warning(f"  Round {i}: AI error: {e}")
                continue

            # Step 2: Test the mutated payload
            try:
                from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

                if method.lower() == "get":
                    parsed = urlparse(test_url)
                    params = parse_qs(parsed.query, keep_blank_values=True)
                    params[param] = [mutated]
                    flat = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
                    exploit_url = urlunparse(parsed._replace(query=urlencode(flat)))
                    resp = smart_request("get", exploit_url, delay=0.3)
                else:
                    data = dict(form_data) if form_data else {}
                    data[param] = mutated
                    resp = smart_request("post", test_url, data=data, delay=0.3)

            except ScanExceptions:
                log_warning(f"  Round {i}: Request failed.")
                continue

            # Step 3: Check if WAF still blocking
            if self._is_blocked(resp):
                log_warning(
                    f"  Round {i}: Still blocked (HTTP {resp.status_code if resp else '?'})"
                )
                blocked_response = resp
                current_payload = mutated  # Feed the mutation back for next round
                continue

            # Step 4: Check if exploitation actually succeeded
            if validation_fn:
                if validation_fn(resp):
                    result.success = True
                    result.final_payload = mutated
                    result.iterations = i
                    result.response_code = resp.status_code
                    result.evidence = resp.text[:500]
                    result.technique = f"AI Mutation (Round {i})"

                    log_success(
                        f"  🎯 WAF BYPASSED in round {i}! "
                        f"Payload: {mutated[:80]}..."
                    )
                    return result
                else:
                    # Not blocked but exploit didn't trigger either
                    log_info(f"  Round {i}: Not blocked but no exploit confirmation yet.")
                    blocked_response = resp
                    current_payload = mutated
            else:
                # No validation function — if not blocked, consider it a bypass
                result.success = True
                result.final_payload = mutated
                result.iterations = i
                result.response_code = resp.status_code
                result.evidence = resp.text[:500]
                result.technique = f"AI Mutation (Round {i})"

                log_success(
                    f"  🎯 WAF BYPASSED in round {i}! "
                    f"Payload: {mutated[:80]}..."
                )
                return result

        # Exhausted all rounds
        log_warning(f"  WAF evasion failed after {max_rounds} rounds.")
        result.iterations = max_rounds
        return result


def get_waf_evader(waf_name=""):
    """Factory function to create a WAF evasion agent."""
    try:
        from utils.ai import get_ai
        ai = get_ai()
        if ai and ai.available:
            return AIWafEvader(ai_client=ai, waf_name=waf_name)
    except ImportError:
        pass
    return AIWafEvader(waf_name=waf_name)
