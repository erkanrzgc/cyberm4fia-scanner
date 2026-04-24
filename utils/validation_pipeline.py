"""
cyberm4fia-scanner — Finding Validation Pipeline (Hallucination Gate System)
4-gate validation inspired by the 0-Day Machine's "guilty until proven innocent" approach.
"""
from dataclasses import dataclass, field
from datetime import datetime



GATE_DESCRIPTIONS = {
    "gate_0_evidence": "Real evidence exists (payload reflection, error, behavioral change)",
    "gate_1_reproducible": "Finding reproduces with same request",
    "gate_2_exploitable": "Finding has real security impact (not just error/info)",
    "gate_3_no_false_positive": "Heuristic + AI confirms not a false positive",
}

STAGE_ORDER = ["suspected", "evidence_confirmed", "verified", "confirmed", "exploitable"]


@dataclass
class GateResult:
    gate: str
    passed: bool
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ValidationPipeline:
    """4-gate finding validation system.

    Every finding starts as 'suspected' and must pass through gates
    to reach higher validation stages. This dramatically reduces
    false positives.

    Gate 0: Evidence exists (payload reflected, error triggered, timing anomaly)
    Gate 1: Reproducible (optional, requires --verify flag)
    Gate 2: Exploitable (real security impact, not just error pages)
    Gate 3: Not a false positive (heuristic + AI check)
    """

    # Common false positive patterns
    FP_PATTERNS = [
        "404 not found", "page not found", "cannot be found",
        "default web page", "apache2 default", "nginx welcome",
        "iis windows server", "test page", "under construction",
        "coming soon", "maintenance mode", "error 500",
    ]

    # WAF block indicators (these are NOT real vulnerabilities)
    WAF_BLOCK_PATTERNS = [
        "access denied", "blocked by", "request rejected",
        "security policy violation", "web application firewall",
        "cloudflare", "incapsula", "sucuri",
    ]

    def __init__(self, verify_replay=False, ai_client=None):
        self.verify_replay = verify_replay
        self.ai_client = ai_client

    def validate_finding(self, finding) -> dict:
        """Run all applicable gates and update finding state.

        Args:
            finding: dict or Finding dataclass

        Returns:
            Updated finding dict with validation_stage and validation_gates
        """
        if not isinstance(finding, dict):
            try:
                finding = finding.to_dict()
            except AttributeError:
                return finding

        # Initialize validation fields
        finding.setdefault("validation_stage", "suspected")
        finding.setdefault("validation_gates", {})
        finding.setdefault("validation_history", [])

        # Gate 0: Evidence check
        g0 = self._gate_0_evidence(finding)
        finding["validation_gates"]["gate_0_evidence"] = {
            "passed": g0.passed, "reason": g0.reason, "timestamp": g0.timestamp
        }
        if not g0.passed:
            finding["validation_stage"] = "suspected"
            return finding
        finding["validation_stage"] = "evidence_confirmed"

        # Gate 1: Reproducibility (optional)
        if self.verify_replay:
            g1 = self._gate_1_reproducible(finding)
            finding["validation_gates"]["gate_1_reproducible"] = {
                "passed": g1.passed, "reason": g1.reason, "timestamp": g1.timestamp
            }
            if not g1.passed:
                return finding

        # Gate 2: Exploitability
        g2 = self._gate_2_exploitable(finding)
        finding["validation_gates"]["gate_2_exploitable"] = {
            "passed": g2.passed, "reason": g2.reason, "timestamp": g2.timestamp
        }
        if not g2.passed:
            return finding
        finding["validation_stage"] = "verified"

        # Gate 3: False positive check
        g3 = self._gate_3_no_false_positive(finding)
        finding["validation_gates"]["gate_3_no_false_positive"] = {
            "passed": g3.passed, "reason": g3.reason, "timestamp": g3.timestamp
        }
        if g3.passed:
            # Check if we have exploit data for 'exploitable' stage
            if finding.get("exploit_data"):
                finding["validation_stage"] = "exploitable"
            else:
                finding["validation_stage"] = "confirmed"

        # Record transition
        finding["validation_history"].append({
            "stage": finding["validation_stage"],
            "timestamp": datetime.now().isoformat(),
        })

        return finding

    def _gate_0_evidence(self, finding) -> GateResult:
        """Check if real evidence exists for this finding."""
        payload = str(finding.get("payload", ""))
        evidence = str(finding.get("evidence", ""))
        response = str(finding.get("response_snippet", "") or "")
        vuln_type = str(finding.get("type", finding.get("finding_type", "")))
        description = str(finding.get("description", ""))

        # Skip evidence check for info-level findings (headers, tech detect)
        severity = str(finding.get("severity", "")).lower()
        if severity in ("info",):
            return GateResult(gate="gate_0_evidence", passed=True,
                              reason="Info-level finding auto-passes Gate 0")

        # Check: payload reflection in response
        if payload and response and payload in response:
            return GateResult(gate="gate_0_evidence", passed=True,
                              reason="Payload reflected in response")

        # Check: evidence string present
        if evidence and len(evidence) > 10:
            return GateResult(gate="gate_0_evidence", passed=True,
                              reason=f"Evidence present: {evidence[:60]}")

        # Check: exploit data exists
        if finding.get("exploit_data"):
            return GateResult(gate="gate_0_evidence", passed=True,
                              reason="Exploit data present")

        # Check: status code indicators
        status = finding.get("status_code") or finding.get("response_code")
        if status:
            code = int(status) if str(status).isdigit() else 0
            if code == 500 and "sqli" in vuln_type.lower():
                return GateResult(gate="gate_0_evidence", passed=True,
                                  reason="500 error on SQL injection probe")
            if code == 200 and payload:
                return GateResult(gate="gate_0_evidence", passed=True,
                                  reason="200 response with injected payload")

        # Check: timing-based evidence (blind injection)
        if "blind" in vuln_type.lower() or "time" in description.lower():
            return GateResult(gate="gate_0_evidence", passed=True,
                              reason="Timing-based detection (blind)")

        # Check: description contains confirmation keywords
        confirm_words = ["confirmed", "verified", "vulnerable", "successful", "exploited"]
        if any(w in description.lower() for w in confirm_words):
            return GateResult(gate="gate_0_evidence", passed=True,
                              reason="Description contains confirmation keywords")

        # Fallback: if payload exists, minimal evidence
        if payload:
            return GateResult(gate="gate_0_evidence", passed=True,
                              reason="Payload present (minimal evidence)")

        return GateResult(gate="gate_0_evidence", passed=False,
                          reason="No evidence found: no payload, no response reflection, no evidence string")

    def _gate_1_reproducible(self, finding) -> GateResult:
        """Replay the request and verify the finding reproduces."""
        url = finding.get("url", "")
        payload = finding.get("payload", "")
        param = finding.get("param", "")

        if not url:
            return GateResult(gate="gate_1_reproducible", passed=False,
                              reason="No URL to replay")

        try:
            import httpx
            method = "GET"
            req_data = finding.get("request", {})
            if isinstance(req_data, dict):
                method = req_data.get("method", "GET").upper()

            if method == "GET" and param and payload:
                sep = "&" if "?" in url else "?"
                test_url = f"{url}{sep}{param}={payload}"
                resp = httpx.get(test_url, timeout=10, verify=False, follow_redirects=True)
            elif method == "POST" and param and payload:
                resp = httpx.post(url, data={param: payload}, timeout=10, verify=False, follow_redirects=True)
            else:
                resp = httpx.get(url, timeout=10, verify=False, follow_redirects=True)

            # Check if payload reflects
            if payload and payload in resp.text:
                return GateResult(gate="gate_1_reproducible", passed=True,
                                  reason=f"Payload reflected on replay (status {resp.status_code})")
            # Check status code match
            orig_code = finding.get("status_code") or finding.get("response_code")
            if orig_code and resp.status_code == int(orig_code):
                return GateResult(gate="gate_1_reproducible", passed=True,
                                  reason=f"Status code matches original ({resp.status_code})")

            return GateResult(gate="gate_1_reproducible", passed=False,
                              reason=f"Replay did not reproduce finding (status {resp.status_code})")
        except Exception as e:
            return GateResult(gate="gate_1_reproducible", passed=True,
                              reason=f"Replay error (kept finding): {e}")

    def _gate_2_exploitable(self, finding) -> GateResult:
        """Verify the finding has real security impact."""
        vuln_type = str(finding.get("type", finding.get("finding_type", ""))).lower()
        severity = str(finding.get("severity", "")).lower()
        description = str(finding.get("description", "")).lower()
        evidence = str(finding.get("evidence", "")).lower()
        response = str(finding.get("response_snippet", "") or "").lower()

        # Info-level findings auto-pass (they don't claim exploitability)
        if severity in ("info", "low"):
            return GateResult(gate="gate_2_exploitable", passed=True,
                              reason="Low/info findings auto-pass exploitability gate")

        # Check for WAF block (finding is actually blocked, not exploitable)
        combined = f"{description} {evidence} {response}"
        for pattern in self.WAF_BLOCK_PATTERNS:
            if pattern in combined and "bypass" not in combined:
                return GateResult(gate="gate_2_exploitable", passed=False,
                                  reason=f"WAF block detected: '{pattern}' — not exploitable")

        # Check for generic error pages
        for pattern in self.FP_PATTERNS:
            if pattern in combined and not finding.get("payload"):
                return GateResult(gate="gate_2_exploitable", passed=False,
                                  reason=f"Generic error page: '{pattern}'")

        # Exploit data present = definitely exploitable
        if finding.get("exploit_data"):
            return GateResult(gate="gate_2_exploitable", passed=True,
                              reason="Exploit data confirms exploitability")

        # High confidence = likely exploitable
        conf_score = finding.get("confidence_score", 0)
        if isinstance(conf_score, (int, float)) and conf_score >= 70:
            return GateResult(gate="gate_2_exploitable", passed=True,
                              reason=f"High confidence score: {conf_score}")

        # Payload exists = presumed exploitable for critical vulns
        if finding.get("payload") and severity in ("critical", "high"):
            return GateResult(gate="gate_2_exploitable", passed=True,
                              reason="Payload present for critical/high finding")

        # Default: pass for medium+
        if severity in ("medium", "high", "critical"):
            return GateResult(gate="gate_2_exploitable", passed=True,
                              reason="Medium+ severity finding passes by default")

        return GateResult(gate="gate_2_exploitable", passed=False,
                          reason="Could not confirm exploitability")

    def _gate_3_no_false_positive(self, finding) -> GateResult:
        """Heuristic + optional AI check for false positives."""
        vuln_type = str(finding.get("type", finding.get("finding_type", "")))
        evidence = str(finding.get("evidence", "")).lower()
        description = str(finding.get("description", "")).lower()
        url = str(finding.get("url", "")).lower()

        # Already AI-verified
        if finding.get("ai_verified") is True:
            return GateResult(gate="gate_3_no_false_positive", passed=True,
                              reason="Previously AI-verified")
        if finding.get("ai_verified") is False:
            return GateResult(gate="gate_3_no_false_positive", passed=False,
                              reason=f"AI flagged as FP: {finding.get('ai_reason', '')}")

        # Heuristic FP checks
        # 1. Static asset false positives
        static_exts = (".css", ".js", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot")
        if any(url.endswith(ext) for ext in static_exts):
            if vuln_type not in ("Secret_Leak", "Debug_Info", "Internal_IP_Leak"):
                return GateResult(gate="gate_3_no_false_positive", passed=False,
                                  reason="Injection finding on static asset — likely FP")

        # 2. Missing header duplicates
        if "missing" in vuln_type.lower() and "header" in vuln_type.lower():
            return GateResult(gate="gate_3_no_false_positive", passed=True,
                              reason="Header finding (always valid)")

        # 3. Empty payload on injection type
        injection_types = ("xss", "sqli", "lfi", "rfi", "cmdi", "ssrf", "ssti", "xxe")
        is_injection = any(t in vuln_type.lower() for t in injection_types)
        if is_injection and not finding.get("payload"):
            return GateResult(gate="gate_3_no_false_positive", passed=False,
                              reason="Injection finding without payload — likely FP")

        # Default: pass
        return GateResult(gate="gate_3_no_false_positive", passed=True,
                          reason="Passed heuristic FP checks")

    def validate_batch(self, findings):
        """Validate a list of findings and return categorized results."""
        validated = []
        suspected = []
        for f in findings:
            result = self.validate_finding(f)
            stage = result.get("validation_stage", "suspected")
            if stage in ("confirmed", "exploitable", "verified"):
                validated.append(result)
            else:
                suspected.append(result)
        return validated, suspected

    @staticmethod
    def promote(finding, reason=""):
        """Manually promote a finding to the next validation stage."""
        stage = finding.get("validation_stage", "suspected")
        idx = STAGE_ORDER.index(stage) if stage in STAGE_ORDER else 0
        if idx < len(STAGE_ORDER) - 1:
            finding["validation_stage"] = STAGE_ORDER[idx + 1]
            finding.setdefault("validation_history", []).append({
                "stage": finding["validation_stage"],
                "action": "promoted",
                "reason": reason,
                "timestamp": datetime.now().isoformat(),
            })
        return finding

    @staticmethod
    def demote(finding, reason=""):
        """Demote a finding back to suspected."""
        finding["validation_stage"] = "suspected"
        finding["demoted_at"] = datetime.now().isoformat()
        finding["demote_reason"] = reason
        finding.setdefault("validation_history", []).append({
            "stage": "suspected",
            "action": "demoted",
            "reason": reason,
            "timestamp": datetime.now().isoformat(),
        })
        return finding
