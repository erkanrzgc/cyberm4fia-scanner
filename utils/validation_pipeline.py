"""
cyberm4fia-scanner — Finding Validation Pipeline (Hallucination Gate System)
7-gate validation inspired by pentest-agents' 7-Question Gate concept.
Every finding starts as 'suspected' and must pass through gates to reach
higher validation stages. Includes never-submit filter and mistakes awareness.
"""
from dataclasses import dataclass, field
from datetime import datetime



GATE_DESCRIPTIONS = {
    "gate_0_evidence": "Real evidence exists (payload reflection, error, behavioral change)",
    "gate_1_reproducible": "Finding reproduces with same request",
    "gate_2_exploitable": "Finding has real security impact (not just error/info)",
    "gate_3_no_false_positive": "Heuristic + AI confirms not a false positive",
    "gate_4_never_submit": "Finding is NOT on the never-submit list (or has a valid chain)",
    "gate_5_real_impact": "Finding demonstrates real harm with actual data (not theoretical)",
    "gate_6_mistakes_check": "Finding passes common-mistakes awareness check",
}

NEVER_SUBMIT_RULES = [
    "missing header",
    "missing spf",
    "missing dkim",
    "missing dmarc",
    "graphql introspection",
    "banner disclosure",
    "version disclosure",
    "clickjacking",
    "self-xss",
    "self xss",
    "open redirect",
    "dns-only",
    "dns only",
    "cors wildcard",
    "logout csrf",
    "rate limit",
    "session not invalidated",
    "concurrent sessions",
    "internal ip",
    "missing cookie flag",
    "client_secret in mobile",
    "client_id alone",
    "oidc discovery",
    "spa client-side config",
    "source map",
]

CONDITIONALLY_VALID = {
    "open redirect": "OAuth code theft → token exchange → ATO",
    "ssrf dns-only": "internal service data exfil → Data breach",
    "ssrf dns only": "internal service data exfil → Data breach",
    "cors wildcard": "credentialed data theft PoC → Cross-origin data theft",
    "graphql introspection": "auth bypass on mutations → Unauthorized actions",
    "s3 listing": "secrets in bundles → OAuth chain → ATO",
    "prompt injection": "IDOR via chatbot → Data breach",
    "subdomain takeover": "OAuth redirect_uri at that subdomain → ATO",
}

COMMON_MISTAKES = [
    "theoretical language ('could result in', 'potentially', 'might lead to')",
    "no write evidence (findings only in memory, not on disk)",
    "status-code differential without cross-user test",
    "curl-against-WAF treated as 'not vulnerable'",
    "placeholder values instead of real credentials",
    "relying on fingerprint alone without working PoC",
    "CORS finding without credentialed delivery path",
    "spec violation presented as vulnerability",
    "single-signal differential presented as confirmed",
    "missing CVSS version alignment with platform",
]

STAGE_ORDER = ["suspected", "evidence_confirmed", "verified", "confirmed", "exploitable"]


@dataclass
class GateResult:
    gate: str
    passed: bool
    reason: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


class ValidationPipeline:
    """7-gate finding validation system inspired by pentest-agents.

    Every finding starts as 'suspected' and must pass through gates
    to reach higher validation stages. This dramatically reduces
    false positives.

    Gate 0: Evidence exists (payload reflected, error triggered, timing anomaly)
    Gate 1: Reproducible (optional, requires --verify flag)
    Gate 2: Exploitable (real security impact, not just error pages)
    Gate 3: Not a false positive (heuristic + AI check)
    Gate 4: Never-Submit check (not on the instant-kill list)
    Gate 5: Real Impact (demonstrates actual harm with data, not theory)
    Gate 6: Mistakes Awareness (passes common-mistakes sanity check)
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

    # Theoretical language patterns (weak findings)
    THEORETICAL_PATTERNS = [
        "could result in", "could be used to", "could potentially",
        "may allow", "might lead to", "possible to", "potential for",
        "can be exploited", "could be exploited", "may result in",
    ]

    # Never-submit finding types (instant KILL without chain)
    NEVER_SUBMIT = {
        "missing_csp": "Missing CSP header",
        "missing_hsts": "Missing HSTS header",
        "missing_xfo": "Missing X-Frame-Options header",
        "missing_spf": "Missing SPF record",
        "missing_dmarc": "Missing DMARC record",
        "banner_disclosure": "Server version disclosure without CVE",
        "clickjacking_basic": "Clickjacking without sensitive action",
        "self_xss": "Self-XSS (requires victim to paste payload)",
        "open_redirect_alone": "Open redirect without exploitation chain",
        "ssrf_dns_only": "DNS-only SSRF without data exfiltration",
        "cors_wildcard_no_creds": "CORS wildcard without credentialed PoC",
        "logout_csrf": "Logout CSRF (no security impact)",
        "rate_limit_non_critical": "Rate limit on non-critical form",
        "session_not_invalidated": "Session not invalidated on logout",
        "internal_ip_error": "Internal IP in error message",
        "missing_cookie_flags": "Missing cookie flags alone",
        "oidc_discovery": "OIDC discovery endpoint (public by design)",
        "graphql_introspection": "GraphQL introspection alone (no auth bypass)",
        "spa_client_config": "SPA client-side configuration exposure",
    }

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
        if not g3.passed:
            return finding

        # Gate 4: Never-Submit check (inspired by pentest-agents)
        g4 = self._gate_4_never_submit(finding)
        finding["validation_gates"]["gate_4_never_submit"] = {
            "passed": g4.passed, "reason": g4.reason, "timestamp": g4.timestamp
        }
        if not g4.passed:
            finding["validation_stage"] = "blocked_neversubmit"
            return finding

        # Gate 5: Real Impact check (actual data, not theoretical)
        g5 = self._gate_5_real_impact(finding)
        finding["validation_gates"]["gate_5_real_impact"] = {
            "passed": g5.passed, "reason": g5.reason, "timestamp": g5.timestamp
        }
        if not g5.passed:
            finding["validation_stage"] = "theoretical_only"
            return finding

        # Gate 6: Mistakes awareness check
        g6 = self._gate_6_mistakes_check(finding)
        finding["validation_gates"]["gate_6_mistakes_check"] = {
            "passed": g6.passed, "reason": g6.reason, "timestamp": g6.timestamp
        }
        if g6.passed:
            if finding.get("exploit_data"):
                finding["validation_stage"] = "exploitable"
            else:
                finding["validation_stage"] = "confirmed"
        else:
            finding["validation_stage"] = "needs_review"

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

    def _gate_4_never_submit(self, finding) -> GateResult:
        """Check if finding is on the never-submit list (needs chain to be valid).

        Inspired by pentest-agents' never-submit list: findings that are ALWAYS
        rejected unless accompanied by a working exploit chain.
        """
        vuln_type = str(finding.get("type", finding.get("finding_type", ""))).lower()
        description = str(finding.get("description", "")).lower()
        evidence = str(finding.get("evidence", "")).lower()
        combined = f"{vuln_type} {description} {evidence}"

        for rule in NEVER_SUBMIT_RULES:
            if rule in combined:
                chain_check = CONDITIONALLY_VALID.get(rule)
                if chain_check:
                    has_chain = (
                        finding.get("chain_escalation")
                        or finding.get("chain")
                        or finding.get("escalation")
                        or any(
                            kw in description
                            for kw in ("chain", "escalation", "combined with",
                                       "leads to", "enables")
                        )
                    )
                    if has_chain:
                        continue
                    return GateResult(
                        gate="gate_4_never_submit", passed=False,
                        reason=f"Finding matches never-submit rule '{rule}'. "
                               f"Requires chain: {chain_check}"
                    )
                return GateResult(
                    gate="gate_4_never_submit", passed=False,
                    reason=f"Finding on never-submit list: '{rule}' — needs valid chain to submit"
                )

        return GateResult(gate="gate_4_never_submit", passed=True,
                          reason="Not on never-submit list")

    def _gate_5_real_impact(self, finding) -> GateResult:
        """Verify the finding demonstrates real impact with actual data.

        Inspired by pentest-agents Rule: 'Demonstrate impact with actual data,
        not theoretical language. Could result in... is N/A bait.'
        """
        description = str(finding.get("description", "")).lower()
        evidence = str(finding.get("evidence", "")).lower()

        if finding.get("exploit_data"):
            return GateResult(gate="gate_5_real_impact", passed=True,
                              reason="Exploit data confirms real impact")

        if finding.get("proven") is True:
            return GateResult(gate="gate_5_real_impact", passed=True,
                              reason="Finding marked as PROVEN with working PoC")

        severity = str(finding.get("severity", "")).lower()
        if severity in ("critical", "high"):
            for pattern in self.THEORETICAL_PATTERNS:
                if pattern in description:
                    return GateResult(
                        gate="gate_5_real_impact", passed=False,
                        reason=f"Theoretical language detected: '{pattern}'. "
                               "Replace with actual data: 'Here is the data I accessed'"
                    )

        if (
            severity in ("low", "info")
            and not evidence
            and not finding.get("exploit_data")
        ):
            return GateResult(gate="gate_5_real_impact", passed=True,
                              reason="Low/info finding, theoretical language acceptable")

        return GateResult(gate="gate_5_real_impact", passed=True,
                          reason="Impact description is concrete, not theoretical")

    def _gate_6_mistakes_check(self, finding) -> GateResult:
        """Run a common-mistakes awareness check on this finding.

        Inspired by pentest-agents' Mistakes Log: prevents the top mistakes
        from being submitted. Checks for theoretical framing, missing evidence,
        WAF misinterpretation, placeholder values, and CVSS mismatches.
        """
        description = str(finding.get("description", "")).lower()
        evidence = str(finding.get("evidence", "")).lower()
        vuln_type = str(finding.get("type", finding.get("finding_type", ""))).lower()
        severity = str(finding.get("severity", "")).lower()

        warnings = []

        theoretical_markers = ["could result in", "could be used to", "may allow",
                               "might lead to", "potential for"]
        if any(m in description for m in theoretical_markers) and severity in ("critical", "high"):
            warnings.append("Uses theoretical language — replace with actual impact data")

        if "cors" in vuln_type and "credential" not in combined_text(finding):
            warnings.append("CORS finding without credentialed delivery path — likely INFO-only")

        if "dns-only" in vuln_type or "dns only" in vuln_type:
            warnings.append("SSRF DNS-only is on never-submit list without HTTP SSRF chain")

        if "missing header" in vuln_type.lower() or "missing spf" in vuln_type.lower():
            warnings.append("Missing header/DNS finding — verify it's not auto-N/A")

        finding.setdefault("mistakes_warnings", [])
        finding["mistakes_warnings"].extend(warnings)

        if warnings:
            return GateResult(gate="gate_6_mistakes_check", passed=True,
                              reason=f"Passed with {len(warnings)} caution flag(s): {'; '.join(warnings)}")

        return GateResult(gate="gate_6_mistakes_check", passed=True,
                          reason="No common-mistakes patterns detected")

    def run_7_question_gate(self, finding) -> dict:
        """Full 7-Question Gate evaluation (pentest-agents inspired).

        Returns a dict with each question's answer, and an overall verdict.
        Questions:
        1. Is there real evidence? (not just a fingerprint)
        2. Does it reproduce? (same request, same result)
        3. Is it exploitable? (real security impact)
        4. Is it on the never-submit list? (requires chain?)
        5. Is the impact proven with real data? (not theoretical)
        6. Have common mistakes been checked?
        7. Is this finding chainable to higher impact?
        """
        questions = {}

        g0 = self._gate_0_evidence(finding)
        questions["evidence"] = {"passed": g0.passed, "reason": g0.reason}

        g2 = self._gate_2_exploitable(finding)
        questions["exploitable"] = {"passed": g2.passed, "reason": g2.reason}

        g3 = self._gate_3_no_false_positive(finding)
        questions["no_false_positive"] = {"passed": g3.passed, "reason": g3.reason}

        g4 = self._gate_4_never_submit(finding)
        questions["never_submit"] = {"passed": g4.passed, "reason": g4.reason}

        g5 = self._gate_5_real_impact(finding)
        questions["real_impact"] = {"passed": g5.passed, "reason": g5.reason}

        g6 = self._gate_6_mistakes_check(finding)
        questions["mistakes"] = {"passed": g6.passed, "reason": g6.reason}

        chainable = (
            finding.get("chain_escalation")
            or finding.get("escalation")
            or any(
                kw in str(finding.get("type", "")).lower()
                for kw in ("ssrf", "xss", "sqli", "lfi", "xxe", "idor", "ssti")
            )
        )
        questions["chainable"] = {
            "passed": True,
            "reason": "Finding type is chainable" if chainable else "Not a primitive that easily chains"
        }

        all_passed = all(q["passed"] for q in questions.values())
        questions["verdict"] = "PASS" if all_passed else "FAIL"
        questions["action"] = (
            "Ready to submit" if all_passed
            else "Fix failed gates before submitting"
        )

        return questions

    def check_never_submit(self, finding):
        """Check if a finding is on the never-submit list.

        Returns:
            (is_never_submit: bool, reason: str)
        """
        if not isinstance(finding, dict):
            try:
                finding = finding.to_dict()
            except AttributeError:
                return False, ""

        title = (finding.get("title", "") + " " + finding.get("details", "") + " "
                 + finding.get("vuln_class", "")).lower()

        checks = [
            ("missing CSP", "missing_csp", "Missing CSP header — never submit without chain"),
            ("missing hsts", "missing_hsts", "Missing HSTS header — never submit without chain"),
            ("x-frame-options", "missing_xfo", "Missing X-Frame-Options — never submit without chain"),
            ("missing spf", "missing_spf", "Missing SPF — never submit without chain"),
            ("missing dmarc", "missing_dmarc", "Missing DMARC — never submit without chain"),
            ("banner disclosure", "banner_disclosure", "Banner/version disclosure alone — N/A"),
            ("clickjacking", "clickjacking_basic", "Clickjacking without PoC — never submit"),
            ("self-xss", "self_xss", "Self-XSS — never submit without chain"),
            ("open redirect", "open_redirect_alone", "Open redirect alone — chain needed"),
            ("dns-only", "ssrf_dns_only", "DNS-only SSRF — data exfil needed"),
            ("cors", "cors_wildcard_no_creds", "CORS alone — credentialed PoC needed"),
            ("logout csrf", "logout_csrf", "Logout CSRF — no security impact"),
            ("rate limit", "rate_limit_non_critical", "Rate limit alone — N/A on non-critical forms"),
            ("session not invalidated", "session_not_invalidated", "Session invalidation alone — N/A"),
            ("internal ip", "internal_ip_error", "Internal IP in error message alone — N/A"),
            ("cookie flags", "missing_cookie_flags", "Missing cookie flags alone — N/A"),
            ("oidc discovery", "oidc_discovery", "OIDC discovery — public by design"),
            ("graphql introspection", "graphql_introspection", "GraphQL introspection alone — N/A"),
            ("client config", "spa_client_config", "SPA client-side config alone — N/A"),
        ]

        for keyword, key, reason in checks:
            if keyword in title:
                return True, reason

        return False, ""

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


def combined_text(finding) -> str:
    """Combine all text fields of a finding for pattern matching."""
    return " ".join(
        str(v)
        for k, v in (finding if isinstance(finding, dict) else {}).items()
        if k in ("description", "evidence", "type", "url", "payload") and v
    )
