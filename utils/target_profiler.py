"""
cyberm4fia-scanner — Target Profiler & Priority Scoring
Builds intelligence profiles for targets and scores them for scan prioritization.
"""
from dataclasses import dataclass, field
from urllib.parse import urlparse



# Tech stack → module recommendations
TECH_MODULE_MAP = {
    "php": ["lfi", "rfi", "sqli", "file_upload", "deserialization"],
    "wordpress": ["lfi", "sqli", "xss", "file_upload", "brute_force"],
    "java": ["deserialization", "ssti", "xxe", "sqli"],
    "spring": ["deserialization", "ssti", "sqli", "ssrf"],
    "node": ["proto_pollution", "ssrf", "ssti", "xss", "nosql"],
    "express": ["proto_pollution", "ssrf", "ssti", "xss"],
    "react": ["xss", "dom_xss", "open_redirect", "csrf"],
    "angular": ["xss", "dom_xss", "ssti", "open_redirect"],
    "vue": ["xss", "dom_xss", "open_redirect"],
    "next": ["ssrf", "xss", "open_redirect", "ssti"],
    "django": ["ssti", "sqli", "csrf", "ssrf"],
    "flask": ["ssti", "sqli", "lfi", "ssrf"],
    "rails": ["deserialization", "sqli", "csrf", "ssti"],
    "asp.net": ["deserialization", "sqli", "xxe", "file_upload"],
    "nginx": ["header_inject", "smuggling", "forbidden_bypass"],
    "apache": ["lfi", "header_inject", "smuggling"],
    "iis": ["lfi", "header_inject", "file_upload"],
    "graphql": ["api_scanner", "sqli", "auth_bypass"],
    "rest": ["api_scanner", "sqli", "auth_bypass", "race_condition"],
}

# WAF strength multiplier (lower = harder to exploit)
WAF_STRENGTH = {
    "Cloudflare": 0.4,
    "Akamai": 0.3,
    "AWS WAF": 0.5,
    "Imperva / Incapsula": 0.35,
    "F5 BIG-IP ASM": 0.4,
    "ModSecurity": 0.6,
    "Wordfence": 0.7,
    "Sucuri": 0.5,
    "Generic WAF": 0.6,
}


@dataclass
class ScanRecommendation:
    """Full scan recommendation based on target profile."""
    target: str
    priority_score: float
    recommended_modules: list = field(default_factory=list)
    skip_modules: list = field(default_factory=list)
    payload_strategy: str = ""
    estimated_time_minutes: int = 10
    notes: list = field(default_factory=list)

    def to_context_string(self):
        lines = [
            f"Target: {self.target} (priority: {self.priority_score:.0f}/100)",
            f"Recommended modules: {', '.join(self.recommended_modules[:8])}",
        ]
        if self.skip_modules:
            lines.append(f"Skip: {', '.join(self.skip_modules[:5])}")
        if self.payload_strategy:
            lines.append(f"Strategy: {self.payload_strategy}")
        for n in self.notes[:3]:
            lines.append(f"  \u2139 {n}")
        return "\n".join(lines)


class TargetProfiler:
    """Build intelligence profiles and compute priority scores."""

    def __init__(self):
        self._intel = None

    def _get_intel(self):
        if self._intel is None:
            try:
                from utils.scan_intelligence import get_scan_intelligence
                self._intel = get_scan_intelligence()
            except Exception:
                pass
        return self._intel

    def build_profile(self, target):
        """Build a target profile from intelligence data."""
        intel = self._get_intel()
        if intel:
            return intel.get_target_profile(target)
        # Fallback: empty profile
        from utils.scan_intelligence import TargetIntel
        domain = urlparse(target).hostname or target
        return TargetIntel(target=target, domain=domain)

    def compute_priority_score(self, target, tech_stack=None, waf_name="",
                                defences=None, past_findings=0, past_scans=0):
        """Compute a 0-100 priority score for a target.

        Higher score = more likely to find vulnerabilities.

        Scoring:
        + Large tech stack (more attack surface)
        + Dynamic content indicators
        + Known vulnerable technologies
        + Previous successful findings
        - WAF detected (penalty based on WAF strength)
        - Rate limiting / captcha
        - Many past scans with no findings
        """
        score = 50.0  # Baseline

        # Tech stack bonus (+0-15)
        if tech_stack:
            score += min(len(tech_stack) * 2, 15)
            # Bonus for known-vulnerable tech
            vuln_tech = {"php", "wordpress", "drupal", "joomla", "struts", "spring"}
            tech_names = {str(t.get("name", t) if isinstance(t, dict) else t).lower()
                          for t in tech_stack}
            if tech_names & vuln_tech:
                score += 10

        # Past findings bonus (+0-15)
        if past_findings > 0:
            score += min(past_findings * 3, 15)

        # WAF penalty (-5 to -30)
        if waf_name:
            strength = WAF_STRENGTH.get(waf_name, 0.5)
            penalty = (1 - strength) * 30
            score -= penalty

        # Defence penalties
        if defences:
            for d in defences:
                dtype = d.defence_type if hasattr(d, "defence_type") else str(d)
                if dtype == "rate_limit":
                    score -= 10
                elif dtype == "captcha":
                    score -= 15
                elif dtype == "ip_block":
                    score -= 20
                elif dtype == "hardened":
                    score -= 10

        # Diminishing returns on repeated scans with no findings
        if past_scans > 2 and past_findings == 0:
            score -= min(past_scans * 5, 20)

        return max(0.0, min(100.0, score))

    def get_recommended_modules(self, target, tech_stack=None, waf_name=""):
        """Recommend scan modules based on target characteristics."""
        modules = set()

        # Always recommended
        modules.update(["xss", "sqli", "cors", "header_inject"])

        # Tech-based recommendations
        if tech_stack:
            for tech in tech_stack:
                name = str(tech.get("name", tech) if isinstance(tech, dict) else tech).lower()
                for key, mods in TECH_MODULE_MAP.items():
                    if key in name:
                        modules.update(mods)

        # WAF-specific
        if waf_name:
            modules.add("forbidden_bypass")
            modules.add("smuggling")

        return sorted(modules)

    def get_scan_recommendation(self, target, tech_stack=None, waf_name="",
                                 defences=None, past_findings=0, past_scans=0):
        """Generate a full scan recommendation."""
        score = self.compute_priority_score(
            target, tech_stack, waf_name, defences, past_findings, past_scans
        )
        modules = self.get_recommended_modules(target, tech_stack, waf_name)

        # Get skip modules from intelligence
        skip = []
        intel = self._get_intel()
        if intel:
            report = intel.query_intelligence(target)
            skip = report.modules_to_skip

        # Determine payload strategy
        if waf_name:
            strategy = f"Use WAF bypass payloads targeting {waf_name}. Employ encoding, case randomization, and comment injection."
        elif score > 70:
            strategy = "High-value target. Use aggressive payloads with full coverage."
        else:
            strategy = "Standard payload set. Focus on common injection vectors."

        notes = []
        if past_scans == 0:
            notes.append("First scan — full reconnaissance recommended")
        if waf_name:
            notes.append(f"WAF detected: {waf_name}. Expect higher block rate.")
        if past_findings > 0:
            notes.append(f"{past_findings} findings in previous scans — target has known weaknesses")

        # Estimated time
        est_time = max(5, len(modules) * 2)
        if waf_name:
            est_time = int(est_time * 1.5)

        return ScanRecommendation(
            target=target, priority_score=score,
            recommended_modules=modules, skip_modules=skip,
            payload_strategy=strategy, estimated_time_minutes=est_time,
            notes=notes,
        )
