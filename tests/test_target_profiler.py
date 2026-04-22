"""Tests for the Target Profiler & Priority Scoring."""
import pytest
from utils.target_profiler import TargetProfiler, ScanRecommendation


@pytest.fixture
def profiler():
    return TargetProfiler()


class TestTargetProfiler:
    def test_baseline_priority_score(self, profiler):
        score = profiler.compute_priority_score("https://example.com")
        assert score == 50.0  # baseline

    def test_tech_stack_bonus(self, profiler):
        tech = [{"name": "PHP"}, {"name": "Apache"}, {"name": "MySQL"}]
        score = profiler.compute_priority_score("https://example.com", tech_stack=tech)
        assert score > 50.0  # tech stack gives bonus

    def test_vulnerable_tech_bonus(self, profiler):
        tech = [{"name": "WordPress"}, {"name": "PHP"}]
        score = profiler.compute_priority_score("https://example.com", tech_stack=tech)
        assert score >= 64  # baseline + tech bonus + vuln tech bonus

    def test_waf_penalty(self, profiler):
        score = profiler.compute_priority_score("https://example.com", waf_name="Cloudflare")
        assert score < 50.0  # WAF gives penalty

    def test_past_findings_bonus(self, profiler):
        score = profiler.compute_priority_score("https://example.com", past_findings=3)
        assert score > 50.0

    def test_repeated_scans_penalty(self, profiler):
        score = profiler.compute_priority_score("https://example.com", past_scans=5, past_findings=0)
        assert score < 50.0  # diminishing returns

    def test_defence_penalties(self, profiler):
        from utils.scan_intelligence import Defence
        defences = [
            Defence(defence_type="rate_limit"),
            Defence(defence_type="captcha"),
        ]
        score = profiler.compute_priority_score("https://example.com", defences=defences)
        assert score < 50.0

    def test_score_clamped_0_100(self, profiler):
        from utils.scan_intelligence import Defence
        defences = [Defence(defence_type="ip_block"), Defence(defence_type="captcha"),
                     Defence(defence_type="rate_limit"), Defence(defence_type="hardened")]
        score = profiler.compute_priority_score("https://example.com", waf_name="Akamai", defences=defences)
        assert score >= 0.0
        assert score <= 100.0

    def test_recommended_modules_php(self, profiler):
        tech = [{"name": "PHP"}]
        modules = profiler.get_recommended_modules("https://example.com", tech_stack=tech)
        assert "lfi" in modules
        assert "sqli" in modules

    def test_recommended_modules_node(self, profiler):
        tech = [{"name": "Node.js"}]
        modules = profiler.get_recommended_modules("https://example.com", tech_stack=tech)
        assert "ssrf" in modules

    def test_waf_adds_bypass_modules(self, profiler):
        modules = profiler.get_recommended_modules("https://example.com", waf_name="Cloudflare")
        assert "forbidden_bypass" in modules
        assert "smuggling" in modules

    def test_scan_recommendation(self, profiler):
        rec = profiler.get_scan_recommendation(
            "https://example.com",
            tech_stack=[{"name": "PHP"}, {"name": "Apache"}],
            waf_name="ModSecurity",
        )
        assert isinstance(rec, ScanRecommendation)
        assert rec.priority_score > 0
        assert len(rec.recommended_modules) > 0
        assert "ModSecurity" in rec.payload_strategy

    def test_first_scan_note(self, profiler):
        rec = profiler.get_scan_recommendation("https://example.com", past_scans=0)
        assert any("First scan" in n for n in rec.notes)

    def test_context_string(self, profiler):
        rec = profiler.get_scan_recommendation(
            "https://example.com",
            tech_stack=[{"name": "PHP"}],
        )
        ctx = rec.to_context_string()
        assert "example.com" in ctx
        assert "Recommended modules" in ctx
