"""Tests for the PortSwigger-inspired + garak sprint additions.

Covers:
* utils.external_tools.garak.GarakTool — preflight, env aliasing,
  stdout row parsing, severity mapping
* modules.llm_endpoint_detector — path probe, body / header / HTML
  fingerprinting
* modules.authz_audit — high/low/no-auth equivalence + verdict shape
* modules.cache_poisoning — looks_cached + token reflection bookkeeping
* modules.esi_injection — payload sentinel + decision tree
* All 4 new SKILL.md files load via the AI skill loader
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

pytestmark = pytest.mark.unit


# ── GarakTool ────────────────────────────────────────────────────────


class TestGarakTool:
    def test_binary_default(self):
        from utils.external_tools import GarakTool
        t = GarakTool()
        assert t.binary == "garak"
        assert t.default_timeout >= 600  # plenty of room for LLM probes

    def test_build_command_uses_defaults(self):
        from utils.external_tools import GarakTool
        cmd = GarakTool().get_command("https://chat.example/v1/chat/completions")
        # Either ``garak`` wrapper or ``python -m garak``
        assert cmd[0] in {"garak", "python"}
        # Critical flags survive
        assert "--target_name" in cmd
        assert "--probes" in cmd
        assert "--generations" in cmd

    def test_parse_output_extracts_fail_rows(self):
        from utils.external_tools import GarakTool
        stdout = (
            "encoding.InjectBase64           openai-gpt: FAIL   ok=12/40 (30.0%)\n"
            "latentinjection.HijackHateful   openai-gpt: PASS   ok=40/40 (100.0%)\n"
            "dan.Dan_11_0                    openai-gpt: FAIL   ok=2/20  (10.0%)\n"
        )
        parsed = GarakTool().parse_output(stdout, stderr="", returncode=0)
        rows = parsed["rows"]
        assert len(rows) == 3
        fails = [r for r in rows if r["verdict"] == "FAIL"]
        assert len(fails) == 2
        assert fails[0]["failed"] == 28
        assert fails[0]["fail_rate"] == 0.7

    def test_to_findings_skips_passing_probes(self):
        from utils.external_tools import GarakTool
        parsed = {"rows": [
            {"probe": "encoding.X", "verdict": "FAIL", "passed": 0, "total": 10, "failed": 10, "fail_rate": 1.0},
            {"probe": "dan.Y",      "verdict": "PASS", "passed": 10, "total": 10, "failed": 0, "fail_rate": 0.0},
            {"probe": "leakreplay.Z", "verdict": "FAIL", "passed": 10, "total": 10, "failed": 0, "fail_rate": 0.0},
        ], "report_jsonl": ""}
        out = GarakTool().to_findings(parsed, target="https://chat/x")
        # Only the first row (FAIL + failed>0) survives
        assert len(out) == 1
        assert out[0]["type"].startswith("LLM_")
        assert out[0]["verification_state"] == "verified"

    def test_run_aliases_nvidia_api_key(self, monkeypatch):
        """When NVIDIA_API_KEY is set and NIM_API_KEY is not, run() bridges them."""
        from utils.external_tools import GarakTool
        monkeypatch.setenv("NVIDIA_API_KEY", "nvapi-stub")
        monkeypatch.delenv("NIM_API_KEY", raising=False)

        # Stub the binary preflight + subprocess.run inside run()
        captured_env = {}

        def fake_run(cmd, capture_output, text, timeout, env, check):
            captured_env.update(env)
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch.object(GarakTool, "is_available", return_value=True), \
             patch("subprocess.run", side_effect=fake_run):
            GarakTool().run("https://chat/x")

        assert captured_env.get("NIM_API_KEY") == "nvapi-stub"


# ── LLM endpoint detector ────────────────────────────────────────────


class TestLLMDetector:
    def test_openai_chat_completion_body_shape(self):
        from modules.llm_endpoint_detector import _check_response_for_llm
        body = '{"id":"chatcmpl-abc","choices":[{"message":{"content":"hi"}}]}'
        ok, ev = _check_response_for_llm(body)
        assert ok
        assert "message" in ev or "id prefix" in ev

    def test_ollama_response_body_shape(self):
        from modules.llm_endpoint_detector import _check_response_for_llm
        ok, ev = _check_response_for_llm('{"response":"hello"}')
        assert ok
        assert "response" in ev

    def test_anthropic_content_shape(self):
        from modules.llm_endpoint_detector import _check_response_for_llm
        body = '{"id":"msg_1","content":[{"type":"text","text":"hi"}]}'
        ok, ev = _check_response_for_llm(body)
        assert ok
        assert "Anthropic" in ev

    def test_non_llm_json_rejected(self):
        from modules.llm_endpoint_detector import _check_response_for_llm
        ok, _ = _check_response_for_llm('{"users":[1,2,3]}')
        assert not ok

    def test_header_fingerprint(self):
        from modules.llm_endpoint_detector import _check_headers_for_llm
        ok, ev = _check_headers_for_llm({"Server": "vllm/0.3"})
        assert ok
        assert "vllm" in ev

    def test_html_fingerprint(self):
        from modules.llm_endpoint_detector import _check_html_for_llm
        html = '<script src="https://api.openai.com/v1/chat"></script>'
        ok, ev = _check_html_for_llm(html)
        assert ok

    def test_findings_round_trip(self):
        from modules.llm_endpoint_detector import (
            LLMEndpoint,
            endpoints_to_findings,
        )
        eps = [LLMEndpoint(
            url="https://x/api/chat",
            confidence="high",
            evidence="body shape: choices[].message",
            suggested_target_type="rest",
        )]
        findings = endpoints_to_findings(eps)
        assert findings[0]["type"] == "LLM_Endpoint_Discovered"
        assert findings[0]["severity"] == "INFO"


# ── Authz audit ──────────────────────────────────────────────────────


class TestAuthzAudit:
    def test_equivalence_same_status_same_length(self):
        from modules.authz_audit import _responses_equivalent
        ok, reason = _responses_equivalent(200, "a" * 100, 200, "b" * 100)
        assert ok
        assert "within" in reason

    def test_equivalence_status_mismatch(self):
        from modules.authz_audit import _responses_equivalent
        ok, _ = _responses_equivalent(200, "a" * 100, 403, "denied")
        assert not ok

    def test_equivalence_length_outside_tolerance(self):
        from modules.authz_audit import _responses_equivalent
        ok, _ = _responses_equivalent(200, "a" * 100, 200, "b" * 200)
        assert not ok

    def test_strip_auth_drops_known_headers(self):
        from modules.authz_audit import _strip_auth_headers
        h = {
            "Authorization": "Bearer abc",
            "Cookie": "session=xyz",
            "X-API-Key": "k",
            "User-Agent": "test/1",
        }
        out = _strip_auth_headers(h)
        assert "Authorization" not in out
        assert "Cookie" not in out
        assert "X-API-Key" not in out
        assert out["User-Agent"] == "test/1"

    def test_audit_emits_broken_access_when_noauth_succeeds(self, monkeypatch):
        from modules.authz_audit import (
            AuthzProbeRequest,
            audit_requests,
            verdicts_to_findings,
        )

        # Stub smart_request — high-priv returns 200/100b, no-auth ALSO 200/100b
        from unittest.mock import MagicMock

        def fake_smart_request(method, url, headers=None, data=None):
            return MagicMock(status_code=200, text="x" * 100)

        monkeypatch.setattr("utils.request.smart_request", fake_smart_request)
        req = AuthzProbeRequest(
            method="GET",
            url="https://x/api/admin/users",
            headers={"Authorization": "Bearer admin"},
        )
        verdicts = audit_requests([req])
        assert len(verdicts) == 1
        assert verdicts[0].enforced is False
        findings = verdicts_to_findings(verdicts)
        assert len(findings) == 1
        assert findings[0]["type"] == "Broken_Access_Control_NoAuth"
        assert findings[0]["severity"] == "HIGH"


# ── Cache poisoning ──────────────────────────────────────────────────


class TestCachePoisoning:
    def test_cache_hit_recognised(self):
        from modules.cache_poisoning import _looks_cached
        ok, ev = _looks_cached({"X-Cache": "HIT"})
        assert ok
        assert "HIT" in ev

    def test_cache_miss_not_flagged(self):
        from modules.cache_poisoning import _looks_cached
        ok, _ = _looks_cached({"X-Cache": "MISS"})
        assert not ok

    def test_age_header_implies_cache(self):
        from modules.cache_poisoning import _looks_cached
        ok, ev = _looks_cached({"Age": "42"})
        assert ok
        assert "age=42" in ev

    def test_age_zero_not_cached(self):
        from modules.cache_poisoning import _looks_cached
        ok, _ = _looks_cached({"Age": "0"})
        assert not ok

    def test_probe_header_catalogue_complete(self):
        from modules.cache_poisoning import _PROBE_HEADERS
        # Must cover the classic Web Cache Entanglement set
        names = {h.lower() for h in _PROBE_HEADERS}
        for required in (
            "x-forwarded-host", "x-original-url", "x-rewrite-url",
            "x-forwarded-scheme", "forwarded", "true-client-ip",
        ):
            assert required in names


# ── ESI injection ────────────────────────────────────────────────────


class TestESI:
    def test_payload_contains_sentinel(self):
        from modules.esi_injection import _esi_payload
        p = _esi_payload("tokenXYZ")
        assert "<esi:vars>" in p
        assert "tokenXYZ-INSIDE" in p

    def test_processed_vs_reflected_decision(self, monkeypatch):
        """When the response strips <esi:vars> and shows the sentinel,
        we flag ESI processing. When the raw tag is reflected, we don't."""
        from modules.esi_injection import _scan_param
        from unittest.mock import MagicMock

        # Case 1: ESI processed — sentinel without surrounding tag
        def fake_processed(method, url, params=None, data=None, headers=None):
            return MagicMock(text="prefix esi-token123-INSIDE suffix")

        monkeypatch.setattr("utils.request.smart_request", fake_processed)
        # patch the random token so we can predict
        with patch("modules.esi_injection._random_token", return_value="esi-token123"):
            hit = _scan_param("https://x/q", "q", method="get")
        assert hit is not None
        assert "ESI tag was processed" in hit["evidence"]

        # Case 2: raw reflection (XSS, not ESI)
        def fake_reflected(method, url, params=None, data=None, headers=None):
            return MagicMock(text="prefix <esi:vars>esi-token123-INSIDE</esi:vars> suffix")

        monkeypatch.setattr("utils.request.smart_request", fake_reflected)
        with patch("modules.esi_injection._random_token", return_value="esi-token123"):
            hit2 = _scan_param("https://x/q", "q", method="get")
        assert hit2 is None  # raw reflection — not flagged as ESI


# ── New SKILL.md files load via the AI skill loader ─────────────────


class TestNewSkills:
    @pytest.mark.parametrize("slug,keyword", [
        ("offensive-llm-app-pentest", "llm_endpoint"),
        ("offensive-cache-poisoning", "cache_poisoning"),
        ("offensive-authz-bypass-systematic", "authz_audit"),
        ("offensive-esi-injection", "esi"),
    ])
    def test_skill_resolves_via_keyword(self, slug, keyword):
        from utils.ai import _load_skill_for_vuln, skill_slug_for_vuln
        assert skill_slug_for_vuln(keyword) == slug
        body = _load_skill_for_vuln(keyword)
        assert body
        assert "EXPERT SKILL KNOWLEDGE BASE" in body
