"""
Tests for utils/ai.py — Ollama AI Integration
Tests run without requiring Ollama to be installed.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.ai import OllamaClient, generate_smart_payloads, generate_scan_summary


class TestOllamaClientInit:
    """Test OllamaClient initialization (without real Ollama)."""

    def test_default_model(self):
        client = OllamaClient.__new__(OllamaClient)
        client.model = "whiterabbitneo"
        client.base_url = "http://localhost:11434"
        client.available = False
        assert client.model == "whiterabbitneo"

    def test_custom_model(self):
        client = OllamaClient.__new__(OllamaClient)
        client.model = "mistral"
        assert client.model == "mistral"

    def test_unavailable_client_returns_empty(self):
        client = OllamaClient.__new__(OllamaClient)
        client.model = "whiterabbitneo"
        client.base_url = "http://localhost:11434"
        client.available = False
        result = client.generate("test prompt")
        assert result == ""

    def test_unavailable_generate_no_crash(self):
        client = OllamaClient.__new__(OllamaClient)
        client.available = False
        assert client.generate("test") == ""


class TestAIFunctions:
    """Test AI analysis functions with mocked client."""

    def _make_mock_client(self, response: str = ""):
        client = OllamaClient.__new__(OllamaClient)
        client.available = True
        client.model = "whiterabbitneo"
        client._mock_response = response

        def mock_generate(prompt, system="", temperature=0.3):
            return client._mock_response

        client.generate = mock_generate
        return client

    def test_generate_smart_payloads_unavailable(self):
        client = OllamaClient.__new__(OllamaClient)
        client.available = False
        result = generate_smart_payloads(client, "XSS")
        assert result == []

    def test_generate_smart_payloads_valid_json(self):
        client = self._make_mock_client(
            '["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]'
        )
        result = generate_smart_payloads(client, "XSS")
        assert isinstance(result, list)
        assert len(result) == 2

    def test_generate_smart_payloads_invalid_json(self):
        client = self._make_mock_client("not json")
        result = generate_smart_payloads(client, "XSS")
        assert result == []

    def test_generate_scan_summary_unavailable(self):
        client = OllamaClient.__new__(OllamaClient)
        client.available = False
        result = generate_scan_summary(client, [], "https://example.com", {})
        assert result == ""

    def test_generate_scan_summary_available(self):
        client = self._make_mock_client(
            "Executive summary: 3 critical vulnerabilities found."
        )
        result = generate_scan_summary(
            client,
            [{"type": "XSS_Param"}, {"type": "SQLi_Param"}],
            "https://example.com",
            {"requests": 120, "vulns": 2, "waf": 0},
        )
        assert "Executive summary" in result


class TestFalsePositiveFilter:
    """Test false positive detection logic."""

    def _make_mock_client(self, response: str):
        client = OllamaClient.__new__(OllamaClient)
        client.available = True

        def mock_generate(prompt, system="", temperature=0.3):
            return response

        client.generate = mock_generate
        return client

    def test_filter_keeps_real_vuln(self):
        from utils.ai import detect_false_positives

        client = self._make_mock_client(
            '{"real": true, "confidence": 90, "reason": "valid"}'
        )
        vulns = [{"type": "XSS_Param", "url": "http://ex.com", "payload": "<script>"}]
        result = detect_false_positives(client, vulns)
        assert len(result) == 1
        assert result[0].get("ai_verified") is True

    def test_filter_removes_fp(self):
        from utils.ai import detect_false_positives

        client = self._make_mock_client(
            '{"real": false, "confidence": 20, "reason": "reflection only"}'
        )
        vulns = [{"type": "XSS_Param", "url": "http://ex.com", "payload": "<script>"}]
        result = detect_false_positives(client, vulns)
        assert len(result) == 0

    def test_filter_empty_list(self):
        from utils.ai import detect_false_positives

        client = self._make_mock_client("{}")
        result = detect_false_positives(client, [])
        assert result == []


class TestAIModule:
    """Test module-level configuration."""

    def test_default_model_constant(self):
        from utils.ai import DEFAULT_MODEL

        assert DEFAULT_MODEL == "whiterabbitneo"

    def test_ollama_base_constant(self):
        from utils.ai import OLLAMA_BASE

        assert "11434" in OLLAMA_BASE
        assert "localhost" in OLLAMA_BASE

    def test_init_ai_returns_client(self):
        # Should not crash even without Ollama running
        from utils.ai import init_ai

        client = init_ai(model="mistral")
        assert client is not None
        assert client.model == "mistral"
        assert isinstance(client.available, bool)

    def test_get_ai_returns_same_instance(self):
        from utils.ai import init_ai, get_ai

        init_ai(model="mistral")
        client1 = get_ai()
        client2 = get_ai()
        assert client1 is client2
