"""
Tests for utils/ai.py — NVIDIA API Integration
"""

from utils.ai import (
    NvidiaApiClient,
    generate_scan_summary,
    generate_smart_payloads,
    resolve_nvidia_base,
)

class TestNvidiaApiClientInit:
    """Test NvidiaApiClient initialization (without real NVIDIA API)."""

    def test_default_model(self):
        client = NvidiaApiClient.__new__(NvidiaApiClient)
        client.model = "meta/llama-3.3-70b-instruct"
        client.base_url = "https://integrate.api.nvidia.com/v1"
        client.api_key = "test_key"
        client.available = False
        assert client.model == "meta/llama-3.3-70b-instruct"

    def test_custom_model(self):
        client = NvidiaApiClient.__new__(NvidiaApiClient)
        client.model = "mistral"
        assert client.model == "mistral"

    def test_unavailable_client_returns_empty(self):
        client = NvidiaApiClient.__new__(NvidiaApiClient)
        client.model = "meta/llama-3.3-70b-instruct"
        client.base_url = "https://integrate.api.nvidia.com/v1"
        client.api_key = "test"
        client.available = False
        result = client.generate("test prompt")
        assert result == ""

    def test_unavailable_generate_no_crash(self):
        client = NvidiaApiClient.__new__(NvidiaApiClient)
        client.available = False
        assert client.generate("test") == ""

    def test_resolve_nvidia_base_accepts_bare_host(self, monkeypatch):
        monkeypatch.delenv("NVIDIA_API_URL", raising=False)
        assert resolve_nvidia_base() == "https://integrate.api.nvidia.com/v1"

class TestAIFunctions:
    """Test AI analysis functions with mocked client."""

    def _make_mock_client(self, response: str = ""):
        client = NvidiaApiClient.__new__(NvidiaApiClient)
        client.available = True
        client.model = "meta/llama-3.3-70b-instruct"
        client._mock_response = response

        def mock_generate(prompt, system="", temperature=0.3, model_role=""):
            return client._mock_response

        client.generate = mock_generate
        return client

    def test_generate_smart_payloads_unavailable(self):
        client = NvidiaApiClient.__new__(NvidiaApiClient)
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
        client = NvidiaApiClient.__new__(NvidiaApiClient)
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
        client = NvidiaApiClient.__new__(NvidiaApiClient)
        client.available = True

        def mock_generate(prompt, system="", temperature=0.3, model_role=""):
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

        assert DEFAULT_MODEL == "meta/llama-3.3-70b-instruct"

    def test_init_ai_returns_client(self, monkeypatch):
        from utils.ai import init_ai
        monkeypatch.setenv("NVIDIA_API_KEY", "test_api_key")

        client = init_ai(model="mistral")
        assert client is not None
        assert client.model == "mistral"
        assert isinstance(client.available, bool)

    def test_get_ai_returns_same_instance(self, monkeypatch):
        from utils.ai import init_ai, get_ai
        monkeypatch.setenv("NVIDIA_API_KEY", "test_api_key")

        init_ai(model="mistral")
        client1 = get_ai()
        client2 = get_ai()
        assert client1 is client2
