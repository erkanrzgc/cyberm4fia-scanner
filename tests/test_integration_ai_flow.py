import httpx
import pytest
from unittest.mock import patch, Mock

from utils.ai import NvidiaApiClient
from utils.ai_exploit_agent import AIExploitAgent, ExploitContext


def _ok_response(json_body):
    """Build a Mock response with status_code=200 and the given JSON body."""
    resp = Mock()
    resp.status_code = 200
    resp.json.return_value = json_body
    return resp


@pytest.fixture
def mock_httpx_post():
    """Patch httpx.post AND httpx.get so NvidiaApiClient._check_connection
    succeeds offline and generate() can hit the patched post path."""
    with patch("httpx.post") as mock_post, patch("httpx.get") as mock_get:
        mock_get.return_value = _ok_response({"data": []})
        yield mock_post

@pytest.fixture
def mock_httpx_get():
    with patch("httpx.get") as mock_get:
        yield mock_get

def test_ai_client_generate_success(mock_httpx_post):
    """Test standard prompt generation via NVIDIA client."""
    mock_httpx_post.return_value = _ok_response({
        "choices": [{"message": {"content": "Analysis: Found Reflected XSS."}}],
    })

    client = NvidiaApiClient(model="meta/llama-3.3-70b-instruct", api_key="test-key")
    response = client.generate("Analyze <script>alert(1)</script>", "You are a cyber security expert.")

    assert response == "Analysis: Found Reflected XSS."
    mock_httpx_post.assert_called_once()
    kwargs = mock_httpx_post.call_args.kwargs
    assert "json" in kwargs
    assert kwargs["json"]["model"] == "meta/llama-3.3-70b-instruct"
    assert len(kwargs["json"]["messages"]) == 2

def test_ai_client_timeout_returns_none(mock_httpx_post):
    """Test AI client handles timeout gracefully."""
    mock_httpx_post.side_effect = httpx.TimeoutException("NVIDIA API timed out")

    client = NvidiaApiClient(model="fake-model", api_key="test-key")
    response = client.generate("Hello")
    assert response in (None, "")

def test_ai_exploit_agent_integration(mock_httpx_post):
    """Test the AI exploit agent orchestration flow with NVIDIA backend."""
    mock_httpx_post.return_value = _ok_response({
        "choices": [{
            "message": {
                "content": "```json\n{\"plan\": \"Exploit SQLi\", \"code\": \"print('Exploited')\"}\n```",
            },
        }],
    })

    client = NvidiaApiClient(model="Llama-3", api_key="test-key")
    agent = AIExploitAgent(ai_client=client)
    ctx = ExploitContext(url="http://target.com", vuln_type="SQLi", param="id")

    # Use internal parsing method
    result = agent._analyze_context(ctx, 1)

    assert result is not None
    assert "print('Exploited')" in result.get("code", "")
    assert "Exploit SQLi" in result.get("plan", "")
