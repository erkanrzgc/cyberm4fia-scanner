import httpx
import pytest
from unittest.mock import patch, Mock

from utils.ai import NvidiaApiClient
from utils.ai_exploit_agent import AIExploitAgent, ExploitContext

@pytest.fixture
def mock_httpx_post():
    with patch("httpx.post") as mock_post:
        yield mock_post

@pytest.fixture
def mock_httpx_get():
    with patch("httpx.get") as mock_get:
        yield mock_get

def test_ai_client_generate_success(mock_httpx_post):
    """Test standard prompt generation via NVIDIA client."""
    # Mock chat response (OpenAI-compatible)
    mock_chat = Mock()
    mock_chat.status_code = 200
    mock_chat.json.return_value = {
        "choices": [{
            "message": {"content": "Analysis: Found Reflected XSS."}
        }]
    }
    mock_httpx_post.return_value = mock_chat

    client = NvidiaApiClient(model="meta/llama-3.1-70b-instruct", api_key="test-key")
    response = client.generate("Analyze <script>alert(1)</script>", "You are a cyber security expert.")
    
    assert response == "Analysis: Found Reflected XSS."
    mock_httpx_post.assert_called_once()
    kwargs = mock_httpx_post.call_args.kwargs
    assert "json" in kwargs
    assert kwargs["json"]["model"] == "meta/llama-3.1-70b-instruct"
    assert len(kwargs["json"]["messages"]) == 2

def test_ai_client_timeout_returns_none(mock_httpx_post):
    """Test AI client handles timeout gracefully."""
    mock_httpx_post.side_effect = httpx.TimeoutException("NVIDIA API timed out")
    
    client = NvidiaApiClient(model="fake-model", api_key="test-key")
    response = client.generate("Hello")
    assert response in (None, "")

def test_ai_exploit_agent_integration(mock_httpx_post):
    """Test the AI exploit agent orchestration flow with NVIDIA backend."""
    mock_chat = Mock()
    mock_chat.status_code = 200
    mock_chat.json.return_value = {
        "choices": [{
            "message": {"content": "```json\n{\"plan\": \"Exploit SQLi\", \"code\": \"print('Exploited')\"}\n```"}
        }]
    }
    mock_httpx_post.return_value = mock_chat

    client = NvidiaApiClient(model="Llama-3", api_key="test-key")
    agent = AIExploitAgent(ai_client=client)
    ctx = ExploitContext(url="http://target.com", vuln_type="SQLi", param="id")
    
    # Use internal parsing method
    result = agent._analyze_context(ctx, 1)
    
    assert result is not None
    assert "print('Exploited')" in result.get("code", "")
    assert "Exploit SQLi" in result.get("plan", "")
