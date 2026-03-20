import httpx
import pytest
from unittest.mock import patch, Mock

from utils.ai import OllamaClient
from utils.ai_exploit_agent import AIExploitAgent, ExploitContext

@pytest.fixture
def mock_httpx_post():
    with patch("httpx.post") as mock_post:
        yield mock_post

@pytest.fixture
def mock_httpx_get():
    with patch("httpx.get") as mock_get:
        yield mock_get

def test_ai_client_generate_success(mock_httpx_post, mock_httpx_get):
    """Test standard prompt generation via Ollama client."""
    # Mock tags to pretend model is installed
    mock_tags = Mock()
    mock_tags.status_code = 200
    mock_tags.json.return_value = {"models": [{"name": "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B:latest"}]}
    mock_httpx_get.return_value = mock_tags

    # Mock chat response
    mock_chat = Mock()
    mock_chat.status_code = 200
    mock_chat.json.return_value = {"message": {"content": "Analysis: Found Reflected XSS."}}
    mock_httpx_post.return_value = mock_chat

    client = OllamaClient(model="WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B")
    response = client.generate("Analyze <script>alert(1)</script>", "You are a cyber security expert.")
    
    assert response == "Analysis: Found Reflected XSS."
    mock_httpx_post.assert_called_once()
    kwargs = mock_httpx_post.call_args.kwargs
    assert "json" in kwargs
    assert kwargs["json"]["model"] == "WhiteRabbitNeo/Llama-3.1-WhiteRabbitNeo-2-8B"
    assert len(kwargs["json"]["messages"]) == 2

def test_ai_client_timeout_returns_none(mock_httpx_post, mock_httpx_get):
    """Test AI client handles timeout gracefully."""
    # Mock tags 
    mock_tags = Mock()
    mock_tags.status_code = 200
    mock_tags.json.return_value = {"models": [{"name": "fake-model"}]}
    mock_httpx_get.return_value = mock_tags

    mock_httpx_post.side_effect = httpx.TimeoutException("Ollama timed out")
    
    client = OllamaClient(model="fake-model")
    response = client.generate("Hello")
    assert response in (None, "")

def test_ai_exploit_agent_integration(mock_httpx_post, mock_httpx_get):
    """Test the AI exploit agent orchestration flow."""
    mock_tags = Mock()
    mock_tags.status_code = 200
    mock_tags.json.return_value = {"models": [{"name": "Llama-3"}]}
    mock_httpx_get.return_value = mock_tags

    mock_chat = Mock()
    mock_chat.status_code = 200
    mock_chat.json.return_value = {"message": {"content": "```json\n{\"plan\": \"Exploit SQLi\", \"code\": \"print('Exploited')\"}\n```"}}
    mock_httpx_post.return_value = mock_chat

    client = OllamaClient(model="Llama-3")
    agent = AIExploitAgent(ai_client=client)
    ctx = ExploitContext(url="http://target.com", vuln_type="SQLi", param="id")
    
    # Use internal parsing method
    result = agent._analyze_context(ctx, 1)
    
    assert result is not None
    assert "print('Exploited')" in result.get("code", "")
    assert "Exploit SQLi" in result.get("plan", "")

