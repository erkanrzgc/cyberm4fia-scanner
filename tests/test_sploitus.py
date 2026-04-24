import pytest
from unittest.mock import patch, MagicMock
from utils.sploitus_search import SploitusSearch
import httpx

@pytest.fixture
def searcher():
    return SploitusSearch(timeout=1)

@patch("httpx.Client.post")
def test_search_success(mock_post, searcher):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "exploits": [
            {"title": "Test Exploit 1", "score": 8, "href": "https://test.com/1"},
            {"title": "Test Exploit 2", "score": 4}
        ]
    }
    mock_post.return_value = mock_resp
    
    results = searcher.search("wordpress")
    assert len(results) == 2
    assert results[0]["title"] == "Test Exploit 1"
    assert results[0]["score"] == 8

@patch("httpx.Client.post")
def test_search_failure(mock_post, searcher):
    mock_resp = MagicMock()
    mock_resp.status_code = 500
    mock_post.return_value = mock_resp
    
    results = searcher.search("wordpress")
    assert len(results) == 0

@patch("httpx.Client.post")
def test_search_exception(mock_post, searcher):
    mock_post.side_effect = httpx.RequestError("Failed to connect")
    
    results = searcher.search("wordpress")
    assert len(results) == 0

@patch("httpx.Client.post")
def test_enrich_findings(mock_post, searcher):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"exploits": [{"title": "RCE", "score": 10}]}
    mock_post.return_value = mock_resp
    
    findings = [{"type": "Log4j", "cve": "CVE-2021-44228", "url": "http://test.com"}]
    tech_stack = {"Apache Tomcat": "9.0.0"}
    
    enrichments = searcher.enrich_findings(findings, tech_stack)
    
    assert len(enrichments) == 2
    assert any(e["source"] == "finding" for e in enrichments)
    assert any(e["source"] == "tech_stack" for e in enrichments)
