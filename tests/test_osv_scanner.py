import json
from unittest.mock import patch, MagicMock

import pytest

from modules.osv_scanner import (
    query_osv_api,
    extract_cve_info,
    check_tech_stack_vulns,
    analyze_exposed_manifest,
)


@pytest.fixture
def mock_osv_response():
    """Mock a successful OSV API response with a vulnerability."""
    return {
        "vulns": [
            {
                "id": "GHSA-1234",
                "aliases": ["CVE-2023-12345"],
                "summary": "Critical vulnerability in test package",
                "details": "This is a detailed description mentioning a CRITICAL issue.",
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            }
        ]
    }


@patch("httpx.post")
def test_query_osv_api(mock_post, mock_osv_response):
    """Test OSV API query logic."""
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_osv_response
    mock_post.return_value = mock_resp

    vulns = query_osv_api("django", "1.11.0", "PyPI")
    
    assert len(vulns) == 1
    assert vulns[0]["id"] == "GHSA-1234"
    mock_post.assert_called_once()
    
    # Check payload
    call_args = mock_post.call_args[1]["json"]
    assert call_args["version"] == "1.11.0"
    assert call_args["package"]["name"] == "django"
    assert call_args["package"]["ecosystem"] == "PyPI"


def test_extract_cve_info():
    """Test extracting info from OSV response format."""
    osv_vuln = {
        "id": "GHSA-5555",
        "aliases": ["CVE-2022-99999", "OTHER-ID"],
        "summary": "Test Summary",
        "details": "This allows REMOTE CODE EXECUTION.",
    }
    info = extract_cve_info(osv_vuln)
    
    assert info["cve"] == "CVE-2022-99999"
    assert info["summary"] == "Test Summary"
    assert info["severity"] == "critical"  # Should infer critical from details
    assert info["url"] == "GHSA-5555"


@patch("modules.osv_scanner.query_osv_api")
def test_check_tech_stack_vulns(mock_query, mock_osv_response):
    """Test checking an entire tech stack."""
    mock_query.return_value = mock_osv_response["vulns"]
    
    tech_stack = {"Django": "1.11.0", "nginx": "unknown"}
    findings = check_tech_stack_vulns("https://example.com", tech_stack)
    
    # "nginx" should be skipped because version is unknown
    assert len(findings) == 1
    finding = findings[0]
    assert finding["type"] == "Known_Vulnerability_SCA"
    assert finding["component"] == "Django"
    assert finding["cve"] == "CVE-2023-12345"
    assert finding["severity"] == "critical"


@patch("modules.osv_scanner.query_osv_api")
def test_analyze_exposed_manifest(mock_query, mock_osv_response):
    """Test parsing exposed package.json."""
    mock_query.return_value = mock_osv_response["vulns"]
    
    manifest_content = json.dumps({
        "name": "test-app",
        "dependencies": {
            "express": "^4.16.0",
            "lodash": "~4.17.15"
        }
    })
    
    findings = analyze_exposed_manifest("https://example.com/package.json", manifest_content, "package.json")
    
    assert len(findings) == 2  # One for express, one for lodash
    assert findings[0]["type"] == "Vulnerable_Dependency"
    
    # Check that semver chars were stripped
    # Note: dictionary order is preserved in Python 3.7+
    calls = mock_query.call_args_list
    assert calls[0][0][0] == "express"
    assert calls[0][0][1] == "4.16.0"
    assert calls[1][0][0] == "lodash"
    assert calls[1][0][1] == "4.17.15"
