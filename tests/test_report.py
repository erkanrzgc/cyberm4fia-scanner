import os
import pytest
from modules.report import (
    generate_html_report,
    generate_json_report,
    generate_markdown_report,
    generate_payload_report,
    get_severity,
)
from utils.request import Stats


@pytest.fixture
def mock_vulns():
    return [
        {
            "type": "SQLi_Param",
            "url": "http://test.com/sqli",
            "param": "id",
            "payload": "1' OR '1'='1",
            "method": "GET",
        },
        {
            "type": "XSS_Param",
            "url": "http://test.com/xss",
            "param": "search",
            "payload": "<script>alert(1)</script>",
            "method": "GET",
            "exploit_data": {
                "exploit_type": "Cookie_Stealer",
                "exploits": [{"description": "Steal via script tag"}],
            },
        },
    ]


@pytest.fixture
def temp_scan_dir(tmpdir):
    return str(tmpdir.mkdir("scans"))


def test_get_severity():
    # Test valid and invalid severity mappings
    assert get_severity("SQLi_Param") == "critical"
    assert get_severity("XSS_Param") == "high"
    assert get_severity("Unknown_Vuln") == "medium"


def test_html_report_generation(mock_vulns, temp_scan_dir):
    """Test HTML report generates correctly and contains required CVSS/CWE enrichment"""
    Stats.total_requests = 100
    Stats.waf_blocks = 5

    res = generate_html_report(mock_vulns, "http://test.com", "normal", temp_scan_dir)
    assert res is not None
    assert os.path.exists(res)

    with open(res, "r", encoding="utf-8") as f:
        html = f.read()

    # Verify formatting and execution summary presence
    assert "cyberm4fia-scanner Report" in html
    assert "100" in html  # Requests count
    assert "5" in html  # WAF block count

    # Verify CWE & CVSS badges
    assert "CWE-89" in html  # SQLi CWE
    assert "CWE-79" in html  # XSS CWE

    # Verify Sorting - SQLi (critical) should be before XSS (high)
    sqli_pos = html.find("SQL Injection")
    xss_pos = html.find("Reflected XSS")
    assert sqli_pos < xss_pos


def test_json_report_generation(mock_vulns, temp_scan_dir):
    """Test JSON report structure"""
    stats = {"requests": 100, "vulns": 2, "waf": 0}
    res = generate_json_report(
        mock_vulns, "http://test.com", "normal", stats, temp_scan_dir
    )

    assert os.path.exists(res)
    import json

    with open(res, "r") as f:
        data = json.load(f)

    assert data["target"] == "http://test.com"
    assert len(data["vulnerabilities"]) == 2
    assert data["stats"]["requests"] == 100


def test_markdown_report_generation(mock_vulns, temp_scan_dir):
    """Test Markdown report contains CVSS, CWE, Remediation info"""
    res = generate_markdown_report(
        mock_vulns, "http://test.com", "normal", temp_scan_dir
    )

    assert os.path.exists(res)
    with open(res, "r") as f:
        md = f.read()

    assert "Executive Vulnerability Report" in md
    assert "CWE-89" in md
    assert "**🛡️ Remediation:**" in md


def test_payload_report_generation(mock_vulns, temp_scan_dir):
    """Test Payload simple export contains payloads and params"""
    res = generate_payload_report(temp_scan_dir, "http://test.com", mock_vulns)

    assert os.path.exists(res)
    with open(res, "r") as f:
        content = f.read()

    assert "1' OR '1'='1" in content
    assert "<script>alert(1)</script>" in content


def test_empty_vulns_html(temp_scan_dir):
    """Test that HTML report with no vulns shows 'No vulnerabilities' message"""
    res = generate_html_report([], "http://test.com", "normal", temp_scan_dir)
    assert res is not None
    with open(res, "r", encoding="utf-8") as f:
        html = f.read()
    assert "No vulnerabilities detected" in html


def test_severity_mapping_consistency():
    """Test that get_severity returns values consistent with VULN_REGISTRY"""
    from utils.finding import VULN_REGISTRY

    for vuln_type, info in VULN_REGISTRY.items():
        assert get_severity(vuln_type) == info["severity"], (
            f"Mismatch for {vuln_type}: get_severity={get_severity(vuln_type)}, "
            f"registry={info['severity']}"
        )


def test_html_report_has_filter_js(mock_vulns, temp_scan_dir):
    """Test that HTML report contains client-side filter JavaScript"""
    res = generate_html_report(mock_vulns, "http://test.com", "normal", temp_scan_dir)
    with open(res, "r", encoding="utf-8") as f:
        html = f.read()
    assert "filterVulns" in html
    assert "filter-btn" in html


def test_html_report_has_remediation(mock_vulns, temp_scan_dir):
    """Test that HTML report contains remediation info for each finding"""
    res = generate_html_report(mock_vulns, "http://test.com", "normal", temp_scan_dir)
    with open(res, "r", encoding="utf-8") as f:
        html = f.read()
    assert "Remediation" in html
    assert "parameterized queries" in html  # SQLi remediation
    assert "Content-Security-Policy" in html  # XSS remediation
