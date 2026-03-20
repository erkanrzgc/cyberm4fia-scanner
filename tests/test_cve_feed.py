"""
Tests for utils/cve_feed.py — SiberAdar CVE Threat Intel Feed
"""

from unittest.mock import patch, MagicMock

from utils.cve_feed import fetch_cves, enrich_with_cves, clear_cache, TECH_TO_VENDOR

# ── Sample API Response ───────────────────────────────────────────

MOCK_API_RESPONSE = {
    "cves": [
        {
            "cve_id": "CVE-2026-12345",
            "score": 9.8,
            "severity": "CRITICAL",
            "description": "Critical RCE in PHP",
            "description_tr": "PHP'de kritik uzaktan kod çalıştırma",
            "cwe_ids": "CWE-78",
            "cwe_names": "CWE-78",
            "epss_score": 0.85,
            "epss_percentile": 95,
            "in_kev": True,
            "has_exploit": 1,
            "tags": "remote,no-auth",
            "vendor_products": "php",
            "published": "2026-03-01",
        },
        {
            "cve_id": "CVE-2026-54321",
            "score": 7.5,
            "severity": "HIGH",
            "description": "High severity LFI in PHP",
            "description_tr": "PHP'de yüksek şiddette LFI",
            "cwe_ids": "CWE-98",
            "cwe_names": "CWE-98",
            "epss_score": 0.12,
            "epss_percentile": 40,
            "in_kev": False,
            "has_exploit": 0,
            "tags": "remote",
            "vendor_products": "php",
            "published": "2026-02-15",
        },
        {
            "cve_id": "CVE-2026-00001",
            "score": 4.3,
            "severity": "MEDIUM",
            "description": "Medium info leak",
            "description_tr": "Orta şiddette bilgi sızıntısı",
            "cwe_ids": "CWE-200",
            "cwe_names": "CWE-200",
            "epss_score": 0.01,
            "epss_percentile": 5,
            "in_kev": False,
            "has_exploit": 0,
            "tags": "",
            "vendor_products": "php",
            "published": "2026-01-01",
        },
    ],
    "total": 3,
}

MOCK_TECH_RESULTS = [
    {
        "type": "technology",
        "name": "PHP",
        "category": "Language",
        "version": "8.2.5",
        "evidence": "X-Powered-By: PHP/8.2.5",
    },
    {
        "type": "technology",
        "name": "Nginx",
        "category": "Web Server",
        "version": "1.24.0",
        "evidence": "server: nginx/1.24.0",
    },
    {
        "type": "security_header",
        "name": "CSP",
        "category": "Security",
        "issue": "Missing Content-Security-Policy",
        "severity": "MEDIUM",
    },
]

class TestFetchCves:
    """Test fetch_cves function."""

    def setup_method(self):
        clear_cache()

    @patch("utils.cve_feed.httpx.Client")
    def test_fetch_cves_returns_filtered_results(self, mock_client_cls):
        """Only HIGH/CRITICAL CVEs should be returned."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = MOCK_API_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        results = fetch_cves("php")
        # Should only include CRITICAL and HIGH, not MEDIUM
        assert len(results) == 2
        assert results[0]["cve_id"] == "CVE-2026-12345"
        assert results[1]["cve_id"] == "CVE-2026-54321"

    @patch("utils.cve_feed.httpx.Client")
    def test_fetch_cves_caches_results(self, mock_client_cls):
        """Second call to same tech should use cache."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = MOCK_API_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        fetch_cves("php")
        fetch_cves("php")  # Should hit cache
        # Client should only be created once
        assert mock_client_cls.call_count == 1

    @patch("utils.cve_feed.httpx.Client")
    def test_fetch_cves_handles_api_error(self, mock_client_cls):
        """API errors should return empty list, not crash."""
        mock_client = MagicMock()
        mock_client.get.side_effect = ValueError("Connection failed")
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        results = fetch_cves("php")
        assert results == []

    @patch("utils.cve_feed.httpx.Client")
    def test_fetch_cves_max_results(self, mock_client_cls):
        """Should respect max_results limit."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = MOCK_API_RESPONSE
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        results = fetch_cves("php", max_results=1)
        assert len(results) == 1

class TestEnrichWithCves:
    """Test enrich_with_cves function."""

    def setup_method(self):
        clear_cache()

    @patch("utils.cve_feed.fetch_cves")
    def test_enrich_returns_cve_intel_findings(self, mock_fetch):
        """Should return CVE_Intel findings for detected technologies."""
        mock_fetch.return_value = MOCK_API_RESPONSE["cves"][:2]

        findings = enrich_with_cves(MOCK_TECH_RESULTS)
        # PHP and Nginx both mapped → should have findings
        assert len(findings) > 0
        for f in findings:
            assert f["type"] == "CVE_Intel"

    @patch("utils.cve_feed.fetch_cves")
    def test_enrich_includes_kev_and_exploit_labels(self, mock_fetch):
        """KEV and exploit flags should be in findings."""
        mock_fetch.return_value = [
            MOCK_API_RESPONSE["cves"][0]
        ]  # CVE with KEV + exploit

        findings = enrich_with_cves(MOCK_TECH_RESULTS)
        kev_finding = [f for f in findings if f.get("in_kev")]
        assert len(kev_finding) > 0
        assert "CISA KEV" in kev_finding[0].get("risk_labels", "")

    @patch("utils.cve_feed.fetch_cves")
    def test_enrich_skips_non_technology_items(self, mock_fetch):
        """Security headers should not trigger CVE lookups."""
        mock_fetch.return_value = []

        # Only security_header items — no technology items
        security_only = [
            {
                "type": "security_header",
                "name": "CSP",
                "category": "Security",
                "issue": "Missing CSP",
            }
        ]
        findings = enrich_with_cves(security_only)
        assert findings == []
        mock_fetch.assert_not_called()

    def test_enrich_empty_input(self):
        """Empty input should return empty list."""
        assert enrich_with_cves([]) == []
        assert enrich_with_cves(None) == []

class TestTechToVendorMapping:
    """Test the tech-to-vendor mapping coverage."""

    def test_mapping_has_common_techs(self):
        """Important technologies should be mapped."""
        expected = ["Nginx", "Apache", "PHP", "WordPress", "React", "Node.js"]
        for tech in expected:
            assert tech in TECH_TO_VENDOR, f"{tech} missing from TECH_TO_VENDOR"

    def test_mapping_values_are_lowercase(self):
        """All vendor values should be lowercase for API queries."""
        for tech, vendor in TECH_TO_VENDOR.items():
            assert vendor == vendor.lower(), f"{tech} → {vendor} not lowercase"

class TestClearCache:
    """Test cache clearing."""

    @patch("utils.cve_feed.httpx.Client")
    def test_clear_cache_forces_new_fetch(self, mock_client_cls):
        """After clearing cache, fetch should make a new API call."""
        mock_resp = MagicMock()
        mock_resp.json.return_value = {"cves": []}
        mock_resp.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.get.return_value = mock_resp
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client_cls.return_value = mock_client

        fetch_cves("test")
        clear_cache()
        fetch_cves("test")
        assert mock_client_cls.call_count == 2
