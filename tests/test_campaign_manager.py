"""Tests for the Campaign Manager."""
import json, os, pytest
from utils.campaign_manager import CampaignManager, Campaign


@pytest.fixture
def cm(tmp_path):
    return CampaignManager(base_dir=str(tmp_path / "campaigns"))


class TestCampaignManager:
    def test_create_campaign(self, cm):
        campaign = cm.create_campaign("https://example.com", name="Test Scan")
        assert campaign.target == "https://example.com"
        assert campaign.name == "Test Scan"
        assert campaign.status == "active"
        assert os.path.isdir(cm._campaign_dir(campaign.id))

    def test_campaign_directories_created(self, cm):
        campaign = cm.create_campaign("https://example.com")
        cdir = cm._campaign_dir(campaign.id)
        for sub in ("suspected", "findings", "defences", "intelligence", "reports"):
            assert os.path.isdir(os.path.join(cdir, sub))

    def test_add_findings(self, cm):
        campaign = cm.create_campaign("https://example.com")
        findings = [{"type": "XSS", "severity": "high"}]
        cm.add_findings(campaign.id, findings, validated=True)
        loaded = cm.get_campaign(campaign.id)
        assert loaded.finding_count == 1

    def test_add_suspected(self, cm):
        campaign = cm.create_campaign("https://example.com")
        suspected = [{"type": "SQLi", "severity": "medium"}]
        cm.add_findings(campaign.id, suspected, validated=False)
        loaded = cm.get_campaign(campaign.id)
        assert loaded.suspected_count == 1

    def test_complete_campaign(self, cm):
        campaign = cm.create_campaign("https://example.com")
        cm.complete_campaign(campaign.id, duration=120.5, modules_run=["xss", "sqli"])
        loaded = cm.get_campaign(campaign.id)
        assert loaded.status == "completed"
        assert loaded.duration_seconds == 120.5
        assert "xss" in loaded.modules_run

    def test_list_campaigns(self, cm):
        cm.create_campaign("https://a.com")
        cm.create_campaign("https://b.com")
        campaigns = cm.list_campaigns()
        assert len(campaigns) == 2

    def test_list_campaigns_filtered(self, cm):
        cm.create_campaign("https://a.com")
        cm.create_campaign("https://b.com")
        campaigns = cm.list_campaigns(target="https://a.com")
        assert len(campaigns) == 1

    def test_campaign_stats(self, cm):
        campaign = cm.create_campaign("https://example.com")
        cm.add_findings(campaign.id, [
            {"type": "XSS", "severity": "high"},
            {"type": "SQLi", "severity": "critical"},
        ], validated=True)
        cm.add_findings(campaign.id, [
            {"type": "Maybe_LFI", "severity": "medium"},
        ], validated=False)
        stats = cm.get_campaign_stats(campaign.id)
        assert stats.validated_findings == 2
        assert stats.suspected_findings == 1
        assert stats.total_findings == 3

    def test_add_defences(self, cm):
        campaign = cm.create_campaign("https://example.com")
        cm.add_defences(campaign.id, [
            {"type": "waf", "detail": "Cloudflare"},
        ])
        loaded = cm.get_campaign(campaign.id)
        assert loaded.defence_count == 1

    def test_export_campaign(self, cm):
        campaign = cm.create_campaign("https://example.com")
        cm.add_findings(campaign.id, [{"type": "XSS"}], validated=True)
        exported = cm.export_campaign(campaign.id)
        data = json.loads(exported)
        assert data["target"] == "https://example.com"
        assert len(data["findings"]) == 1

    def test_compare_campaigns(self, cm):
        c1 = cm.create_campaign("https://example.com")
        c2 = cm.create_campaign("https://example.com")
        cm.add_findings(c1.id, [{"type": "XSS", "severity": "high"}], validated=True)
        cm.add_findings(c2.id, [
            {"type": "XSS", "severity": "high"},
            {"type": "SQLi", "severity": "critical"},
        ], validated=True)
        diff = cm.compare_campaigns(c1.id, c2.id)
        assert diff["finding_diff"] == 1
        assert "SQLi" in diff["new_types"]

    def test_campaign_from_dict(self):
        data = {"id": "test", "target": "https://x.com", "name": "Test", "status": "active"}
        campaign = Campaign.from_dict(data)
        assert campaign.id == "test"
        assert campaign.target == "https://x.com"
