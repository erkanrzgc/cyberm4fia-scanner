"""
cyberm4fia-scanner — Campaign Manager
Organized scan sessions with structured output, inspired by the 0-Day Machine's
hunts/campaigns/ pattern.
"""
import json, os, uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime

from utils.colors import log_success, log_warning

SCANS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scans")
CAMPAIGNS_DIR = os.path.join(SCANS_DIR, "campaigns")


@dataclass
class CampaignStats:
    total_findings: int = 0
    validated_findings: int = 0
    suspected_findings: int = 0
    modules_run: list = field(default_factory=list)
    duration_seconds: float = 0.0
    by_severity: dict = field(default_factory=dict)
    by_type: dict = field(default_factory=dict)


@dataclass
class Campaign:
    id: str
    target: str
    name: str
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    status: str = "active"  # active, completed, archived
    notes: str = ""
    modules_run: list = field(default_factory=list)
    duration_seconds: float = 0.0
    metadata: dict = field(default_factory=dict)
    # Finding counts (actual findings stored in files)
    finding_count: int = 0
    suspected_count: int = 0
    defence_count: int = 0

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, data):
        known = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in known}
        return cls(**filtered)


class CampaignManager:
    """Organize scans into campaigns with structured output directories."""

    def __init__(self, base_dir=None):
        self.base_dir = base_dir or CAMPAIGNS_DIR
        os.makedirs(self.base_dir, exist_ok=True)

    def _campaign_dir(self, campaign_id):
        return os.path.join(self.base_dir, campaign_id)

    def _campaign_file(self, campaign_id):
        return os.path.join(self._campaign_dir(campaign_id), "campaign.json")

    def create_campaign(self, target, name=None, notes="") -> Campaign:
        """Create a new campaign for a scan session."""
        from urllib.parse import urlparse
        domain = urlparse(target).hostname or target
        cid = f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
        if not name:
            name = f"Scan of {domain} — {datetime.now().strftime('%Y-%m-%d %H:%M')}"

        campaign = Campaign(id=cid, target=target, name=name, notes=notes)
        cdir = self._campaign_dir(cid)
        os.makedirs(cdir, exist_ok=True)
        for sub in ("suspected", "findings", "defences", "intelligence", "reports"):
            os.makedirs(os.path.join(cdir, sub), exist_ok=True)

        self._save_campaign(campaign)
        log_success(f"Campaign created: {cid}")
        return campaign

    def _save_campaign(self, campaign):
        path = self._campaign_file(campaign.id)
        with open(path, "w") as f:
            json.dump(campaign.to_dict(), f, indent=2, default=str)

    def _load_campaign(self, campaign_id) -> Campaign | None:
        path = self._campaign_file(campaign_id)
        if not os.path.exists(path):
            return None
        with open(path) as f:
            return Campaign.from_dict(json.load(f))

    def get_campaign(self, campaign_id) -> Campaign | None:
        return self._load_campaign(campaign_id)

    def list_campaigns(self, target=None, limit=20) -> list[Campaign]:
        """List campaigns, optionally filtered by target."""
        campaigns = []
        if not os.path.exists(self.base_dir):
            return []
        for entry in sorted(os.listdir(self.base_dir), reverse=True):
            cdir = os.path.join(self.base_dir, entry)
            if not os.path.isdir(cdir):
                continue
            campaign = self._load_campaign(entry)
            if campaign is None:
                continue
            if target:
                from urllib.parse import urlparse
                t_domain = urlparse(target).hostname or target
                c_domain = urlparse(campaign.target).hostname or campaign.target
                if t_domain != c_domain:
                    continue
            campaigns.append(campaign)
            if len(campaigns) >= limit:
                break
        return campaigns

    def add_findings(self, campaign_id, findings, validated=True):
        """Add findings to a campaign (validated or suspected/hallucination bin)."""
        campaign = self._load_campaign(campaign_id)
        if not campaign:
            log_warning(f"Campaign {campaign_id} not found")
            return

        subdir = "findings" if validated else "suspected"
        target_dir = os.path.join(self._campaign_dir(campaign_id), subdir)
        os.makedirs(target_dir, exist_ok=True)

        ts = datetime.now().strftime("%H%M%S")
        filename = f"{subdir}_{ts}.json"
        filepath = os.path.join(target_dir, filename)
        with open(filepath, "w") as f:
            json.dump(findings, f, indent=2, default=str)

        if validated:
            campaign.finding_count += len(findings)
        else:
            campaign.suspected_count += len(findings)
        self._save_campaign(campaign)

    def add_defences(self, campaign_id, defences):
        """Record discovered defences for a campaign."""
        campaign = self._load_campaign(campaign_id)
        if not campaign:
            return

        target_dir = os.path.join(self._campaign_dir(campaign_id), "defences")
        os.makedirs(target_dir, exist_ok=True)
        filepath = os.path.join(target_dir, "defences.json")

        existing = []
        if os.path.exists(filepath):
            with open(filepath) as f:
                existing = json.load(f)

        existing.extend(defences if isinstance(defences, list) else [defences])
        with open(filepath, "w") as f:
            json.dump(existing, f, indent=2, default=str)

        campaign.defence_count = len(existing)
        self._save_campaign(campaign)

    def add_intelligence(self, campaign_id, intel_data):
        """Store intelligence data learned from this campaign."""
        target_dir = os.path.join(self._campaign_dir(campaign_id), "intelligence")
        os.makedirs(target_dir, exist_ok=True)
        filepath = os.path.join(target_dir, "learned.json")
        with open(filepath, "w") as f:
            json.dump(intel_data, f, indent=2, default=str)

    def complete_campaign(self, campaign_id, duration=0.0, modules_run=None):
        """Mark a campaign as completed."""
        campaign = self._load_campaign(campaign_id)
        if not campaign:
            return
        campaign.status = "completed"
        campaign.duration_seconds = duration
        if modules_run:
            campaign.modules_run = list(modules_run)
        self._save_campaign(campaign)
        log_success(f"Campaign completed: {campaign_id} "
                    f"({campaign.finding_count} validated, {campaign.suspected_count} suspected)")

    def get_campaign_stats(self, campaign_id) -> CampaignStats | None:
        """Calculate statistics for a campaign."""
        campaign = self._load_campaign(campaign_id)
        if not campaign:
            return None

        stats = CampaignStats(
            modules_run=campaign.modules_run,
            duration_seconds=campaign.duration_seconds,
        )

        # Load all findings
        findings_dir = os.path.join(self._campaign_dir(campaign_id), "findings")
        all_findings = self._load_dir_findings(findings_dir)
        stats.validated_findings = len(all_findings)

        suspected_dir = os.path.join(self._campaign_dir(campaign_id), "suspected")
        suspected = self._load_dir_findings(suspected_dir)
        stats.suspected_findings = len(suspected)
        stats.total_findings = stats.validated_findings + stats.suspected_findings

        for f in all_findings:
            sev = f.get("severity", "info").lower()
            stats.by_severity[sev] = stats.by_severity.get(sev, 0) + 1
            vt = f.get("type", "Unknown")
            stats.by_type[vt] = stats.by_type.get(vt, 0) + 1

        return stats

    def _load_dir_findings(self, dirpath):
        findings = []
        if not os.path.exists(dirpath):
            return findings
        for fname in os.listdir(dirpath):
            if not fname.endswith(".json"):
                continue
            with open(os.path.join(dirpath, fname)) as f:
                data = json.load(f)
                if isinstance(data, list):
                    findings.extend(data)
                elif isinstance(data, dict):
                    findings.append(data)
        return findings

    def compare_campaigns(self, id1, id2) -> dict:
        """Compare two campaigns to show drift."""
        s1 = self.get_campaign_stats(id1)
        s2 = self.get_campaign_stats(id2)
        if not s1 or not s2:
            return {"error": "Campaign not found"}

        return {
            "campaign_1": id1,
            "campaign_2": id2,
            "finding_diff": s2.validated_findings - s1.validated_findings,
            "severity_diff": {
                sev: s2.by_severity.get(sev, 0) - s1.by_severity.get(sev, 0)
                for sev in set(list(s1.by_severity) + list(s2.by_severity))
            },
            "new_types": [t for t in s2.by_type if t not in s1.by_type],
            "fixed_types": [t for t in s1.by_type if t not in s2.by_type],
        }

    def export_campaign(self, campaign_id, fmt="json") -> str:
        """Export campaign data."""
        campaign = self._load_campaign(campaign_id)
        if not campaign:
            return ""

        data = campaign.to_dict()
        data["findings"] = self._load_dir_findings(
            os.path.join(self._campaign_dir(campaign_id), "findings")
        )
        data["suspected"] = self._load_dir_findings(
            os.path.join(self._campaign_dir(campaign_id), "suspected")
        )
        data["stats"] = asdict(self.get_campaign_stats(campaign_id) or CampaignStats())

        if fmt == "json":
            return json.dumps(data, indent=2, default=str)
        return str(data)
