"""
cyberm4fia-scanner — Scan History & Drift Detection
SQLite-backed scan result history with change detection between scans.
"""

import json
import os
import sqlite3
from datetime import datetime
from dataclasses import dataclass, field

from utils.colors import Colors, log_info, log_success

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
DB_FILE = os.path.join(DATA_DIR, "scan_history.db")


@dataclass
class DriftItem:
    """A single change between two scans."""
    status: str  # NEW, FIXED, SAME, WORSE, BETTER
    vuln_type: str
    url: str
    param: str = ""
    old_severity: str = ""
    new_severity: str = ""
    detail: str = ""


@dataclass
class DriftReport:
    """Summary of changes between two scans."""
    target: str
    previous_scan_date: str
    current_scan_date: str
    items: list = field(default_factory=list)

    @property
    def new_count(self):
        return sum(1 for i in self.items if i.status == "NEW")

    @property
    def fixed_count(self):
        return sum(1 for i in self.items if i.status == "FIXED")

    @property
    def same_count(self):
        return sum(1 for i in self.items if i.status == "SAME")

    @property
    def worse_count(self):
        return sum(1 for i in self.items if i.status == "WORSE")


class ScanHistory:
    """SQLite-backed scan result history with drift detection."""

    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

    def __init__(self, db_path=None):
        self.db_path = db_path or DB_FILE
        self._ensure_dir()
        self._init_db()

    def _ensure_dir(self):
        parent = os.path.dirname(self.db_path)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    scan_date TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    metadata_json TEXT DEFAULT '{}',
                    finding_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_scans_target
                ON scans(target, scan_date DESC)
            """)

    def save_scan(self, target, findings, metadata=None):
        """
        Save scan results to history.
        
        Args:
            target: Target URL/domain.
            findings: List of vulnerability dicts.
            metadata: Optional scan metadata (duration, modules, etc.).
        """
        scan_date = datetime.now().isoformat()
        findings_json = json.dumps(findings, default=str)
        metadata_json = json.dumps(metadata or {}, default=str)

        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "INSERT INTO scans (target, scan_date, findings_json, metadata_json, finding_count) VALUES (?, ?, ?, ?, ?)",
                (target.lower(), scan_date, findings_json, metadata_json, len(findings))
            )

        log_success(f"Scan saved to history ({len(findings)} findings)")
        return scan_date

    def get_previous(self, target):
        """Get the most recent previous scan for a target."""
        with sqlite3.connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT id, scan_date, findings_json, metadata_json FROM scans "
                "WHERE target = ? ORDER BY scan_date DESC LIMIT 1",
                (target.lower(),)
            ).fetchone()

        if not row:
            return None

        return {
            "id": row[0],
            "scan_date": row[1],
            "findings": json.loads(row[2]),
            "metadata": json.loads(row[3]),
        }

    def compute_drift(self, target, new_findings):
        """
        Compare current findings with previous scan and generate drift report.
        
        Args:
            target: Target URL/domain.
            new_findings: List of current vulnerability dicts.
            
        Returns:
            DriftReport or None if no previous scan.
        """
        previous = self.get_previous(target)
        if not previous:
            return None

        now = datetime.now().isoformat()
        report = DriftReport(
            target=target,
            previous_scan_date=previous["scan_date"],
            current_scan_date=now,
        )

        # Build fingerprints for comparison
        old_fps = self._build_fingerprints(previous["findings"])
        new_fps = self._build_fingerprints(new_findings)

        old_keys = set(old_fps.keys())
        new_keys = set(new_fps.keys())

        # NEW: in new but not in old
        for key in new_keys - old_keys:
            fp = new_fps[key]
            report.items.append(DriftItem(
                status="NEW",
                vuln_type=fp["type"],
                url=fp["url"],
                param=fp.get("param", ""),
                new_severity=fp.get("severity", "medium"),
                detail=f"First time found: {fp['type']} at {fp['url']}",
            ))

        # FIXED: in old but not in new
        for key in old_keys - new_keys:
            fp = old_fps[key]
            report.items.append(DriftItem(
                status="FIXED",
                vuln_type=fp["type"],
                url=fp["url"],
                param=fp.get("param", ""),
                old_severity=fp.get("severity", "medium"),
                detail=f"No longer found: {fp['type']} at {fp['url']}",
            ))

        # SAME or WORSE/BETTER: in both
        for key in old_keys & new_keys:
            old_fp = old_fps[key]
            new_fp = new_fps[key]
            old_sev = old_fp.get("severity", "medium").lower()
            new_sev = new_fp.get("severity", "medium").lower()

            old_rank = self.SEVERITY_ORDER.get(old_sev, 2)
            new_rank = self.SEVERITY_ORDER.get(new_sev, 2)

            if new_rank > old_rank:
                status = "WORSE"
                detail = f"Severity upgraded: {old_sev} → {new_sev}"
            elif new_rank < old_rank:
                status = "BETTER"
                detail = f"Severity downgraded: {old_sev} → {new_sev}"
            else:
                status = "SAME"
                detail = f"Still present: {old_fp['type']}"

            report.items.append(DriftItem(
                status=status,
                vuln_type=new_fp["type"],
                url=new_fp["url"],
                param=new_fp.get("param", ""),
                old_severity=old_sev,
                new_severity=new_sev,
                detail=detail,
            ))

        return report

    def _build_fingerprints(self, findings):
        """Build unique fingerprints for each finding for comparison."""
        fps = {}
        for f in findings:
            vtype = f.get("type", "Unknown")
            url = f.get("url", "")
            param = f.get("param", "")
            key = f"{vtype}|{url}|{param}"
            fps[key] = f
        return fps

    def list_scans(self, target=None, limit=20):
        """List recent scans, optionally filtered by target."""
        with sqlite3.connect(self.db_path) as conn:
            if target:
                rows = conn.execute(
                    "SELECT id, target, scan_date, finding_count FROM scans "
                    "WHERE target = ? ORDER BY scan_date DESC LIMIT ?",
                    (target.lower(), limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT id, target, scan_date, finding_count FROM scans "
                    "ORDER BY scan_date DESC LIMIT ?",
                    (limit,)
                ).fetchall()

        return [
            {"id": r[0], "target": r[1], "scan_date": r[2], "finding_count": r[3]}
            for r in rows
        ]

    def print_drift_report(self, report):
        """Print a formatted drift report."""
        if not report:
            log_info("No previous scan found for this target. First scan!")
            return

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 55}")
        print(f"  📊 Scan Drift Report — {report.target}")
        print(f"{'═' * 55}{Colors.END}")
        print(f"  Previous: {report.previous_scan_date[:19]}")
        print(f"  Current:  {report.current_scan_date[:19]}")
        print()

        status_icons = {
            "NEW": f"{Colors.RED}🆕 [NEW]  ",
            "FIXED": f"{Colors.GREEN}✅ [FIXED]",
            "SAME": f"{Colors.YELLOW}🔄 [SAME] ",
            "WORSE": f"{Colors.RED}⬆️  [WORSE]",
            "BETTER": f"{Colors.GREEN}⬇️  [BETTER]",
        }

        for item in sorted(report.items, key=lambda x: {"NEW": 0, "WORSE": 1, "SAME": 2, "BETTER": 3, "FIXED": 4}.get(x.status, 5)):
            icon = status_icons.get(item.status, "?")
            sev = item.new_severity or item.old_severity
            print(f"  {icon}{Colors.END} {item.vuln_type} on {item.url}")
            if item.status in ("WORSE", "BETTER"):
                print(f"         {item.old_severity} → {item.new_severity}")

        print(f"\n  Summary: {Colors.RED}{report.new_count} new{Colors.END} | "
              f"{Colors.GREEN}{report.fixed_count} fixed{Colors.END} | "
              f"{Colors.YELLOW}{report.same_count} unchanged{Colors.END} | "
              f"{Colors.RED}{report.worse_count} worsened{Colors.END}")
        print()


# Singleton accessor
_history_instance = None


def get_scan_history(db_path=None):
    """Get or create the global ScanHistory instance."""
    global _history_instance
    if _history_instance is None:
        _history_instance = ScanHistory(db_path=db_path)
    return _history_instance
