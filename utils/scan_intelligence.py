"""
cyberm4fia-scanner — Scan Intelligence Engine (RAG-Lite Knowledge Loop)
SQLite-FTS5 backed intelligence that learns from every scan.
"""
import hashlib, json, os, sqlite3, threading
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
INTEL_DB = os.path.join(DATA_DIR, "scan_intelligence.db")

@dataclass
class PayloadRecord:
    payload: str; vuln_type: str; success_count: int = 0; fail_count: int = 0
    waf_bypassed: list = field(default_factory=list); last_success: str = ""
    effectiveness: float = 0.0

@dataclass
class Defence:
    defence_type: str; detail: str = ""; first_seen: str = ""; last_seen: str = ""
    bypass_count: int = 0

@dataclass
class TargetIntel:
    target: str; domain: str; total_scans: int = 0; total_findings: int = 0
    defences: list = field(default_factory=list); effective_payloads: list = field(default_factory=list)
    failed_modules: list = field(default_factory=list); tech_stack: list = field(default_factory=list)
    waf_name: str = ""; last_scanned: str = ""; priority_score: float = 50.0

@dataclass
class IntelReport:
    target: str; past_scans: int = 0; known_defences: list = field(default_factory=list)
    recommended_payloads: list = field(default_factory=list)
    modules_to_skip: list = field(default_factory=list)
    modules_to_prioritize: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    def to_context_string(self, max_chars=2000):
        lines = [f"Intelligence briefing for {self.target}:", f"  Past scans: {self.past_scans}"]
        if self.known_defences:
            lines.append(f"  Known defences: {', '.join(f'{d.defence_type}({d.detail})' for d in self.known_defences[:5])}")
        if self.recommended_payloads:
            lines.append("  Recommended payloads (proven effective):")
            for p in self.recommended_payloads[:5]:
                lines.append(f"    - [{p.vuln_type}] {p.payload[:60]} (success: {p.success_count}, eff: {p.effectiveness:.0%})")
        if self.modules_to_skip:
            lines.append(f"  Skip modules (no results in past): {', '.join(self.modules_to_skip[:5])}")
        if self.modules_to_prioritize:
            lines.append(f"  Prioritize modules: {', '.join(self.modules_to_prioritize[:5])}")
        for note in self.notes[:3]:
            lines.append(f"  \u2139 {note}")
        return "\n".join(lines)[:max_chars]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scan_intel (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, domain TEXT NOT NULL,
    vuln_type TEXT NOT NULL, module TEXT DEFAULT '', payload TEXT DEFAULT '',
    payload_hash TEXT DEFAULT '', technique TEXT DEFAULT '', success INTEGER NOT NULL DEFAULT 0,
    waf_name TEXT DEFAULT '', tech_stack TEXT DEFAULT '[]', confidence INTEGER DEFAULT 0,
    response_code INTEGER DEFAULT 0, scan_id TEXT DEFAULT '', campaign_id TEXT DEFAULT '',
    timestamp TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS idx_intel_domain ON scan_intel(domain, vuln_type);
CREATE INDEX IF NOT EXISTS idx_intel_payload ON scan_intel(payload_hash, success);
CREATE INDEX IF NOT EXISTS idx_intel_waf ON scan_intel(waf_name, vuln_type, success);

CREATE TABLE IF NOT EXISTS known_defences (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, domain TEXT NOT NULL,
    defence_type TEXT NOT NULL, detail TEXT DEFAULT '', first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL, bypass_count INTEGER DEFAULT 0,
    UNIQUE(domain, defence_type, detail));
CREATE INDEX IF NOT EXISTS idx_defences_domain ON known_defences(domain);

CREATE TABLE IF NOT EXISTS payload_effectiveness (
    id INTEGER PRIMARY KEY AUTOINCREMENT, vuln_type TEXT NOT NULL,
    payload_hash TEXT NOT NULL, payload TEXT NOT NULL, success_count INTEGER DEFAULT 0,
    fail_count INTEGER DEFAULT 0, waf_bypassed TEXT DEFAULT '[]', last_success TEXT DEFAULT '',
    UNIQUE(vuln_type, payload_hash));
CREATE INDEX IF NOT EXISTS idx_payload_eff ON payload_effectiveness(vuln_type, success_count DESC);

CREATE TABLE IF NOT EXISTS negative_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, domain TEXT NOT NULL,
    module TEXT NOT NULL, reason TEXT DEFAULT '', scan_id TEXT DEFAULT '',
    timestamp TEXT NOT NULL, UNIQUE(domain, module, scan_id));
CREATE INDEX IF NOT EXISTS idx_neg_domain ON negative_results(domain, module);
"""

class ScanIntelligence:
    """SQLite-FTS5 backed scan intelligence engine. Learns from every scan."""

    def __init__(self, db_path=None):
        self.db_path = db_path or INTEL_DB
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_db()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_db(self):
        with self._conn() as conn:
            conn.executescript(_SCHEMA)
            try:
                conn.execute("""CREATE VIRTUAL TABLE IF NOT EXISTS intel_fts USING fts5(
                    vuln_type, payload, technique, waf_name, tech_stack,
                    content=scan_intel, content_rowid=id)""")
            except sqlite3.OperationalError:
                pass

    @staticmethod
    def _domain(target):
        return urlparse(target).hostname or target

    @staticmethod
    def _phash(payload):
        return hashlib.sha256(payload.encode("utf-8", errors="replace")).hexdigest()[:16]

    def record_scan_result(self, target, vuln_type, payload="", success=False,
                           waf_name="", tech_stack="[]", module="", technique="",
                           confidence=0, response_code=0, scan_id="", campaign_id=""):
        domain = self._domain(target)
        ph = self._phash(payload) if payload else ""
        now = datetime.now().isoformat()
        with self._lock, self._conn() as conn:
            conn.execute(
                "INSERT INTO scan_intel (target,domain,vuln_type,module,payload,payload_hash,"
                "technique,success,waf_name,tech_stack,confidence,response_code,scan_id,campaign_id,timestamp) "
                "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (target, domain, vuln_type, module, payload, ph, technique, int(success),
                 waf_name, tech_stack, confidence, response_code, scan_id, campaign_id, now))
            try:
                rid = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                conn.execute("INSERT INTO intel_fts(rowid,vuln_type,payload,technique,waf_name,tech_stack) VALUES(?,?,?,?,?,?)",
                             (rid, vuln_type, payload, technique, waf_name, tech_stack))
            except sqlite3.OperationalError:
                pass
            if payload:
                self._update_payload_eff(conn, vuln_type, payload, ph, success, waf_name)

    def _update_payload_eff(self, conn, vt, payload, ph, success, waf):
        row = conn.execute("SELECT id,success_count,fail_count,waf_bypassed FROM payload_effectiveness WHERE vuln_type=? AND payload_hash=?", (vt, ph)).fetchone()
        now = datetime.now().isoformat()
        if row:
            sc = row["success_count"] + (1 if success else 0)
            fc = row["fail_count"] + (0 if success else 1)
            wl = json.loads(row["waf_bypassed"] or "[]")
            if success and waf and waf not in wl: wl.append(waf)
            conn.execute("UPDATE payload_effectiveness SET success_count=?,fail_count=?,waf_bypassed=?,last_success=? WHERE id=?",
                         (sc, fc, json.dumps(wl), now if success else "", row["id"]))
        else:
            conn.execute("INSERT INTO payload_effectiveness (vuln_type,payload_hash,payload,success_count,fail_count,waf_bypassed,last_success) VALUES(?,?,?,?,?,?,?)",
                         (vt, ph, payload, 1 if success else 0, 0 if success else 1,
                          json.dumps([waf] if success and waf else []), now if success else ""))

    def record_negative_result(self, target, module, reason="no_findings", scan_id=""):
        domain = self._domain(target)
        with self._lock, self._conn() as conn:
            conn.execute("INSERT OR IGNORE INTO negative_results (target,domain,module,reason,scan_id,timestamp) VALUES(?,?,?,?,?,?)",
                         (target, domain, module, reason, scan_id, datetime.now().isoformat()))

    def record_defence(self, target, defence_type, detail=""):
        domain = self._domain(target)
        now = datetime.now().isoformat()
        with self._lock, self._conn() as conn:
            ex = conn.execute("SELECT id FROM known_defences WHERE domain=? AND defence_type=? AND detail=?", (domain, defence_type, detail)).fetchone()
            if ex:
                conn.execute("UPDATE known_defences SET last_seen=? WHERE id=?", (now, ex["id"]))
            else:
                conn.execute("INSERT INTO known_defences (target,domain,defence_type,detail,first_seen,last_seen) VALUES(?,?,?,?,?,?)",
                             (target, domain, defence_type, detail, now, now))

    def record_batch(self, target, findings, scan_id="", campaign_id="", waf_name="", tech_stack="[]"):
        for f in findings:
            if not isinstance(f, dict): continue
            self.record_scan_result(target=target, vuln_type=f.get("type", f.get("finding_type", "Unknown")),
                payload=f.get("payload", ""), success=True, waf_name=waf_name, tech_stack=tech_stack,
                module=f.get("module", ""), technique=f.get("technique", ""),
                confidence=f.get("confidence_score", f.get("ai_confidence", 0)),
                response_code=f.get("status_code", f.get("response_code", 0)),
                scan_id=scan_id, campaign_id=campaign_id)

    def query_intelligence(self, target, vuln_type=""):
        domain = self._domain(target)
        report = IntelReport(target=target)
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(DISTINCT scan_id) as cnt FROM scan_intel WHERE domain=?", (domain,)).fetchone()
            report.past_scans = row["cnt"] if row else 0
            for r in conn.execute("SELECT defence_type,detail,first_seen,last_seen,bypass_count FROM known_defences WHERE domain=? ORDER BY last_seen DESC", (domain,)).fetchall():
                report.known_defences.append(Defence(defence_type=r["defence_type"], detail=r["detail"], first_seen=r["first_seen"], last_seen=r["last_seen"], bypass_count=r["bypass_count"]))
            q = "SELECT * FROM payload_effectiveness WHERE success_count > 0"
            p = []
            if vuln_type: q += " AND vuln_type = ?"; p.append(vuln_type)
            q += " ORDER BY success_count DESC LIMIT 10"
            for r in conn.execute(q, p).fetchall():
                report.recommended_payloads.append(PayloadRecord(payload=r["payload"], vuln_type=r["vuln_type"],
                    success_count=r["success_count"], fail_count=r["fail_count"],
                    waf_bypassed=json.loads(r["waf_bypassed"] or "[]"), last_success=r["last_success"],
                    effectiveness=r["success_count"] / max(r["success_count"] + r["fail_count"], 1)))
            for r in conn.execute("SELECT module, COUNT(*) as cnt FROM negative_results WHERE domain=? GROUP BY module HAVING cnt >= 2 ORDER BY cnt DESC LIMIT 5", (domain,)).fetchall():
                report.modules_to_skip.append(r["module"])
            for r in conn.execute("SELECT DISTINCT module FROM scan_intel WHERE domain=? AND success=1 AND module != '' ORDER BY timestamp DESC LIMIT 5", (domain,)).fetchall():
                report.modules_to_prioritize.append(r["module"])
            waf_defs = [d for d in report.known_defences if d.defence_type == "waf"]
            if waf_defs: report.notes.append(f"WAF detected: {waf_defs[0].detail}. Use evasion payloads.")
            if report.modules_to_skip: report.notes.append(f"Modules {', '.join(report.modules_to_skip)} consistently return no findings.")
        return report

    def get_target_profile(self, target):
        domain = self._domain(target)
        profile = TargetIntel(target=target, domain=domain)
        with self._conn() as conn:
            row = conn.execute("SELECT COUNT(DISTINCT scan_id) as scans, COUNT(CASE WHEN success=1 THEN 1 END) as findings, MAX(timestamp) as last_scan, MAX(waf_name) as waf FROM scan_intel WHERE domain=?", (domain,)).fetchone()
            if row:
                profile.total_scans = row["scans"] or 0; profile.total_findings = row["findings"] or 0
                profile.last_scanned = row["last_scan"] or ""; profile.waf_name = row["waf"] or ""
            tech_row = conn.execute("SELECT tech_stack FROM scan_intel WHERE domain=? AND tech_stack != '[]' ORDER BY timestamp DESC LIMIT 1", (domain,)).fetchone()
            if tech_row:
                try: profile.tech_stack = json.loads(tech_row["tech_stack"])
                except (json.JSONDecodeError, TypeError): pass
            for r in conn.execute("SELECT defence_type,detail,first_seen,last_seen,bypass_count FROM known_defences WHERE domain=?", (domain,)).fetchall():
                profile.defences.append(Defence(defence_type=r["defence_type"], detail=r["detail"], first_seen=r["first_seen"], last_seen=r["last_seen"], bypass_count=r["bypass_count"]))
            for r in conn.execute("SELECT module, COUNT(*) as cnt FROM negative_results WHERE domain=? GROUP BY module ORDER BY cnt DESC", (domain,)).fetchall():
                profile.failed_modules.append({"module": r["module"], "fail_count": r["cnt"]})
        return profile

    def get_effective_payloads(self, vuln_type, waf_name="", limit=10):
        with self._conn() as conn:
            if waf_name:
                rows = conn.execute("SELECT * FROM payload_effectiveness WHERE vuln_type=? AND success_count > 0 AND waf_bypassed LIKE ? ORDER BY success_count DESC LIMIT ?",
                                    (vuln_type, f"%{waf_name}%", limit)).fetchall()
            else:
                rows = conn.execute("SELECT * FROM payload_effectiveness WHERE vuln_type=? AND success_count > 0 ORDER BY success_count DESC LIMIT ?", (vuln_type, limit)).fetchall()
        return [PayloadRecord(payload=r["payload"], vuln_type=r["vuln_type"], success_count=r["success_count"], fail_count=r["fail_count"],
                    waf_bypassed=json.loads(r["waf_bypassed"] or "[]"), last_success=r["last_success"],
                    effectiveness=r["success_count"] / max(r["success_count"] + r["fail_count"], 1)) for r in rows]

    def search(self, query, limit=10):
        with self._conn() as conn:
            try:
                rows = conn.execute("SELECT si.* FROM intel_fts fts INNER JOIN scan_intel si ON fts.rowid = si.id WHERE intel_fts MATCH ? ORDER BY rank LIMIT ?", (query, limit)).fetchall()
                return [dict(r) for r in rows]
            except sqlite3.OperationalError:
                rows = conn.execute("SELECT * FROM scan_intel WHERE payload LIKE ? OR vuln_type LIKE ? ORDER BY timestamp DESC LIMIT ?",
                                    (f"%{query}%", f"%{query}%", limit)).fetchall()
                return [dict(r) for r in rows]

    def get_stats(self):
        with self._conn() as conn:
            return {
                "total_records": conn.execute("SELECT COUNT(*) FROM scan_intel").fetchone()[0],
                "successful_payloads": conn.execute("SELECT COUNT(*) FROM scan_intel WHERE success=1").fetchone()[0],
                "unique_domains": conn.execute("SELECT COUNT(DISTINCT domain) FROM scan_intel").fetchone()[0],
                "known_defences": conn.execute("SELECT COUNT(*) FROM known_defences").fetchone()[0],
                "effective_payloads": conn.execute("SELECT COUNT(*) FROM payload_effectiveness WHERE success_count > 0").fetchone()[0],
                "negative_results": conn.execute("SELECT COUNT(*) FROM negative_results").fetchone()[0],
            }

_instance = None
_instance_lock = threading.Lock()

def get_scan_intelligence(db_path=None):
    global _instance
    with _instance_lock:
        if _instance is None:
            _instance = ScanIntelligence(db_path=db_path)
    return _instance
