"""
cyberm4fia-scanner — Multi-Agent Framework
Autonomous AI-driven pentesting with Planner-Executor-Summarizer loop.
Inspired by HackSynth, PentestGPT, and PentAGI architectures.

The AI DRIVES the scan — it decides what to scan next based on results,
rather than just analyzing results after the fact.

Supports OWASP APTS Graduated Autonomy Levels:
    L1 Assisted        — AI suggests, human approves every action
    L2 Semi-Autonomous  — AI auto-scans, human approves exploitation
    L3 Supervised       — AI exploits within scope, human monitors
    L4 Autonomous       — Full autonomy (strictest safety requirements)

Anti-Shallow Enforcement: Prevents superficial "found nothing" verdicts
and enforces depth-first exploration before marking endpoints exhausted.
Inspired by pentest-agents' chain-table methodology and 7-level WAF bypass protocol.
"""

import time
import signal
import importlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse
from enum import IntEnum

from utils.colors import (
    Colors,
    log_error,
    log_info,
    log_success,
    log_warning,
)
from utils.scan_intelligence import get_scan_intelligence


# ─── Anti-Shallow / Depth Enforcement Constants ──────────────────────────

# Minimum probes per vulnerability class before declaring "no findings"
# Inspired by pentest-agents: 7-level WAF bypass + technique depth requirements
MIN_PROBES_PER_CLASS = {
    "xss": 8,
    "sqli": 10,
    "lfi": 8,
    "cmdi": 8,
    "ssrf": 10,
    "ssti": 6,
    "xxe": 6,
    "jwt": 5,
    "idor": 8,
    "open_redirect": 6,
    "cors": 6,
    "csrf": 5,
    "file_upload": 8,
    "deserialization": 5,
    "proto_pollution": 6,
    "race_condition": 10,
    "smuggling": 6,
    "header_inject": 6,
    "nosqli": 6,
    "cache_poisoning": 6,
    "log4shell": 8,
    "el_injection": 6,
    "ldap": 5,
    "xpath": 5,
    "crlf": 6,
    "csv_injection": 5,
    "graphql": 8,
    "business_logic": 8,
    "forbidden_bypass": 10,
    "subdomain_takeover": 5,
    "oauth": 8,
}

# Exhaustion requires all three conditions
EXHAUSTION_REQUIREMENTS = [
    "min_probes_met",
    "all_bypass_levels_attempted",
    "blocker_recorded",
]

# WAF bypass levels that must be attempted before declaring exhaustion
WAF_BYPASS_LEVELS = {
    1: "Encoding (URL, double-URL, Unicode, HTML entity)",
    2: "Tag alternatives (svg, details, math, dialog instead of script/img)",
    3: "Parser differentials (tag confusion, nesting, re-parenting)",
    4: "Protocol variations (javascript:, data:, vbscript:)",
    5: "Framework-specific sinks (React, Angular, Vue, jQuery, Bootstrap)",
    6: "CSP-bypass techniques (nonce, base-tag, srcdoc, dynamic import)",
    7: "Obfuscation (JSFuck, unicode identifiers, constructor chains)",
}

# Modules that must NEVER return "not vulnerable" without a browser probe
BROWSER_REQUIRED_MODULES = {
    "xss", "dom_xss", "csrf", "business_logic", "file_upload",
    "race_condition", "open_redirect", "account_takeover", "auth_bypass",
}

# Modules susceptible to WAF false negatives (curl 403 ≠ not vulnerable)
WAF_SENSITIVE_MODULES = {
    "xss", "sqli", "cmdi", "ssrf", "lfi", "ssti", "xxe", "forbidden_bypass",
    "header_inject", "smuggling", "cache_poisoning", "file_upload",
}

# Max failed candidates per depth (chain-table rule 5)
MAX_FAILED_CANDIDATES_PER_DEPTH = 3

# 20-minute time box per link (chain-table rule 4)
CHAIN_LINK_TIMEOUT = 1200


# ─── Autonomy Levels (OWASP APTS) ───────────────────────────────────────

class AutonomyLevel(IntEnum):
    """APTS Graduated Autonomy Levels (L1-L4)."""
    L1_ASSISTED = 1       # AI suggests, human approves every action
    L2_SEMI_AUTO = 2      # AI auto-scans, human approves exploitation
    L3_SUPERVISED = 3     # AI exploits within scope, human monitors
    L4_AUTONOMOUS = 4     # Full autonomy — strictest safety requirements

    @classmethod
    def from_string(cls, s):
        mapping = {
            "l1": cls.L1_ASSISTED, "assisted": cls.L1_ASSISTED,
            "l2": cls.L2_SEMI_AUTO, "semi": cls.L2_SEMI_AUTO, "semi-autonomous": cls.L2_SEMI_AUTO,
            "l3": cls.L3_SUPERVISED, "supervised": cls.L3_SUPERVISED,
            "l4": cls.L4_AUTONOMOUS, "autonomous": cls.L4_AUTONOMOUS, "full": cls.L4_AUTONOMOUS,
        }
        return mapping.get(s.lower(), cls.L3_SUPERVISED)


AUTONOMY_LEVEL = AutonomyLevel.L3_SUPERVISED  # Default


def requires_approval(action_type: str) -> bool:
    """Check if an action requires human approval at the current autonomy level."""
    if AUTONOMY_LEVEL <= AutonomyLevel.L1_ASSISTED:
        return True
    if AUTONOMY_LEVEL <= AutonomyLevel.L2_SEMI_AUTO:
        return action_type in ("exploit", "shell", "exfil", "destructive", "write")
    if AUTONOMY_LEVEL <= AutonomyLevel.L3_SUPERVISED:
        return action_type in ("destructive", "scope_exit")
    return False  # L4 full autonomy


# ─── Data Classes ───────────────────────────────────────────────────────

@dataclass
class AgentTask:
    """A task assigned to an agent."""
    id: str
    description: str
    agent_role: str
    status: str = "pending"
    result: Optional[dict] = None
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: str = ""


@dataclass
class MissionReport:
    """Final report from an orchestrated mission."""
    target: str
    start_time: str
    end_time: str = ""
    agents_used: list = field(default_factory=list)
    tasks: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    summary: str = ""
    status: str = "in_progress"

    def to_dict(self):
        return {
            "target": self.target,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "agents_used": self.agents_used,
            "task_count": len(self.tasks),
            "finding_count": len(self.findings),
            "summary": self.summary,
            "status": self.status,
        }


# ─── Agent Memory ───────────────────────────────────────────────────────

class AgentMemory:
    """Persistent context across agent iterations with intelligence integration."""

    def __init__(self, target: str):
        self.target = target
        self.iterations = []
        self.modules_run = set()
        self.all_findings = []
        self.tech_stack = []
        self.discovered_endpoints = []
        self.waf_detected = None
        self.recon_data = {}
        # Intelligence integration (0-Day Machine knowledge loop)
        self.intel_report = None
        self.target_profile = None
        self.scan_recommendation = None
        self._load_intelligence(target)

    def _load_intelligence(self, target: str):
        """Load past intelligence for this target from the knowledge loop."""
        try:
            from utils.scan_intelligence import get_scan_intelligence
            from utils.target_profiler import TargetProfiler

            intel = get_scan_intelligence()
            self.intel_report = intel.query_intelligence(target)
            profiler = TargetProfiler()
            self.target_profile = profiler.build_profile(target)
            self.scan_recommendation = profiler.get_scan_recommendation(
                target,
                tech_stack=self.target_profile.tech_stack,
                waf_name=self.target_profile.waf_name,
                defences=self.target_profile.defences,
                past_findings=self.target_profile.total_findings,
                past_scans=self.target_profile.total_scans,
            )
            if self.intel_report and self.intel_report.past_scans > 0:
                from utils.colors import log_info
                log_info(
                    f"🧠 Intelligence loaded: {self.intel_report.past_scans} past scans, "
                    f"priority {self.scan_recommendation.priority_score:.0f}/100"
                )
        except Exception:
            pass

    def add_iteration(self, plan: dict, results: dict, summary: str):
        self.iterations.append({
            "plan": plan,
            "results": results,
            "summary": summary,
            "timestamp": time.time(),
        })

    def add_findings(self, findings: list):
        self.all_findings.extend(findings)

    def get_context_window(self, max_chars: int = 3000) -> str:
        """Build context for the planner from memory, enriched with intelligence."""
        ctx = [f"Target: {self.target}"]

        # Intelligence data (knowledge loop)
        if self.scan_recommendation:
            ctx.append(f"Priority Score: {self.scan_recommendation.priority_score:.0f}/100")
        if self.intel_report and self.intel_report.past_scans > 0:
            ctx.append(f"Past Scans: {self.intel_report.past_scans}")
            if self.intel_report.known_defences:
                defs = ", ".join(f"{d.defence_type}({d.detail})" for d in self.intel_report.known_defences[:3])
                ctx.append(f"Known Defences: {defs}")
            if self.intel_report.modules_to_skip:
                ctx.append(f"Skip (no results before): {', '.join(self.intel_report.modules_to_skip[:5])}")
            if self.intel_report.modules_to_prioritize:
                ctx.append(f"Prioritize (found vulns before): {', '.join(self.intel_report.modules_to_prioritize[:5])}")

        if self.tech_stack:
            techs = ", ".join(
                t.get("name", "?") for t in self.tech_stack[:10]
                if isinstance(t, dict)
            )
            ctx.append(f"Tech Stack: {techs}")

        if self.waf_detected:
            ctx.append(f"WAF Detected: {self.waf_detected}")

        ctx.append(f"Modules already run: {', '.join(sorted(self.modules_run)) or 'none'}")
        ctx.append(f"Total findings: {len(self.all_findings)}")

        # Critical/High findings
        important = [
            f for f in self.all_findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        if important:
            ctx.append("Critical/High findings:")
            for f in important[:5]:
                ctx.append(
                    f"  - {f.get('type', '?')}: {f.get('url', '?')} "
                    f"[{f.get('severity', '?')}]"
                )

        # Last iteration summary
        if self.iterations:
            ctx.append(f"\nLast iteration:\n{self.iterations[-1]['summary'][:500]}")

        return "\n".join(ctx)[:max_chars]


# ─── System Prompts ─────────────────────────────────────────────────────

PLANNER_SYSTEM = """You are an elite penetration tester AI agent controlling cyberm4fia-scanner.
You analyze scan results and decide the NEXT best scanning action.

Available modules:
- recon: Network recon (ports, DNS, WHOIS, IP info)
- tech_detect: Technology fingerprinting
- header_audit: Security header analysis
- xss: Cross-Site Scripting
- sqli: SQL Injection
- lfi: Local File Inclusion
- cmdi: Command Injection
- ssrf: Server-Side Request Forgery
- ssti: Server-Side Template Injection
- xxe: XML External Entity
- csrf: CSRF scanner
- cors: CORS misconfiguration
- jwt: JWT token attacks
- open_redirect: Open Redirect
- header_inject: HTTP Header Injection
- dom_xss: DOM-based XSS
- smuggling: HTTP Request Smuggling
- deserialization: Insecure Deserialization
- proto_pollution: Prototype Pollution
- business_logic: Business logic flaws
- race_condition: Race conditions
- forbidden_bypass: 403 bypass
- file_upload: File upload vulns
- account_takeover: Account takeover
- auth_bypass: Auth bypass
- csp_bypass: CSP bypass
- cookie_hsts: Cookie & HSTS audit
- subdomain: Subdomain enumeration
- secrets: Secret/credential scanner
- rfi: Remote File Inclusion
- api_scanner: API endpoint security testing
- email_harvest: Email address harvesting
- endpoint_fuzzer: Endpoint/directory discovery
- subdomain_takeover: Subdomain takeover detection
- spray: Service brute-force (requires recon first)

Rules:
1. Always start with recon + tech_detect + header_audit if no prior data exists
2. Choose modules based on discovered technology (PHP→LFI, Java→deserialization, etc.)
3. If WAF detected, prioritize bypass-capable modules
4. Don't repeat modules unless you have new attack vectors
5. Run max 3 modules per iteration
6. When scanning is complete, set "done": true

Respond ONLY with valid JSON:
{"reasoning": "why I chose this", "modules": ["mod1", "mod2"], "priority": "high", "done": false}"""

SUMMARIZER_SYSTEM = """You are a cybersecurity scan analyst. Given raw results,
produce a concise tactical summary for the planner AI.

Include: key findings, new attack surface, what failed/blocked, recommended next steps.
Keep it under 150 words. Be precise and technical."""


# ─── Module Executor ────────────────────────────────────────────────────

MODULE_MAP = {
    "recon":             ("modules.recon", "run_recon", False),
    "tech_detect":       ("modules.tech_detect", "scan_technology", False),
    "header_audit":      ("modules.passive", "scan_passive", False),
    "xss":               ("modules.xss", "scan_xss", True),
    "sqli":              ("modules.sqli", "scan_sqli", True),
    "lfi":               ("modules.lfi", "scan_lfi", True),
    "cmdi":              ("modules.cmdi", "scan_cmdi", True),
    "ssrf":              ("modules.ssrf", "scan_ssrf", True),
    "ssti":              ("modules.ssti", "scan_ssti", False),
    "xxe":               ("modules.xxe", "scan_xxe", False),
    "csrf":              ("modules.csrf", "scan_csrf", True),
    "cors":              ("modules.cors", "scan_cors", False),
    "jwt":               ("modules.jwt_attack", "scan_jwt", False),
    "open_redirect":     ("modules.open_redirect", "scan_open_redirect", False),
    "header_inject":     ("modules.header_inject", "scan_header_inject", False),
    "dom_xss":           ("modules.dom_xss", "scan_dom_xss", False),
    "smuggling":         ("modules.smuggling", "scan_smuggling", False),
    "deserialization":   ("modules.deserialization", "scan_deserialization", False),
    "proto_pollution":   ("modules.proto_pollution", "scan_proto_pollution", True),
    "business_logic":    ("modules.business_logic", "scan_business_logic", True),
    "race_condition":    ("modules.race_condition", "scan_race_condition", True),
    "forbidden_bypass":  ("modules.forbidden_bypass", "scan_forbidden_bypass", False),
    "file_upload":       ("modules.file_upload", "scan_file_upload", True),
    "account_takeover":  ("modules.account_takeover", "scan_account_takeover", False),
    "auth_bypass":       ("modules.auth_bypass", "scan_auth_bypass", False),
    "csp_bypass":        ("modules.csp_bypass", "scan_csp_bypass", False),
    "cookie_hsts":       ("modules.cookie_hsts_audit", "scan_cookie_hsts", False),
    "subdomain":         ("modules.subdomain", "scan_subdomains", False),
    "secrets":           ("modules.secrets_scanner", "scan_secrets", False),
    "cloud_enum":        ("modules.cloud_enum", "scan_cloud_storage", False),
    "rfi":               ("modules.rfi", "scan_rfi", True),
    "api_scanner":       ("modules.api_scanner", "scan_api", False),
    "email_harvest":     ("modules.email_harvest", "scan_email_harvest", False),
    "endpoint_fuzzer":   ("modules.endpoint_fuzzer", "scan_fuzzer_async", False),
    "subdomain_takeover":("modules.subdomain_takeover", "scan_subdomain_takeover", False),
    "spray":             ("modules.spray", "scan_spray", False),
}


def _get_forms(target, delay=0, _cache={}):
    """Crawl and cache forms (singleton per target)."""
    if target in _cache:
        return _cache[target]
    try:
        from modules.dynamic_crawler import run_dynamic_spider
        log_info("  Crawling for forms...")
        pages = run_dynamic_spider(target, delay=delay)
        forms = []
        for page in (pages or []):
            forms.extend(page.get("forms", []))
        _cache[target] = forms
        log_info(f"  Found {len(forms)} forms across {len(pages or [])} pages")
    except Exception:
        _cache[target] = []
    return _cache[target]


def execute_module(mod_id, target, memory, delay=0):
    """Execute a single scanner module and return results."""
    if mod_id not in MODULE_MAP:
        log_warning(f"  Unknown module '{mod_id}', skipping")
        return None

    mod_path, func_name, needs_forms = MODULE_MAP[mod_id]
    memory.modules_run.add(mod_id)

    try:
        module = importlib.import_module(mod_path)
        func = getattr(module, func_name)
        start = time.time()

        if needs_forms:
            forms = _get_forms(target, delay)
            result = func(target, forms, delay)
        elif mod_id == "recon":
            result = func(target, deep=False)
        elif mod_id == "subdomain":
            domain = urlparse(target).hostname
            result = func(domain)
        elif mod_id == "secrets":
            import httpx
            try:
                resp = httpx.get(target, timeout=10, verify=False)
                result = func(target, resp.text)
            except Exception:
                result = []
        elif mod_id == "endpoint_fuzzer":
            import asyncio
            try:
                result = asyncio.run(func(target))
            except Exception:
                result = func(target)
        elif mod_id == "spray":
            # Needs host + open_ports from recon
            host = urlparse(target).hostname
            open_ports = []
            if memory.recon_data and isinstance(memory.recon_data, dict):
                open_ports = memory.recon_data.get("open_ports", [])
            if open_ports:
                result = func(host, open_ports)
            else:
                log_warning("  spray: no open ports from recon, skipping")
                result = []
        elif mod_id == "subdomain_takeover":
            result = func(target)
        else:
            result = func(target)

        elapsed = time.time() - start

        # Extract metadata
        if mod_id == "tech_detect" and isinstance(result, list):
            memory.tech_stack = result
            for t in result:
                if isinstance(t, dict) and t.get("type") == "waf":
                    memory.waf_detected = t.get("name", "Unknown WAF")

        if mod_id == "recon" and isinstance(result, dict):
            memory.recon_data = result

        # Store findings
        if isinstance(result, list):
            findings = [r for r in result if isinstance(r, dict) and r.get("type")]
            memory.add_findings(findings)

        # Anti-shallow: count probes
        if isinstance(result, list):
            probe_count = len(result)
        elif isinstance(result, dict) and "error" not in result:
            probe_count = 1
        else:
            probe_count = 0
        if hasattr(memory, 'depth_tracker') and memory.depth_tracker:
            memory.depth_tracker.record_probe(mod_id, max(probe_count, 1))
        elif hasattr(memory, '_orchestrator_depth'):
            memory._orchestrator_depth.record_probe(mod_id, max(probe_count, 1))

        log_success(f"  ✓ {mod_id} ({elapsed:.1f}s)")
        return result

    except Exception as e:
        log_error(f"  ✗ {mod_id}: {e}")
        return {"error": str(e)}


# ─── Agent Orchestrator ─────────────────────────────────────────────────

class AgentOrchestrator:
    """
    AI-driven pentesting orchestrator with Planner-Executor-Summarizer loop.

    Flow (per iteration):
    1. PLANNER (AI) → analyzes context, decides which modules to run
    2. EXECUTOR → runs the chosen modules
    3. SUMMARIZER (AI) → summarizes results, feeds back to planner
    4. Repeat until AI says "done" or max iterations reached
    """

    MAX_ITERATIONS = 5
    MAX_TIME = 600  # 10 minutes

    def __init__(self, ai_client=None):
        if ai_client is None:
            try:
                from utils.ai import get_dual_ai, get_ai, init_ai
                dual = get_dual_ai()
                if dual and dual.available:
                    ai_client = dual
                else:
                    ai = get_ai()
                    if ai.available:
                        ai_client = ai
                    else:
                        ai_client = init_ai()
            except Exception:
                pass

        self.ai_client = ai_client
        self.interrupted = False
        self.depth_tracker = DepthTracker()

    def _get_ai_client(self, role="exploit"):
        """Get the best AI client for a role."""
        if self.ai_client is None:
            return None
        # DualModelAI
        if hasattr(self.ai_client, "get_client_for_role"):
            return self.ai_client.get_client_for_role(role)
        # NvidiaApiClient
        if getattr(self.ai_client, "available", False):
            return self.ai_client
        return None

    def _handle_interrupt(self, signum, frame):
        print(f"\n{Colors.YELLOW}⚠ Agent interrupted. Finishing current iteration...{Colors.END}")
        self.interrupted = True

    def _ai_plan(self, memory):
        """Ask AI to decide the next scan step."""
        client = self._get_ai_client("exploit")
        if not client or not getattr(client, "available", False):
            # Fallback: deterministic plan
            return self._fallback_plan(memory)

        from utils.ai import _extract_json
        context = memory.get_context_window()

        prompt = f"""Current scan state:

{context}

Based on this data, what should I scan next? Pick the most effective modules (max 3).
If we have enough data, set "done": true.

Respond with JSON only."""

        try:
            response = client.generate(
                prompt, system=PLANNER_SYSTEM,
                temperature=0.3, model_role="exploit",
            )
            result = _extract_json(response)
            if result and isinstance(result, dict) and result.get("modules"):
                return result
        except Exception as e:
            log_warning(f"  Planner AI error: {e}")

        return self._fallback_plan(memory)

    def _fallback_plan(self, memory):
        """Deterministic fallback when AI is unavailable."""
        if not memory.modules_run:
            return {
                "reasoning": "Starting with reconnaissance (fallback mode)",
                "modules": ["recon", "tech_detect", "header_audit"],
                "priority": "high",
                "done": False,
            }

        # Phase 2: Core vulnerability scanning
        core_vulns = {"xss", "sqli", "lfi", "cmdi", "ssrf", "ssti"}
        remaining = core_vulns - memory.modules_run
        if remaining:
            mods = list(remaining)[:3]
            return {
                "reasoning": f"Running core vuln scanners: {', '.join(mods)}",
                "modules": mods,
                "priority": "high",
                "done": False,
            }

        # Phase 3: Advanced testing
        advanced = {"xxe", "csrf", "cors", "jwt", "smuggling", "deserialization"}
        remaining = advanced - memory.modules_run
        if remaining:
            mods = list(remaining)[:3]
            return {
                "reasoning": f"Running advanced scanners: {', '.join(mods)}",
                "modules": mods,
                "priority": "medium",
                "done": False,
            }

        return {"reasoning": "All key modules completed", "modules": [], "done": True}

    def _ai_summarize(self, results, memory):
        """Ask AI to summarize scan results."""
        client = self._get_ai_client("analysis")
        if not client or not getattr(client, "available", False):
            return self._fallback_summarize(results, memory)

        result_text = []
        for mod_id, data in results.items():
            if isinstance(data, list):
                severities = {}
                for d in data:
                    if isinstance(d, dict):
                        sev = d.get("severity", "info")
                        severities[sev] = severities.get(sev, 0) + 1
                sev_str = ", ".join(f"{k}:{v}" for k, v in severities.items())
                result_text.append(f"- {mod_id}: {len(data)} findings ({sev_str or 'raw'})")
            elif isinstance(data, dict):
                if "error" in data:
                    result_text.append(f"- {mod_id}: ERROR - {data['error']}")
                else:
                    result_text.append(f"- {mod_id}: completed")
            else:
                result_text.append(f"- {mod_id}: {str(data)[:80]}")

        prompt = f"""Summarize these scan results for {memory.target}:

{chr(10).join(result_text)}

Total findings: {len(memory.all_findings)}
Modules run: {', '.join(sorted(memory.modules_run))}

Give a tactical summary for planning the next scan step."""

        try:
            response = client.generate(
                prompt, system=SUMMARIZER_SYSTEM,
                temperature=0.2, model_role="analysis",
            )
            if response:
                return response
        except Exception:
            pass

        return self._fallback_summarize(results, memory)

    def _fallback_summarize(self, results, memory):
        """Simple rule-based summary when AI is unavailable."""
        lines = [f"Scan update for {memory.target}:"]
        for mod_id, data in results.items():
            if isinstance(data, list):
                lines.append(f"  {mod_id}: {len(data)} results")
            elif isinstance(data, dict) and "error" in data:
                lines.append(f"  {mod_id}: failed")
            else:
                lines.append(f"  {mod_id}: completed")
        lines.append(f"Total findings: {len(memory.all_findings)}")
        return "\n".join(lines)

    def run_mission(self, target, scope=None):
        """
        Run the AI-driven pentesting loop.

        The AI plans → executor runs → AI summarizes → repeat.
        """
        start_time = time.time()
        memory = AgentMemory(target)
        memory._orchestrator_depth = self.depth_tracker
        old_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_interrupt)

        mission = MissionReport(
            target=target,
            start_time=datetime.now().isoformat(),
            agents_used=["Planner", "Executor", "Summarizer"],
        )

        # ── Banner ──
        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 58}")
        print(f"  🤖 AGENT MODE — AI-Driven Penetration Test")
        print(f"  Target: {target}")
        print(f"  Max iterations: {self.MAX_ITERATIONS} | Timeout: {self.MAX_TIME}s")
        print(f"{'═' * 58}{Colors.END}\n")

        ai_available = bool(self._get_ai_client("exploit"))
        if not ai_available:
            log_warning("AI not available — running in deterministic fallback mode")
            log_info("For AI-driven mode: export NVIDIA_API_KEY=your_key")

        for iteration in range(1, self.MAX_ITERATIONS + 1):
            elapsed = time.time() - start_time
            if elapsed > self.MAX_TIME:
                log_warning(f"Time limit reached ({self.MAX_TIME}s)")
                break

            if self.interrupted:
                break

            print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'─' * 58}")
            print(f"  Iteration {iteration}/{self.MAX_ITERATIONS}")
            print(f"{'─' * 58}{Colors.END}")

            # Brief pause for interrupt opportunity
            print(f"{Colors.DIM}  Ctrl+C to stop after this iteration{Colors.END}")
            try:
                time.sleep(1.5)
            except KeyboardInterrupt:
                self.interrupted = True
                break

            # ── PLAN ──
            icon = "🧠" if ai_available else "📋"
            print(f"\n  {Colors.CYAN}{icon} PLANNER:{Colors.END}", end=" ")
            plan = self._ai_plan(memory)

            reasoning = plan.get("reasoning", "")
            modules = plan.get("modules", [])[:3]
            done = plan.get("done", False)
            priority = plan.get("priority", "medium")

            print(reasoning)
            if modules:
                print(f"  {Colors.BOLD}→ {', '.join(modules)} [{priority}]{Colors.END}")

            # Record decision for Auditability (APTS)
            get_scan_intelligence().record_ai_decision(
                target=target,
                module=",".join(modules),
                reasoning=reasoning,
                action=f"Priority: {priority}, Done: {done}"
            )

            if done or not modules:
                log_success("AI determined scan is complete ✓")
                break

            # ── EXECUTE ──
            print(f"\n  {Colors.YELLOW}⚡ EXECUTOR:{Colors.END}")
            results = {}
            for mod_id in modules:
                result = execute_module(mod_id, target, memory, delay=0)
                if result is not None:
                    results[mod_id] = result

            mission.tasks.append(AgentTask(
                id=f"iter_{iteration}",
                description=f"Ran: {', '.join(modules)}",
                agent_role="executor",
                status="completed",
                result={"modules": modules, "finding_count": len(memory.all_findings)},
            ))

            # ── ESCALATE (Chain Engine) ──
            new_high = [
                f for f in memory.all_findings
                if isinstance(f, dict)
                and f.get("severity", "").lower() in ("critical", "high")
                and not f.get("proven")
            ]
            if new_high:
                try:
                    from utils.vuln_chain import run_escalations
                    print(f"\n  {Colors.RED}🔗 CHAIN ENGINE:{Colors.END}")
                    proven = run_escalations(new_high)
                    if proven:
                        memory.add_findings(proven)
                        mission.findings.extend(proven)
                except Exception as e:
                    log_warning(f"  Chain engine error: {e}")

            # ── SUMMARIZE ──
            icon = "📝" if ai_available else "📊"
            print(f"\n  {Colors.GREEN}{icon} SUMMARIZER:{Colors.END}")
            summary = self._ai_summarize(results, memory)
            # Show truncated summary
            for line in summary.split("\n")[:6]:
                if line.strip():
                    print(f"  {line.strip()}")

            memory.add_iteration(plan, results, summary)

        # ── Restore signal handler ──
        signal.signal(signal.SIGINT, old_handler)
        self.interrupted = False

        # ── Final Report ──
        total_time = time.time() - start_time
        mission.findings = memory.all_findings
        mission.end_time = datetime.now().isoformat()
        mission.status = "completed"

        # Generate final AI summary if available
        client = self._get_ai_client("summary")
        if client and getattr(client, "available", False) and memory.all_findings:
            try:
                from utils.ai import generate_scan_summary
                stats = {"requests": 0, "waf": 0}
                final_summary = generate_scan_summary(
                    client, memory.all_findings, target, stats
                )
                if final_summary:
                    mission.summary = final_summary
            except Exception:
                pass

        if not mission.summary:
            mission.summary = (
                f"Agent scan of {target}: {len(memory.all_findings)} findings "
                f"in {len(memory.iterations)} iterations ({total_time:.0f}s)"
            )

        self._print_final_report(mission, memory, total_time)
        return mission

    def _print_final_report(self, mission, memory, total_time):
        """Print formatted final report."""
        findings = memory.all_findings
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'═' * 58}")
        print(f"  ✅ AGENT MISSION COMPLETE")
        print(f"{'═' * 58}{Colors.END}")
        print(f"  Target:     {mission.target}")
        print(f"  Iterations: {len(memory.iterations)}")
        print(f"  Modules:    {', '.join(sorted(memory.modules_run))}")
        print(f"  Time:       {total_time:.1f}s")
        print(f"  Findings:   {len(findings)}")

        if severity_counts:
            sev_str = "  Severity:   "
            parts = []
            for sev in ("critical", "high", "medium", "low", "info"):
                count = severity_counts.get(sev, 0)
                if count:
                    color = {
                        "critical": Colors.RED, "high": Colors.RED,
                        "medium": Colors.YELLOW, "low": Colors.CYAN,
                        "info": Colors.DIM,
                    }.get(sev, "")
                    parts.append(f"{color}{sev}: {count}{Colors.END}")
            print(sev_str + " | ".join(parts))

        if mission.summary:
            print(f"\n  {Colors.BOLD}Executive Summary:{Colors.END}")
            for line in mission.summary.split("\n")[:5]:
                if line.strip():
                    print(f"  {line.strip()}")

        print()

# ─── Anti-Shallow Depth Tracker ──────────────────────────────────────────

@dataclass
class ModuleDepth:
    """Tracks exploration depth for a single vulnerability class module."""
    module_id: str
    probes_sent: int = 0
    bypass_levels_attempted: set = field(default_factory=set)
    last_result: str = ""
    exhaustion_status: str = "active"   # active, exhausted, blocked
    blocker_reason: str = ""
    waf_detected: bool = False
    browser_used: bool = False

    def meets_min_probes(self) -> bool:
        required = MIN_PROBES_PER_CLASS.get(self.module_id, 5)
        return self.probes_sent >= required

    def all_bypass_levels_attempted(self) -> bool:
        return len(self.bypass_levels_attempted) >= len(WAF_BYPASS_LEVELS)

    def is_exhausted(self) -> bool:
        if self.exhaustion_status == "exhausted":
            return True
        if self.meets_min_probes() and self.all_bypass_levels_attempted() and self.blocker_reason:
            self.exhaustion_status = "exhausted"
            return True
        return False

    def record_blocker(self, reason: str):
        self.blocker_reason = reason
        self.exhaustion_status = "blocked"


class DepthTracker:
    """Enforces anti-shallow exploration: no module returns 'not vulnerable'
    without meeting minimum probe counts and attempting all bypass levels."""

    def __init__(self):
        self.modules: dict[str, ModuleDepth] = {}

    def get_or_create(self, module_id: str) -> ModuleDepth:
        if module_id not in self.modules:
            self.modules[module_id] = ModuleDepth(module_id=module_id)
        return self.modules[module_id]

    def record_probe(self, module_id: str, count: int = 1):
        md = self.get_or_create(module_id)
        md.probes_sent += count

    def record_bypass_level(self, module_id: str, level: int):
        md = self.get_or_create(module_id)
        md.bypass_levels_attempted.add(level)

    def record_browser_use(self, module_id: str):
        md = self.get_or_create(module_id)
        md.browser_used = True

    def check_anti_shallow(self, module_id: str, result) -> tuple[bool, str]:
        """Returns (can_declare_done: bool, reason: str).

        If result has 0 findings and module requires depth, this returns
        (False, reason) meaning the module should NOT be marked done.
        """
        md = self.get_or_create(module_id)

        has_findings = False
        if isinstance(result, list):
            has_findings = len(result) > 0
        elif isinstance(result, dict) and result.get("error") is None:
            has_findings = True

        if has_findings:
            return True, ""

        required_probes = MIN_PROBES_PER_CLASS.get(module_id, 5)
        if md.probes_sent < required_probes:
            return False, (
                f"Anti-shallow: {module_id} has 0 findings but only "
                f"{md.probes_sent}/{required_probes} minimum probes sent. "
                f"Run {required_probes - md.probes_sent} more probes before declaring done."
            )

        if module_id in BROWSER_REQUIRED_MODULES and not md.browser_used:
            return False, (
                f"Anti-shallow: {module_id} requires a browser probe before "
                f"declaring 'not vulnerable'. curl results from CDN-based targets "
                f"are not valid 'not vulnerable' verdicts."
            )

        if module_id in WAF_SENSITIVE_MODULES and not md.all_bypass_levels_attempted():
            remaining_levels = set(WAF_BYPASS_LEVELS.keys()) - md.bypass_levels_attempted
            return False, (
                f"Anti-shallow: {module_id} has not attempted "
                f"WAF bypass levels: {sorted(remaining_levels)}. "
                f"WAF block is not a valid dead-end verdict."
            )

        return True, ""

    def exhaustion_summary(self) -> dict:
        summary = {}
        for mod_id, md in self.modules.items():
            summary[mod_id] = {
                "probes": md.probes_sent,
                "bypass_levels": sorted(md.bypass_levels_attempted),
                "browser_used": md.browser_used,
                "status": md.exhaustion_status,
                "blocker": md.blocker_reason,
            }
        return summary

    def enforce_waf_bypass_decision(self, module_id: str, waf_detected: bool):
        """If WAF is detected, mark module as needing full bypass ladder."""
        md = self.get_or_create(module_id)
        md.waf_detected = waf_detected

    def is_chainable(self, vuln_type: str) -> bool:
        """Check if a vulnerability type is chainable to higher impact."""
        chainable_primitives = {
            "ssrf", "xss", "sqli", "lfi", "xxe", "idor", "ssti",
            "open_redirect", "file_upload", "jwt", "subdomain_takeover",
            "command_injection", "deserialization", "proto_pollution",
        }
        return vuln_type.lower() in chainable_primitives

    def get_chain_candidates(self, vuln_type: str) -> list[str]:
        """Given a vulnerability type, return list of escalation targets."""
        chain_map = {
            "ssrf": ["cloud_metadata", "internal_access", "auth_bypass"],
            "xss": ["session_hijack", "account_takeover", "data_theft"],
            "sqli": ["data_exfil", "rce", "auth_bypass"],
            "lfi": ["source_disclosure", "rce", "credential_theft"],
            "xxe": ["ssrf", "credential_theft", "data_exfil"],
            "idor": ["ato", "data_breach", "account_manipulation"],
            "ssti": ["rce", "data_exfil", "internal_access"],
            "open_redirect": ["oauth_theft", "phishing"],
            "file_upload": ["rce", "xss", "app_takeover"],
            "jwt": ["auth_bypass", "session_hijack", "ato"],
            "subdomain_takeover": ["phishing", "cookie_theft", "ato"],
            "command_injection": ["rce", "reverse_shell", "data_exfil"],
            "deserialization": ["rce", "data_exfil"],
            "proto_pollution": ["rce", "xss", "data_exfil"],
        }
        return chain_map.get(vuln_type.lower(), [])
