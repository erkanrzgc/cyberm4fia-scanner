"""
cyberm4fia-scanner — Multi-Agent Framework
Autonomous AI-driven pentesting with Planner-Executor-Summarizer loop.
Inspired by HackSynth, PentestGPT, and PentAGI architectures.

The AI DRIVES the scan — it decides what to scan next based on results,
rather than just analyzing results after the fact.
"""

import json
import time
import signal
import importlib
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import ScanExceptions


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
    """Persistent context across agent iterations."""

    def __init__(self, target: str):
        self.target = target
        self.iterations = []
        self.modules_run = set()
        self.all_findings = []
        self.tech_stack = []
        self.discovered_endpoints = []
        self.waf_detected = None
        self.recon_data = {}

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
        """Build context for the planner from memory."""
        ctx = [f"Target: {self.target}"]

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
    "proto_pollution":   ("modules.proto_pollution", "scan_proto_pollution", False),
    "business_logic":    ("modules.business_logic", "scan_business_logic", False),
    "race_condition":    ("modules.race_condition", "scan_race_condition", False),
    "forbidden_bypass":  ("modules.forbidden_bypass", "scan_forbidden_bypass", False),
    "file_upload":       ("modules.file_upload", "scan_file_upload", False),
    "account_takeover":  ("modules.account_takeover", "scan_account_takeover", False),
    "auth_bypass":       ("modules.auth_bypass", "scan_auth_bypass", False),
    "csp_bypass":        ("modules.csp_bypass", "scan_csp_bypass", False),
    "cookie_hsts":       ("modules.cookie_hsts_audit", "scan_cookie_hsts", False),
    "subdomain":         ("modules.subdomain", "scan_subdomains", False),
    "secrets":           ("modules.secrets_scanner", "scan_secrets", False),
    "cloud_enum":        ("modules.cloud_enum", "scan_cloud_storage", False),
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
                from utils.ai import get_dual_ai, get_ai, init_ai, init_dual_ai
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

    def _get_ai_client(self, role="exploit"):
        """Get the best AI client for a role."""
        if self.ai_client is None:
            return None
        # DualModelAI
        if hasattr(self.ai_client, "get_client_for_role"):
            return self.ai_client.get_client_for_role(role)
        # OllamaClient
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
            log_info("For AI-driven mode: ollama serve && ollama pull WhiteRabbitNeo")

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
                from utils.ai import generate_scan_summary, get_runtime_stats
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
