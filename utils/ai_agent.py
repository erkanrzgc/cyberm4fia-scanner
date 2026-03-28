"""
cyberm4fia-scanner — AI Agent Mode (Planner-Executor-Summarizer)

Inspired by HackSynth & PentestGPT architectures.
The AI drives the scan autonomously: plans the next attack,
executes the right module, summarizes results, and loops.

Usage:
    python3 scanner.py -u https://target.com --agent
"""

import time
import json
import signal
import sys
from typing import Optional
from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.ai import (
    OllamaClient, DualModelAI, get_ai, get_dual_ai,
    init_ai, init_dual_ai, _extract_json,
    SECURITY_SYSTEM_PROMPT, resolve_ollama_base,
)
from utils.request import ScanExceptions


# ─── Agent System Prompts ───────────────────────────────────────────────

PLANNER_SYSTEM = """You are an elite penetration tester AI agent controlling cyberm4fia-scanner.
You analyze reconnaissance data and scan results, then decide the NEXT best action.

Available modules you can invoke:
- recon: Network recon (ports, DNS, WHOIS, IP info)
- tech_detect: Technology fingerprinting (frameworks, servers, languages)
- header_audit: Security header analysis (CSP, HSTS, X-Frame, etc.)
- xss: Cross-Site Scripting scanner
- sqli: SQL Injection scanner
- lfi: Local File Inclusion scanner
- cmdi: Command Injection scanner
- ssrf: Server-Side Request Forgery scanner
- ssti: Server-Side Template Injection scanner
- xxe: XML External Entity scanner
- csrf: Cross-Site Request Forgery scanner
- cors: CORS misconfiguration scanner
- jwt: JWT token attack scanner
- open_redirect: Open Redirect scanner
- header_inject: HTTP Header Injection scanner
- dom_xss: DOM-based XSS scanner
- smuggling: HTTP Request Smuggling scanner
- deserialization: Insecure Deserialization scanner
- proto_pollution: Prototype Pollution scanner
- business_logic: Business logic flaw scanner
- race_condition: Race condition scanner
- forbidden_bypass: 403 Forbidden bypass scanner
- file_upload: File upload vulnerability scanner
- account_takeover: Account takeover scanner
- auth_bypass: Authentication bypass scanner
- csp_bypass: CSP bypass scanner
- cookie_hsts: Cookie & HSTS audit
- fuzzer: API endpoint discovery/fuzzing
- subdomain: Subdomain enumeration
- secrets: Secret/credential scanner
- cloud_enum: Cloud storage enumeration

Rules:
1. Always start with recon + tech_detect if no prior data exists
2. Choose modules based on discovered technology (e.g. PHP → LFI/RFI, Java → deserialization)
3. If WAF detected, prioritize WAF bypass techniques
4. Don't repeat a module that already ran unless you have new attack vectors
5. When you think scanning is complete, set "done": true

Respond ONLY with valid JSON:
{
    "reasoning": "Why I chose this action (1-2 sentences)",
    "modules": ["module1", "module2"],
    "priority": "critical|high|medium|low",
    "focus": "Optional: specific parameter or endpoint to focus on",
    "done": false
}"""

SUMMARIZER_SYSTEM = """You are a cybersecurity scan results analyst.
Given raw scan output, produce a concise tactical summary for the planner AI.

Include:
1. Key findings (vulns found, severity)
2. New attack surface discovered (endpoints, params, tech)
3. What failed or was blocked (WAF, rate limiting)
4. Recommended next steps

Keep it under 200 words. Be precise and technical."""


# ─── Agent Memory ───────────────────────────────────────────────────────

class AgentMemory:
    """Maintains context across agent iterations."""

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
        ctx_parts = [f"Target: {self.target}"]

        if self.tech_stack:
            techs = ", ".join(
                t.get("name", "?") for t in self.tech_stack[:10]
                if isinstance(t, dict)
            )
            ctx_parts.append(f"Tech Stack: {techs}")

        if self.waf_detected:
            ctx_parts.append(f"WAF: {self.waf_detected}")

        ctx_parts.append(f"Modules already run: {', '.join(sorted(self.modules_run)) or 'none'}")

        finding_count = len(self.all_findings)
        ctx_parts.append(f"Total findings so far: {finding_count}")

        # Add critical/high findings
        important = [
            f for f in self.all_findings
            if f.get("severity", "").lower() in ("critical", "high")
        ]
        if important:
            ctx_parts.append("Critical/High findings:")
            for f in important[:5]:
                ctx_parts.append(
                    f"  - {f.get('type', '?')}: {f.get('url', '?')} "
                    f"({f.get('severity', '?')})"
                )

        # Add last iteration summary
        if self.iterations:
            last = self.iterations[-1]
            ctx_parts.append(f"\nLast action summary:\n{last['summary']}")

        ctx = "\n".join(ctx_parts)
        return ctx[:max_chars]


# ─── Agent Components ───────────────────────────────────────────────────

class AgentPlanner:
    """Plans the next scan step using AI."""

    def __init__(self, client: OllamaClient):
        self.client = client

    def plan(self, memory: AgentMemory) -> dict:
        context = memory.get_context_window()
        prompt = f"""Current scan state:

{context}

Based on this data, what should I scan next? Choose the most effective modules.
If we have enough data and no more productive scans remain, set "done": true.

Respond with JSON only."""

        response = self.client.generate(
            prompt,
            system=PLANNER_SYSTEM,
            temperature=0.3,
            model_role="exploit",
        )

        result = _extract_json(response)
        if result and isinstance(result, dict):
            return result

        # Fallback: if AI response is broken, do a default plan
        if not memory.modules_run:
            return {
                "reasoning": "Starting with reconnaissance",
                "modules": ["recon", "tech_detect", "header_audit"],
                "priority": "high",
                "done": False,
            }

        return {"reasoning": "AI parse error, ending scan", "modules": [], "done": True}


class AgentExecutor:
    """Executes scanner modules based on agent plan."""

    # Module ID → (import_path, function_name, needs_forms)
    MODULE_MAP = {
        "recon": ("modules.recon", "run_recon", False),
        "tech_detect": ("modules.tech_detect", "scan_technology", False),
        "header_audit": ("modules.passive", "scan_passive", False),
        "xss": ("modules.xss", "scan_xss", True),
        "sqli": ("modules.sqli", "scan_sqli", True),
        "lfi": ("modules.lfi", "scan_lfi", True),
        "cmdi": ("modules.cmdi", "scan_cmdi", True),
        "ssrf": ("modules.ssrf", "scan_ssrf", True),
        "ssti": ("modules.ssti", "scan_ssti", False),
        "xxe": ("modules.xxe", "scan_xxe", False),
        "csrf": ("modules.csrf", "scan_csrf", True),
        "cors": ("modules.cors", "scan_cors", False),
        "jwt": ("modules.jwt_attack", "scan_jwt", False),
        "open_redirect": ("modules.open_redirect", "scan_open_redirect", False),
        "header_inject": ("modules.header_inject", "scan_header_inject", False),
        "dom_xss": ("modules.dom_xss", "scan_dom_xss", False),
        "smuggling": ("modules.smuggling", "scan_smuggling", False),
        "deserialization": ("modules.deserialization", "scan_deserialization", False),
        "proto_pollution": ("modules.proto_pollution", "scan_proto_pollution", False),
        "business_logic": ("modules.business_logic", "scan_business_logic", False),
        "race_condition": ("modules.race_condition", "scan_race_condition", False),
        "forbidden_bypass": ("modules.forbidden_bypass", "scan_forbidden_bypass", False),
        "file_upload": ("modules.file_upload", "scan_file_upload", False),
        "account_takeover": ("modules.account_takeover", "scan_account_takeover", False),
        "auth_bypass": ("modules.auth_bypass", "scan_auth_bypass", False),
        "csp_bypass": ("modules.csp_bypass", "scan_csp_bypass", False),
        "cookie_hsts": ("modules.cookie_hsts_audit", "scan_cookie_hsts", False),
        "subdomain": ("modules.subdomain", "scan_subdomains", False),
        "secrets": ("modules.secrets_scanner", "scan_secrets", False),
        "cloud_enum": ("modules.cloud_enum", "scan_cloud_storage", False),
    }

    def __init__(self, target: str, delay: float = 0):
        self.target = target
        self.delay = delay
        self._forms_cache = None

    def _get_forms(self) -> list:
        """Crawl and cache forms for modules that need them."""
        if self._forms_cache is not None:
            return self._forms_cache

        try:
            from modules.dynamic_crawler import run_dynamic_spider
            log_info("Agent: Crawling for forms...")
            pages = run_dynamic_spider(self.target, delay=self.delay)
            forms = []
            for page in (pages or []):
                forms.extend(page.get("forms", []))
            self._forms_cache = forms
            log_info(f"Agent: Found {len(forms)} forms across {len(pages or [])} pages")
        except Exception:
            self._forms_cache = []

        return self._forms_cache

    def execute(self, modules: list, memory: AgentMemory) -> dict:
        """Run the specified modules and return combined results."""
        results = {}

        for mod_id in modules:
            if mod_id not in self.MODULE_MAP:
                log_warning(f"Agent: Unknown module '{mod_id}', skipping")
                continue

            mod_path, func_name, needs_forms = self.MODULE_MAP[mod_id]
            memory.modules_run.add(mod_id)

            try:
                import importlib
                module = importlib.import_module(mod_path)
                func = getattr(module, func_name)

                log_info(f"Agent: Running {mod_id}...")
                start = time.time()

                # Build args based on module type
                if needs_forms:
                    forms = self._get_forms()
                    if mod_id in ("sqli", "lfi", "cmdi", "ssrf", "xss"):
                        result = func(self.target, forms, self.delay)
                    elif mod_id == "csrf":
                        result = func(self.target, forms, self.delay)
                    else:
                        result = func(self.target, forms, self.delay)
                elif mod_id == "recon":
                    result = func(self.target, deep=False)
                elif mod_id == "subdomain":
                    from urllib.parse import urlparse
                    domain = urlparse(self.target).hostname
                    result = func(domain)
                elif mod_id == "secrets":
                    import httpx
                    try:
                        resp = httpx.get(self.target, timeout=10, verify=False)
                        result = func(self.target, resp.text)
                    except Exception:
                        result = []
                else:
                    result = func(self.target)

                elapsed = time.time() - start

                # Normalize result
                if isinstance(result, dict):
                    results[mod_id] = result
                elif isinstance(result, list):
                    results[mod_id] = result
                    # Add findings to memory
                    findings = [
                        r for r in result
                        if isinstance(r, dict) and r.get("type")
                    ]
                    memory.add_findings(findings)
                else:
                    results[mod_id] = str(result) if result else "No results"

                # Extract special data for memory
                if mod_id == "tech_detect" and isinstance(result, list):
                    memory.tech_stack = result
                    # Check for WAF
                    for t in result:
                        if isinstance(t, dict) and t.get("type") == "waf":
                            memory.waf_detected = t.get("name", "Unknown WAF")

                if mod_id == "recon" and isinstance(result, dict):
                    memory.recon_data = result

                log_success(f"Agent: {mod_id} completed ({elapsed:.1f}s)")

            except Exception as e:
                log_error(f"Agent: {mod_id} failed: {e}")
                results[mod_id] = {"error": str(e)}

        return results


class AgentSummarizer:
    """Summarizes scan results for the planner."""

    def __init__(self, client: OllamaClient):
        self.client = client

    def summarize(self, results: dict, memory: AgentMemory) -> str:
        # Build a concise result summary
        result_text = []
        for mod_id, data in results.items():
            if isinstance(data, list):
                finding_count = len(data)
                severities = {}
                for d in data:
                    if isinstance(d, dict):
                        sev = d.get("severity", "info")
                        severities[sev] = severities.get(sev, 0) + 1
                sev_str = ", ".join(f"{k}: {v}" for k, v in severities.items())
                result_text.append(
                    f"- {mod_id}: {finding_count} findings ({sev_str or 'raw data'})"
                )
            elif isinstance(data, dict):
                if "error" in data:
                    result_text.append(f"- {mod_id}: ERROR - {data['error']}")
                else:
                    result_text.append(f"- {mod_id}: completed (dict result)")
            else:
                result_text.append(f"- {mod_id}: {str(data)[:100]}")

        prompt = f"""Summarize these scan results for target {memory.target}:

{chr(10).join(result_text)}

Total findings accumulated: {len(memory.all_findings)}
Modules run so far: {', '.join(sorted(memory.modules_run))}

Provide a tactical summary for the next planning step."""

        response = self.client.generate(
            prompt,
            system=SUMMARIZER_SYSTEM,
            temperature=0.2,
            model_role="analysis",
        )

        return response if response else "Summary generation failed."


# ─── Main Agent Loop ────────────────────────────────────────────────────

class AgentLoop:
    """Main agent orchestrator — Planner → Executor → Summarizer loop."""

    def __init__(
        self,
        target: str,
        max_iterations: int = 5,
        max_time: int = 600,
        delay: float = 0,
        base_url: str = None,
    ):
        self.target = target
        self.max_iterations = max_iterations
        self.max_time = max_time
        self.delay = delay
        self.interrupted = False

        # Initialize AI
        base = resolve_ollama_base(base_url)
        dual = init_dual_ai(base_url=base)
        if dual and dual.available:
            self.planner_client = dual.get_client_for_role("exploit") or get_ai(base)
            self.summarizer_client = dual.get_client_for_role("analysis") or get_ai(base)
        else:
            client = init_ai(base_url=base)
            self.planner_client = client
            self.summarizer_client = client

        self.planner = AgentPlanner(self.planner_client)
        self.executor = AgentExecutor(target, delay)
        self.summarizer = AgentSummarizer(self.summarizer_client)
        self.memory = AgentMemory(target)

        # Handle Ctrl+C gracefully
        signal.signal(signal.SIGINT, self._handle_interrupt)

    def _handle_interrupt(self, signum, frame):
        print(f"\n{Colors.YELLOW}⚠ Agent interrupted by user. Finishing...{Colors.END}")
        self.interrupted = True

    def run(self) -> dict:
        """Run the agent loop."""
        start_time = time.time()

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 55}")
        print(f"  🤖 AGENT MODE — AI-Driven Penetration Test")
        print(f"  Target: {self.target}")
        print(f"  Max iterations: {self.max_iterations}")
        print(f"{'═' * 55}{Colors.END}\n")

        if not self.planner_client.available:
            log_error("AI not available. Cannot run agent mode.")
            log_info("Make sure Ollama is running: ollama serve")
            log_info("Falling back to normal scan mode...")
            return {"error": "AI not available", "findings": []}

        for iteration in range(1, self.max_iterations + 1):
            # Check limits
            elapsed = time.time() - start_time
            if elapsed > self.max_time:
                log_warning(f"Agent: Time limit reached ({self.max_time}s)")
                break

            if self.interrupted:
                break

            print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'─' * 55}")
            print(f"  [Iteration {iteration}/{self.max_iterations}]")
            print(f"{'─' * 55}{Colors.END}")

            # 3-second interruptible pause
            print(f"{Colors.DIM}  Press Ctrl+C to stop after this iteration...{Colors.END}")
            try:
                time.sleep(2)
            except KeyboardInterrupt:
                self.interrupted = True
                break

            # ── PLAN ──
            print(f"\n  {Colors.CYAN}🧠 PLANNER:{Colors.END}", end=" ")
            plan = self.planner.plan(self.memory)

            reasoning = plan.get("reasoning", "No reasoning provided")
            modules = plan.get("modules", [])
            done = plan.get("done", False)
            priority = plan.get("priority", "medium")

            print(f"{reasoning}")
            if modules:
                print(f"  {Colors.BOLD}→ Modules: {', '.join(modules)} [{priority}]{Colors.END}")

            if done or not modules:
                log_success("Agent: AI determined scan is complete.")
                break

            # ── EXECUTE ──
            print(f"\n  {Colors.YELLOW}⚡ EXECUTOR:{Colors.END}")
            results = self.executor.execute(modules, self.memory)

            # ── SUMMARIZE ──
            print(f"\n  {Colors.GREEN}📝 SUMMARIZER:{Colors.END}", end=" ")
            summary = self.summarizer.summarize(results, self.memory)
            print(f"{summary[:300]}")

            # Store in memory
            self.memory.add_iteration(plan, results, summary)

        # ── Final Report ──
        total_time = time.time() - start_time
        total_findings = len(self.memory.all_findings)
        iterations_done = len(self.memory.iterations)

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'═' * 55}")
        print(f"  ✅ AGENT COMPLETE")
        print(f"  Iterations: {iterations_done}")
        print(f"  Total findings: {total_findings}")
        print(f"  Time: {total_time:.1f}s")
        print(f"  Modules used: {', '.join(sorted(self.memory.modules_run))}")
        print(f"{'═' * 55}{Colors.END}\n")

        return {
            "findings": self.memory.all_findings,
            "iterations": iterations_done,
            "modules_run": list(self.memory.modules_run),
            "time": total_time,
            "tech_stack": self.memory.tech_stack,
            "recon": self.memory.recon_data,
        }


# ─── Entry Point ────────────────────────────────────────────────────────

def run_agent_mode(
    target: str,
    max_iterations: int = 5,
    delay: float = 0,
    base_url: str = None,
) -> dict:
    """Run the AI agent mode scan."""
    agent = AgentLoop(
        target=target,
        max_iterations=max_iterations,
        delay=delay,
        base_url=base_url,
    )
    return agent.run()
