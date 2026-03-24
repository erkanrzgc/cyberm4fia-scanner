"""
Tests for core/module_registry.py
"""

import os

from core.module_registry import (
    canonicalize_scan_url,
    canonicalize_scan_urls,
    iter_async_module_specs,
    iter_phase_module_specs,
    run_phase_modules,
)

class TestModuleRegistry:
    def test_canonicalize_scan_url_strips_fragments_and_noise_params(self):
        assert (
            canonicalize_scan_url(
                "https://example.com/login?_rsc=abc123&from=%2Fdash#hero"
            )
            == "https://example.com/login?from=%2Fdash"
        )

    def test_canonicalize_scan_urls_deduplicates_nextjs_variants(self):
        urls = canonicalize_scan_urls(
            [
                "https://example.com/login?_rsc=abc123",
                "https://example.com/login?_rsc=def456",
                "https://example.com/login#top",
                "https://example.com/login?from=%2Fdash",
            ]
        )

        assert urls == [
            "https://example.com/login",
            "https://example.com/login?from=%2Fdash",
        ]

    def test_async_registry_filters_and_preserves_order(self):
        specs = list(
            iter_async_module_specs(
                {
                    "xss": True,
                    "xxe": True,
                    "dom_xss": True,
                    "templates": True,
                    "sqli": False,
                }
            )
        )

        assert [spec.id for spec in specs] == ["xss", "xxe", "dom_xss", "templates"]
        assert specs[0].phase == "page_scan"
        assert specs[0].requires_forms is True
        assert specs[0].build_args("http://t", ["form"], 0.5) == (
            "http://t",
            ["form"],
            0.5,
        )
        assert specs[1].build_args("http://t", ["form"], 0.5) == ("http://t", 0.5)
        assert specs[2].build_args("http://t", ["form"], 0.5) == ("http://t",)

    def test_target_phase_registry_collects_results(self, monkeypatch, tmp_path):
        import modules.api_scanner as api_mod
        import modules.cloud_enum as cloud_mod
        import modules.cors as cors_mod
        import modules.header_inject as header_mod
        import modules.recon as recon_mod
        import modules.subdomain_takeover as takeover_mod

        calls = []

        monkeypatch.setattr(
            cloud_mod,
            "scan_cloud_storage",
            lambda url, delay=0: [{"type": "Cloud", "url": url, "delay": delay}],
        )
        monkeypatch.setattr(
            takeover_mod,
            "scan_subdomain_takeover",
            lambda url, delay=0: [{"type": "Takeover", "url": url}],
        )
        monkeypatch.setattr(
            api_mod,
            "scan_api",
            lambda url, delay=0, spec_path=None: [{"type": "API", "spec": spec_path}],
        )
        monkeypatch.setattr(
            recon_mod,
            "scan_subdomains",
            lambda host: calls.append(("subdomain", host)),
        )
        monkeypatch.setattr(
            cors_mod,
            "scan_cors",
            lambda url: [{"type": "CORS", "url": url}],
        )
        monkeypatch.setattr(
            header_mod,
            "scan_header_inject",
            lambda url, delay=0: [{"type": "Header", "delay": delay}],
        )

        state = {
            "url": "http://example.com",
            "delay": 0.4,
            "options": {"api_spec": str(tmp_path / "openapi.yaml")},
            "target_host": "example.com",
            "scan_dir": str(tmp_path),
            "crawled_forms": [],
            "urls_to_scan": ["http://example.com"],
            "recon_data": {},
            "all_vulns": [],
        }

        phase4 = run_phase_modules(
            "phase4_target",
            {"cloud": True, "takeover": True, "api_scan": True, "subdomain": True},
            state,
        )
        checks = run_phase_modules(
            "target_checks",
            {"cors": True, "header_inject": True},
            state,
        )

        assert [item["type"] for item in phase4] == ["Cloud", "Takeover", "API"]
        assert [item["type"] for item in checks] == ["CORS", "Header"]
        assert calls == [("subdomain", "example.com")]

    def test_pre_scan_phase_populates_recon_and_tech_state(self, monkeypatch):
        import modules.recon as recon_mod
        import modules.tech_detect as tech_mod
        import utils.cve_feed as cve_mod
        import utils.shodan_lookup as osint_mod

        monkeypatch.setattr(
            recon_mod,
            "run_recon",
            lambda url, deep=False: {"url": url, "deep": deep, "open_ports": [80]},
        )
        monkeypatch.setattr(
            osint_mod,
            "scan_osint",
            lambda url, shodan_api_key=None, delay=0: {"domain": url, "delay": delay},
        )
        monkeypatch.setattr(
            tech_mod,
            "scan_technology",
            lambda url, delay=0: [{"name": "nginx", "url": url}],
        )
        monkeypatch.setattr(
            cve_mod,
            "enrich_with_cves",
            lambda tech_results: [{"type": "CVE_Intel", "count": len(tech_results)}],
        )

        state = {
            "url": "http://example.com",
            "delay": 0.4,
            "options": {"recon": True, "osint": True, "tech": True},
            "recon_data": None,
            "all_vulns": [],
        }

        findings = run_phase_modules("pre_scan", state["options"], state)

        assert findings == [{"type": "CVE_Intel", "count": 1}]
        assert state["recon_data"]["deep"] is True
        assert state["osint_data"]["delay"] == 0.4
        assert state["tech_results"] == [{"name": "nginx", "url": "http://example.com"}]
        assert state["cve_intel"] == [{"type": "CVE_Intel", "count": 1}]

    def test_discovery_phases_mutate_scan_state(self, monkeypatch):
        import modules.crawler as crawler_mod
        import modules.dynamic_crawler as dynamic_mod
        import modules.endpoint_fuzzer as fuzzer_mod

        calls = {"crawl": 0}

        monkeypatch.setattr(
            fuzzer_mod,
            "scan_fuzzer_async",
            lambda url, wordlist_file, threads=0, delay=0: [
                {"url": "http://example.com/api", "status": 200},
                {"url": "http://example.com/old", "status": 404},
            ],
        )
        monkeypatch.setattr(
            dynamic_mod,
            "run_dynamic_spider",
            lambda url, delay=0: {
                "links": [
                    "http://example.com/app#hero",
                    "http://example.com/app?_rsc=1",
                ],
                "forms": [{"action": "/submit"}],
                "endpoints": [
                    ("GET", "http://example.com/data"),
                    ("GET", "http://example.com/data?_rsc=2"),
                    ("POST", "http://example.com/write"),
                ],
            },
        )
        monkeypatch.setattr(
            crawler_mod,
            "crawl_site",
            lambda url, max_pages=30: calls.__setitem__("crawl", calls["crawl"] + 1),
        )

        state = {
            "url": "http://example.com",
            "delay": 0.2,
            "options": {"threads": 20, "headless": True},
            "wordlist_file": "wordlists/api_endpoints.txt",
            "urls_to_scan": ["http://example.com"],
            "crawled_forms": [],
            "all_vulns": [],
        }

        run_phase_modules("discovery_seed", {"fuzz": True}, state)
        run_phase_modules("discovery_expand", {"headless": True, "crawl": True}, state)

        assert "http://example.com/api" in state["urls_to_scan"]
        assert "http://example.com/app" in state["urls_to_scan"]
        assert "http://example.com/data" in state["urls_to_scan"]
        assert "http://example.com/app#hero" not in state["urls_to_scan"]
        assert "http://example.com/data?_rsc=2" not in state["urls_to_scan"]
        assert "http://example.com/write" not in state["urls_to_scan"]
        assert state["crawled_forms"] == [{"action": "/submit"}]
        assert calls["crawl"] == 0

    def test_page_hooks_respect_form_requirements(self, monkeypatch):
        import modules.csrf as csrf_mod
        import modules.passive as passive_mod
        import modules.secrets_scanner as secrets_mod
        import modules.csp_bypass as csp_mod
        import modules.cookie_hsts_audit as cookie_mod
        import core.module_runners as runners

        runners._csp_checked_hosts.clear()
        runners._hsts_checked_hosts.clear()

        monkeypatch.setattr(
            passive_mod,
            "scan_passive",
            lambda scan_url, response=None: [{"type": "Passive", "url": scan_url}],
        )
        monkeypatch.setattr(
            csrf_mod,
            "scan_csrf",
            lambda scan_url, forms, delay=0: [{"type": "CSRF", "forms": len(forms)}],
        )
        monkeypatch.setattr(
            secrets_mod,
            "scan_secrets",
            lambda scan_url, response_text: [
                {"type": "Secret_Exposure", "url": scan_url, "body": response_text}
            ],
        )
        monkeypatch.setattr(
            csp_mod,
            "scan_csp_bypass",
            lambda scan_url, response=None: [{"type": "CSP_Bypass", "url": scan_url}],
        )
        monkeypatch.setattr(
            cookie_mod,
            "scan_cookie_hsts",
            lambda scan_url, response=None: [
                {"type": "Insecure_Cookie", "url": scan_url}
            ],
        )

        class FakeResponse:
            text = "const apiKey = 'secret';"

        state = {
            "scan_url": "http://example.com",
            "response": FakeResponse(),
            "forms": [{"id": "login"}],
            "delay": 0.3,
            "all_vulns": [],
        }

        findings = run_phase_modules(
            "page_hooks",
            {"passive": True, "secrets": True, "csrf": True},
            state,
        )
        assert [item["type"] for item in findings] == [
            "Passive",
            "Secret_Exposure",
            "CSRF",
            "CSP_Bypass",
            "Insecure_Cookie",
        ]

        state["forms"] = []
        runners._csp_checked_hosts.clear()
        runners._hsts_checked_hosts.clear()
        findings = run_phase_modules(
            "page_hooks",
            {"passive": True, "secrets": True, "csrf": True},
            state,
        )
        assert [item["type"] for item in findings] == [
            "Passive",
            "Secret_Exposure",
            "CSP_Bypass",
            "Insecure_Cookie",
        ]

    def test_post_scan_registry_runs_side_effect_and_result_modules(
        self, monkeypatch, tmp_path
    ):
        import modules.email_harvest as email_mod
        import modules.jwt_attack as jwt_mod
        import modules.open_redirect as redirect_mod
        import utils.vuln_chain as chain_mod
        import utils.wordlist_gen as wordlist_mod

        calls = {"email": [], "wordlist": [], "chain": []}

        monkeypatch.setattr(
            redirect_mod,
            "scan_open_redirect",
            lambda scan_url, delay=0: [{"type": "Redirect", "url": scan_url}],
        )
        monkeypatch.setattr(
            jwt_mod,
            "scan_jwt",
            lambda url, delay=0, cookie=None: [{"type": "JWT", "cookie": cookie}],
        )
        monkeypatch.setattr(
            email_mod,
            "scan_email_harvest",
            lambda url, delay=0: calls["email"].append((url, delay)),
        )
        monkeypatch.setattr(
            wordlist_mod,
            "generate_wordlist",
            lambda url, depth, output_file, delay=0: calls["wordlist"].append(
                (url, depth, output_file, delay)
            ),
        )
        monkeypatch.setattr(
            chain_mod,
            "analyze_chains",
            lambda vulns: calls["chain"].append(list(vulns)),
        )

        state = {
            "url": "http://example.com",
            "delay": 0.7,
            "options": {"cookie": "sid=1"},
            "target_host": "example.com",
            "scan_dir": str(tmp_path),
            "crawled_forms": [],
            "urls_to_scan": ["http://example.com/a", "http://example.com/b"],
            "recon_data": {},
            "all_vulns": [{"type": "Baseline"}],
        }

        results = run_phase_modules(
            "post_scan",
            {
                "redirect": True,
                "jwt": True,
                "email": True,
                "wordlist": True,
                "chain": True,
            },
            state,
        )

        assert [item["type"] for item in results] == ["Redirect", "Redirect", "JWT"]
        assert calls["email"] == [("http://example.com", 0.7)]
        assert calls["wordlist"] == [
            (
                "http://example.com",
                2,
                os.path.join(str(tmp_path), "wordlist.txt"),
                0.7,
            )
        ]
        assert [item["type"] for item in calls["chain"][0]] == [
            "Baseline",
            "Redirect",
            "Redirect",
            "JWT",
        ]

    def test_analysis_and_reporting_phases_use_shared_state(
        self, monkeypatch, tmp_path
    ):
        import modules.poc_generator as poc_mod
        import modules.report as report_mod
        import utils.ai as ai_mod
        import utils.finding as finding_mod
        import core.output as output_mod

        class FakeAI:
            available = True

        rendered = []
        monkeypatch.setattr(ai_mod, "get_ai", lambda: FakeAI())
        monkeypatch.setattr(
            ai_mod,
            "detect_false_positives",
            lambda ai, vulns: vulns[:1],
        )
        monkeypatch.setattr(
            ai_mod,
            "analyze_vulnerability",
            lambda ai, vuln: "analysis",
        )
        monkeypatch.setattr(
            ai_mod,
            "generate_remediation",
            lambda ai, vulns: [{"type": "fix", "count": len(vulns)}],
        )
        monkeypatch.setattr(
            ai_mod,
            "generate_scan_summary",
            lambda ai, vulns, url, stats: f"summary:{len(vulns)}:{stats['vulns']}",
        )
        monkeypatch.setattr(
            report_mod,
            "generate_html_report",
            lambda *args, **kwargs: rendered.append("html"),
        )
        monkeypatch.setattr(
            report_mod,
            "generate_payload_report",
            lambda *args: rendered.append("payload"),
        )
        monkeypatch.setattr(
            report_mod,
            "generate_markdown_report",
            lambda *args, **kwargs: rendered.append("markdown"),
        )
        monkeypatch.setattr(
            report_mod,
            "generate_json_report",
            lambda *args: rendered.append("json"),
        )
        monkeypatch.setattr(
            output_mod,
            "save_sarif",
            lambda *args: rendered.append("sarif"),
        )
        monkeypatch.setattr(
            output_mod,
            "save_findings_json",
            lambda *args: rendered.append("findings_json"),
        )
        monkeypatch.setattr(
            output_mod,
            "print_severity_summary",
            lambda *args: rendered.append("severity"),
        )
        monkeypatch.setattr(
            finding_mod,
            "normalize_all",
            lambda vulns: ["norm" for _ in vulns],
        )
        monkeypatch.setattr(
            poc_mod,
            "generate_pocs",
            lambda *args: rendered.append("pocs"),
        )

        state = {
            "url": "http://example.com",
            "mode": "normal",
            "scan_dir": str(tmp_path),
            "recon_data": {"open_ports": []},
            "all_vulns": [
                {"type": "XSS_Param", "url": "http://example.com"},
                {"type": "Noise", "url": "http://example.com"},
            ],
            "options": {"ai": True, "html": True, "sarif": True, "json_output": True},
            "summary_printer": lambda findings, recon_data=None, stats=None: (
                rendered.append(f"summary:{len(findings)}")
            ),
            "report_stats_factory": lambda count: {"vulns": count},
            "summary_stats_factory": lambda count: {
                "total_requests": 10,
                "waf_blocks": 1,
                "errors": 0,
                "retries": 2,
                "duration_seconds": 3.5,
            },
        }

        run_phase_modules("analysis", {"ai": True}, state)
        run_phase_modules("reporting", {"html": True, "sarif": True}, state)

        assert len(state["all_vulns"]) == 1
        assert state["all_vulns"][0]["ai_analysis"] == "analysis"
        assert state["ai_summary"] == "summary:1:1"
        assert state["ai_remediations"] == [{"type": "fix", "count": 1}]
        assert state["finding_count"] == 1
        assert rendered == [
            "summary:1",
            "html",
            "payload",
            "markdown",
            "pocs",
            "json",
            "sarif",
            "findings_json",
            "severity",
        ]

    def test_result_processors_handle_prompts_and_side_effects(self, monkeypatch):
        import modules.cmdi_shell as cmdi_shell_mod
        import modules.sqli as sqli_mod
        import modules.sqli_exploit as sqli_exploit_mod
        import modules.xss_exploit as xss_exploit_mod

        calls = {
            "xss": 0,
            "xss_interactive": 0,
            "sqli_exploit": [],
            "cmdi_shell": 0,
        }

        monkeypatch.setattr(
            xss_exploit_mod,
            "run_xss_exploit",
            lambda vulns, suppress_output=True: calls.__setitem__("xss", len(vulns)),
        )
        monkeypatch.setattr(
            xss_exploit_mod,
            "run_xss_exploit_interactive",
            lambda vulns: calls.__setitem__("xss_interactive", len(vulns)),
        )
        monkeypatch.setattr(
            sqli_exploit_mod,
            "run_sqli_exploit",
            lambda vuln: (
                calls["sqli_exploit"].append(vuln["type"]) or {"database": "app"}
            ),
        )
        monkeypatch.setattr(
            sqli_mod,
            "scan_blind_sqli",
            lambda scan_url, forms, delay=0: [{"type": "SQLi_Blind", "url": scan_url}],
        )

        class DummyShell:
            def __init__(self, url, vuln_data):
                self.url = url
                self.vuln_data = vuln_data

            def run(self):
                calls["cmdi_shell"] += 1

        monkeypatch.setattr(cmdi_shell_mod, "InteractiveShell", DummyShell)

        answers = iter(["3", "1"])
        state = {
            "scan_url": "http://example.com",
            "forms": [{"id": "login"}],
            "delay": 0.4,
            "options": {"exploit": True},
            "xss_vulns": [{"type": "XSS_Param", "url": "http://example.com"}],
            "sqli_vulns": [{"type": "SQLi_Union", "url": "http://example.com"}],
            "cmdi_vulns": [{"type": "CMDi_Form", "url": "http://example.com"}],
            "prompt_input": lambda prompt, default="": next(answers),
            "all_vulns": [],
        }

        results = run_phase_modules(
            "result_processors",
            {"xss": True, "sqli": True, "cmdi": True, "exploit": True},
            state,
        )

        assert calls["xss"] == 1
        assert calls["xss_interactive"] == 0
        assert calls["cmdi_shell"] == 1
        assert calls["sqli_exploit"] == ["SQLi_Union"]
        assert results == []

    def test_phase_registry_filters_by_phase(self):
        specs = list(
            iter_phase_module_specs(
                "post_scan",
                {"redirect": True, "cors": True, "jwt": True},
            )
        )

        assert [spec.id for spec in specs] == ["redirect", "jwt"]
