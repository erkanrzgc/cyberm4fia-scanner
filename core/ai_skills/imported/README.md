# Imported AI Skill Libraries & Methodology References

This directory contains AI agent prompts, skills, methodology references,
and pattern databases imported from external open-source projects. They
**complement** the native `core/ai_skills/offensive-*` and
`osint-methodology/` skills — they do not replace them.

Each subdirectory has its own `SOURCE.md` documenting the upstream URL,
import date, files included, why it was imported, and license note.

## Imported sources

### AI agent libraries

| Subdir | Upstream | Files | What |
|---|---|---:|---|
| [`bug-bounty-agents/`](./bug-bounty-agents/) | [matty69v/Bug-Bounty-Agents](https://github.com/matty69v/Bug-Bounty-Agents) | 45 | 43+ agent prompts for the full bug-bounty lifecycle |
| [`pentest-agents/`](./pentest-agents/) | [H-mmer/pentest-agents](https://github.com/H-mmer/pentest-agents) | 61 | 48 specialized agents + 8 methodology rules + docs |
| [`claude-osint/`](./claude-osint/) | [elementalsouls/Claude-OSINT](https://github.com/elementalsouls/Claude-OSINT) | 15 | Paired Claude skills: tactical arsenal + strategic methodology |
| [`cyberstrike-ai/`](./cyberstrike-ai/) | [Ed1s0nZ/CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) | 37 | 15+ agent prompts + role YAML configs (Chinese/English) |

### Vulnerability checklists & pattern databases

| Subdir | Upstream | Files | What |
|---|---|---:|---|
| [`vulnerability-checklist/`](./vulnerability-checklist/) | [Az0x7/vulnerability-Checklist](https://github.com/Az0x7/vulnerability-Checklist) | 27 | Manual testing checklists for 27 bug classes |
| [`vice/`](./vice/) | [Webba-Creative-Technologies/vice](https://github.com/Webba-Creative-Technologies/vice) | 12 | Secret-pattern DB + 10 white-box audit modules (git-history scan, code-vulnerability AST, Supabase RLS audit, …) — **reference for new scanner capabilities** |
| [`hack-skills/`](./hack-skills/) | [yaklang/hack-skills](https://github.com/yaklang/hack-skills) | 30 | **Selective import** — 30 of 101 SKILL.md files relevant to web/API/auth/cloud/AI scope (web-cache-deception, websocket, http2, container escape, k8s, SAML/OAuth, JNDI/EL/XSLT, prompt-injection, …). AD/Pwn/mobile/crypto-attacks intentionally skipped. |

### Scan-engine profiles & methodology

| Subdir | Upstream | Files | What |
|---|---|---:|---|
| [`rengine-profiles/`](./rengine-profiles/) | [yogeshojha/rengine](https://github.com/yogeshojha/rengine) | 4 | 6 pre-tuned scan-engine YAMLs + keyword library + external-tools registry |
| [`octoscan-chains.md`](./octoscan-chains.md) | [Coucoudb/OctoScan](https://github.com/Coucoudb/OctoScan) | 1 | 4 built-in tool-chain profiles (quick / web / recon / full) |

### Capability-gap design references

| Subdir | Upstream | Files | What |
|---|---|---:|---|
| [`reverse-api-engineer/`](./reverse-api-engineer/) | [kalil0321/reverse-api-engineer](https://github.com/kalil0321/reverse-api-engineer) | 13 | LLM-driven live-browser API capture + auto-generated typed clients — design ref for evolving `utils/har_analyzer.py` |

**Total imported:** 245 files across 10 source projects.

## Considered but **not imported** (with reasons)

Honest record of repos that were evaluated and rejected:

| Project | Reason for rejection |
|---|---|
| [Ed1s0nZ/CyberStrikeAI](https://github.com/Ed1s0nZ/CyberStrikeAI) (binary) | Go binary — not portable into our Python stack. **Markdown content WAS imported** under [`cyberstrike-ai/`](./cyberstrike-ai/) |
| [yogeshojha/rengine](https://github.com/yogeshojha/rengine) (full framework) | The full Django+Celery framework duplicates our scanner architecture. **YAML scan profiles WERE imported** under [`rengine-profiles/`](./rengine-profiles/) |
| [Coucoudb/OctoScan](https://github.com/Coucoudb/OctoScan) (full framework) | Rust orchestrator wrapping 9 external tools — duplicates our orchestrator. **Tool-chain methodology WAS imported** as [`octoscan-chains.md`](./octoscan-chains.md) |
| [hahwul/dalfox](https://github.com/hahwul/dalfox) | Dedicated XSS scanner; our `modules/xss.py` + `dom_xss.py` + `dom_xss exploit` already cover reflected/stored/DOM XSS with custom payload pipeline. Marginal incremental value vs. integration cost. |
| [webxos/phalanx](https://github.com/webxos/phalanx) | "Polyglot Harness" = Python core that calls external tools. This is **structurally identical** to our `utils/agent_orchestrator.py` + `utils/meta_tools.py` + `utils/docker_executor.py` stack. Pure overlap, no novel pattern. |
| [P0cL4bs/flexphish](https://github.com/P0cL4bs/flexphish) | Offensive phishing campaign framework (lure pages, email templates, victim tracking). Our scanner is a **defensive vulnerability scanner**; phishing payloads do not feed any defensive module. `qishing.py` and `brand_protection.py` already cover the defensive phishing-detection angle. |
| [yogsec/Hacking-Tools](https://github.com/yogsec/Hacking-Tools) | Curated link list of existing tools — no original code or methodology to import. |
| [D4Vinci/Scrapling](https://github.com/D4Vinci/Scrapling) | High-quality stealth scraping library. **Recommended as a runtime dependency for `dynamic_crawler.py`** when stealth is needed (not imported here — should be `pip install scrapling` when wired in). |
| [pikpikcu/airecon](https://github.com/pikpikcu/airecon) | Already integrated via `scripts/setup_airecon_dataset.sh` (dataset only — the agent itself overlaps with our `utils/ai_intent_agent.py`). |
| [OWASP/Nettacker](https://github.com/OWASP/Nettacker) | Alternative scanner architecture. Its **drift-detection** idea is already implemented in our `utils/scan_history.py::DriftReport`. |
| [OWASP/APTS](https://github.com/OWASP/APTS) | Already implemented under `core/governance/apts/` (8 pillars scaffolded). |
| [Argh94/Proxy-List](https://github.com/Argh94/Proxy-List) | Wired in as fallback inside `utils/proxy_rotator.py` (no markdown to import). |
| [proxifly/free-proxy-list](https://github.com/proxifly/free-proxy-list) | Already the primary source in `utils/proxy_rotator.py`. |
| [kalil0321/reverse-api-engineer](https://github.com/kalil0321/reverse-api-engineer) (full runtime) | Full runtime requires Chrome native messaging + Claude Agent SDK. **Design references and prompts WERE imported** under [`reverse-api-engineer/`](./reverse-api-engineer/) for porting work. |
| [kleiton0x00/Advanced-SQL-Injection-Cheatsheet](https://github.com/kleiton0x00/Advanced-SQL-Injection-Cheatsheet) | Markdown payload cheatsheet — `payloads/sqli.txt` is already 399 lines and 8 categories. Manual diff/dedupe required before merging. Deferred. |

## Integration pattern

The scanner's autonomous agents (`utils/ai_intent_agent.py`,
`utils/ai_exploit_agent.py`, `utils/agent_orchestrator.py`) can load any
of these files as supplementary context (system prompt, methodology
reference, per-finding triage guide) when reasoning about a target or
delegating a subtask to the LLM.

The `vice/` and `reverse-api-engineer/` imports are **design references
for new modules not yet built** — see their respective `SOURCE.md` for
the ranked porting plan.

## Re-importing / updating

To refresh an import to a newer upstream commit:

```bash
TMP=/tmp/skill_imports
mkdir -p "$TMP" && cd "$TMP"
git clone --depth=1 <upstream-url> <reponame>
# then re-run the copy logic and update the import date in SOURCE.md
```

Always preserve attribution in `SOURCE.md`.
