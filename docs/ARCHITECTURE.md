# Architecture

A condensed map of the scanner's moving parts. Read this before touching
something cross-cutting (orchestration, AI, or external tools).

## 30-second mental model

```
       ┌─────────────────────────────────────────────────────────────┐
       │                       scanner.py / CLI                       │
       └─────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
       ┌─────────────────────────────────────────────────────────────┐
       │  core/scan_options + core/cli + core/scope                   │
       │  parsed options · scope filter · scan profile                │
       └─────────────────────────────────────────────────────────────┘
                                   │
                                   ▼
       ┌─────────────────────────────────────────────────────────────┐
       │   modules/<vuln_class>.py    — 80+ attack/recon modules     │
       │   utils/request, utils/concurrency, utils/payloads          │
       └────────────────┬─────────────────────────┬──────────────────┘
                        │                         │
                        ▼                         ▼
       ┌─────────────────────────────┐  ┌────────────────────────────┐
       │   utils/ai* (NVIDIA NIM)     │  │  utils/external_tools/     │
       │   ai_intent_agent            │  │  ExternalTool + 10         │
       │   agent_orchestrator         │  │  wrappers (masscan, …)     │
       │   PlannerStage + adaptive    │  │                            │
       │   loop, ExploitStage,        │  └────────────────────────────┘
       │   ValidateStage, ReportStage │
       │   utils/code_executor        │  ◀── sandboxed exploit runner
       │   utils/llm_budget           │      (subprocess + Docker)
       └─────────────────────────────┘
                        │
                        ▼
       ┌─────────────────────────────────────────────────────────────┐
       │   utils/finding + modules/report + utils/attack_mapping     │
       │   findings → MITRE ATT&CK tag → HTML/JSON report            │
       └─────────────────────────────────────────────────────────────┘
```

## Layers

### `core/`
Bootstrapping and configuration. Not where attack logic lives.

- `cli.py` — argparse wiring + interactive prompt
- `scan_options.py`, `scan_option_specs/` — typed scan configuration
- `scope.py` — `ScopeFilter` (URL allow/deny)
- `module_registry/` — declarative mapping flag → module function
- `documentation.py` — auto-generates README tables from the registry
- `ai_skills/` — `SKILL.md` knowledge base. `offensive-*/` are ours;
  `imported/hack-skills/` is the upstream MIT-licensed library
- `governance/apts/` — Autonomous Penetration Testing Standards docs

### `modules/`
The actual attack and recon code. One module per vulnerability class. See
[MODULES.md](MODULES.md) for the tier breakdown — 25 production, 55 beta.

Module shape:
```python
async def run(target_url: str, options: ScanOptions, context: ScanContext) -> list[Finding]:
    ...
```

### `utils/`
Cross-cutting infrastructure.

- **AI / orchestration**
  - `ai.py` — NVIDIA NIM client + the `_SKILL_MAP` skill loader
  - `ai_intent_agent.py` — LLM-writes-code-→-sandbox-→-self-heal loop
  - `agent_orchestrator.py` — `MissionContext`, stages, pipelines,
    `run_adaptive_mission` (LLM-driven Plan→Exploit loop)
  - `llm_budget.py` — call-count guard wrapped around the AI client
- **Exploit execution**
  - `code_executor.py` — subprocess sandbox (RLIMIT + restricted `__builtins__`)
  - `docker_executor.py` — Docker-based sandbox (preferred)
  - See [SECURITY_SANDBOX.md](SECURITY_SANDBOX.md) for the threat model
- **External tools**
  - `external_tools/base.py` — `ExternalTool` abstract adapter
  - `external_tools/<tool>.py` — masscan, arjun, sslyze, testssl, wpscan,
    smbmap, kube-hunter, gowitness, gitleaks, cloudhunter
- **Recon / network**
  - `recon_tools.py`, `request.py`, `async_request.py`, `concurrency.py`
- **Auth flows**
  - `auth_flows/`, `auth_cli.py`, `session_manager.py`
- **Findings & reporting**
  - `finding.py` (the `Observation` dataclass)
  - `attack_mapping.py` (MITRE ATT&CK tagger)

### `tests/`
pytest. ~1000 tests. Test files are named `test_<module>.py`. A coverage
guard (`test_skill_coverage.py`) fails if a new module lands without a
SKILL.md mapping.

## The two orchestration modes

### Fixed pipeline — `run_mission`
```
Recon → Exploit (seeded intents) → Validate → Report
```
Use this for deterministic, reproducible scans where you know exactly which
intents to attack up front.

### Adaptive LLM loop — `run_adaptive_mission`
```
Recon → [Plan → Exploit] × N → Validate → Report
```
The `PlannerStage` reads `MissionContext.tech_profile + findings` and proposes
the next batch of intents. The loop drains intents between rounds, dedupes via
`planned_signatures`, and exits early when no new in-scope intent is proposed.
Guards: `max_rounds`, `max_intents_per_round`, `max_llm_calls`, scope filter.

## How external tools fit in

Each `ExternalTool` subclass implements two methods (`get_command`,
`parse_output`) plus an optional `to_findings` for vuln-style mappings. The
base class handles availability checks (`shutil.which`), timeout enforcement,
and structured `ToolResult` construction. **A failing or missing tool never
raises** — it returns a diagnostic ToolResult so the rest of the mission
proceeds.

`ExternalToolStage` runs a list of these against the mission and merges
their `to_findings` into `ctx.findings`. `default_external_tools()` returns
the bundled adapter set.

## AI skill loader

`utils.ai._load_skill_for_vuln(vuln_type)` resolves a `vuln_type` (or module
name) to one of:
1. `core/ai_skills/offensive-<slug>/SKILL.md` (our content)
2. `core/ai_skills/imported/hack-skills/skills/<slug>/SKILL.md` (MIT, upstream)

The mapping is `_SKILL_MAP` in `utils/ai.py`. Coverage is enforced by
[test_skill_coverage.py](../tests/test_skill_coverage.py).

## File / directory cheat-sheet

```
scanner.py                  → CLI entry point
api_server.py               → REST API (FastAPI)
core/cli.py                 → argparse + interactive mode
core/scan_options.py        → ScanOptions dataclass
core/scope.py               → ScopeFilter
modules/*.py                → one attack per file
utils/ai*.py                → NVIDIA NIM + agent + intent loop
utils/external_tools/       → ExternalTool adapters
utils/code_executor.py      → subprocess sandbox
utils/docker_executor.py    → Docker sandbox
utils/agent_orchestrator.py → pipeline + adaptive loop
tests/test_<module>.py      → pytest suites
docs/MODULES.md             → tier classification
docs/SECURITY_SANDBOX.md    → sandbox threat model
```
