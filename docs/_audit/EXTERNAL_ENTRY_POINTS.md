# External Entry Points — Dormant Agent Harness

Six files in `utils/` form the Cairn-inspired autonomous-agent harness
that **landed on 2026-05-01** (per project memory). They are
**intentionally not wired into `scanner.py` / `api_server.py`** — they
are invoked by an *external* MCP / Cairn runner, exposed as MCP tools,
or imported by the orchestrator stages.

This document is the source of truth for: which file does what, how it
gets invoked from outside, and which test exercises it. If any of
these files ever shows up unused in a future `vulture` / orphan scan,
read this document first before deleting.

## File map

| File | Role | Invoked by | Test |
|---|---|---|---|
| `utils/mcp_server.py` | MCP Tool Surface — exposes scanner capabilities as MCP tools (`ToolSpec` + `dispatch()` + `serve_stdio()`). | External MCP runner (Claude Desktop, Cursor, custom Claude Agent SDK). | `tests/test_mcp_server.py` |
| `utils/agent_orchestrator.py` | Pipeline of `Stage` objects (Recon → Exploit → Validate → Report) sharing a `MissionContext`. | `utils.mcp_server` (`build_default_pipeline` is reachable as an MCP tool); also direct external import. | `tests/test_agent_orchestrator.py` |
| `utils/ai_intent_agent.py` | Intent-driven loop: LLM writes a Python exploit script, sandbox runs it, traceback feeds back for self-healing. | `utils.agent_orchestrator` (`ExploitStage`), `utils.mcp_server` (`exploit_intent` tool). | `tests/test_ai_intent_agent.py`, `tests/test_meta_tools.py` |
| `utils/meta_tools.py` | Subprocess wrappers + parsers for `nmap` / `sqlmap` / `nuclei` so the AI layer gets structured data. | `utils.agent_orchestrator` (`ReconStage`), `utils.mcp_server` (`run_nmap` etc.). | `tests/test_meta_tools.py` |
| `utils/code_executor.py` | Subprocess sandbox: import whitelist + CPU/memory/wallclock caps. | `utils.ai_intent_agent` (default sandbox), `utils.docker_executor` (fallback path). | `tests/test_code_executor.py` |
| `utils/docker_executor.py` | Docker-container sandbox: stronger isolation, same `ExecutionResult` contract as subprocess sandbox. | `utils.ai_intent_agent` when `EXEC_BACKEND=docker`. | `tests/test_docker_executor.py` |

## How they connect

```
        ┌──────────────────────────────┐
        │ External MCP runner          │
        │ (Claude Desktop / Cursor /   │
        │  custom Agent SDK script)    │
        └──────────────┬───────────────┘
                       │ stdio MCP protocol
                       ▼
        ┌──────────────────────────────┐
        │ utils.mcp_server             │
        │   serve_stdio() + dispatch() │
        └──┬──────────┬──────────┬─────┘
           │          │          │
           ▼          ▼          ▼
   agent_orch    ai_intent_   meta_tools
   estrator     agent        (nmap / sqlmap /
                                nuclei wrappers)
        │
        ▼
   ai_intent_agent
        │
        ▼  picks sandbox backend
   ┌────┴────┐
   │         │
   ▼         ▼
 code_     docker_
 executor  executor
```

## Why we keep them (Option B, conservative)

The cleanup pass evaluated three options:

- **A**: Wire into `scanner.py` as `--agent-mode`. Costs README +
  flag wiring + extra integration tests. Out of scope for cleanup.
- **B**: Mark as external entry point + document. **Chosen.** No
  behavior change; future contributors won't accidentally delete them.
- **C**: Remove. Conflicts with the explicit project-memory note that
  the Cairn stack "landed" on 2026-05-01.

## Banner on each file

Each of the six files carries a `.. external-entry-point::` directive
at the top of its module docstring pointing back to this file. That
banner is the single signal a reviewer (or `vulture --confidence`) sees
when wondering "is this dead?".

## How to actually run the harness

```bash
# 1. Install the optional MCP SDK
pip install mcp

# 2. Launch the scanner MCP server over stdio
python -m utils.mcp_server

# 3. From an external Claude Agent SDK / Claude Desktop config,
#    point at the above command as an MCP server.
```

For ad-hoc testing without an MCP client:

```python
from utils.mcp_server import dispatch
result = dispatch("scan_target", {"url": "https://example.com"})
print(result)
```

## Risk: silent breakage

The biggest risk with a dormant subsystem is that nobody notices when
it stops working. Mitigations already in place:

1. The 6 files have **65+ unit tests** across
   `tests/test_mcp_server.py`, `tests/test_meta_tools.py`,
   `tests/test_code_executor.py`, `tests/test_docker_executor.py`,
   `tests/test_ai_intent_agent.py`, `tests/test_agent_orchestrator.py`.
2. Those tests run as part of the standard `pytest tests/` invocation
   — no separate suite, no opt-in flag.
3. `_check_connection` mocking convention (Faz 9 / 10) means they
   don't hit live NVIDIA NIM during CI.
