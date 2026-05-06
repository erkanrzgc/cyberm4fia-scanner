# Known Tech Debt — files >800 LOC after cleanup

After the 2026-05-06 cleanup pass, the largest file in the repo went from
1169 LOC (`utils/finding.py`) to 476 LOC (`utils/finding/normalization.py`)
via package split.

The remaining files over the 800-LOC budget are **intentionally not split
in this cleanup pass** — splitting them carries refactoring risk that the
cleanup mandate explicitly excluded ("davranış değişikliği yok"). They
are recorded here so a future, scoped refactor can target them.

## Inventory

| File | LOC | Why kept whole | Future split hint |
|---|---|---|---|
| `core/module_runners.py` | 1374 | Each `_run_*` is a thin adapter for one phase module. Splitting would scatter the registry-runner pairing across many tiny files and hurt navigation. | Group by phase (pre_scan / discovery / scan / post_scan / reporting) into a `runners/` package. |
| `core/scan_option_specs.py` | 1057 | Pure declarative spec table — reads top-to-bottom. Splitting reduces grep-ability. | Only split if argparse parsing logic is added; data-only files don't need to be small. |
| `core/module_registry.py` | 988 | Single `PhaseModuleSpec` tuple table that every other file searches. Splitting destroys the "one place to see all modules" property. | Keep whole. Treat as configuration. |
| `modules/sqli_exploit.py` | 1056 | Two distinct exploit classes (`SQLiExploit` ~550 LOC, `BlindSQLiExploit` ~360 LOC). Could split cleanly but the public entry point `run_sqli_exploit` couples them. | Move each class to its own file under `modules/sqli_exploit/`, keep `run_sqli_exploit` in `__init__.py`. |
| `utils/ai_exploit_agent.py` | 1024 | `AIExploitAgent` class itself is ~700 LOC; the class IS the unit of cohesion. Mechanical line-count split would just hide it across files. | Extract prompt-builder helpers and response-parser helpers as separate modules; leave the agent class intact. |
| `utils/agent_framework.py` | 1019 | `AgentOrchestrator` ~370 LOC + `AgentMemory` ~210 LOC + `DepthTracker` ~110 LOC + dispatcher functions. Per project memory, the agent harness is "frozen" (Cairn-inspired stack landed 2026-05-01). | Once the harness stabilises long-term, extract `memory.py`, `depth.py`, `dispatcher.py`. |
| `modules/smart_payload.py` | 942 | Function-heavy file (15+ small mutation/context helpers + one large `probe_xss_context`). Splittable but currently navigated as one integrated payload-engine. | `smart_payload/contexts.py` + `smart_payload/mutators.py` + `smart_payload/probes.py`. |
| `utils/exploit_finder.py` | 820 | Single coherent CVE-search engine with multiple back-end adapters inline. | Extract adapters (`exploit_db`, `nuclei`, `metasploit`) to a `backends/` subpackage. |

## Why Pilot-Only

The cleanup mandate prioritised:

1. Deleting genuinely dead code (Faz 2)
2. Replacing pretend-features with honest behaviour (Faz 4)
3. Proving a low-risk split pattern on the highest-value target (Faz 6 — `utils/finding.py`)

Splitting all eight remaining files would have:

- Multiplied refactor risk by ~8× (every package façade is a chance to
  miss a re-export and break a caller).
- Added zero behaviour change while the project mandate explicitly says
  "davranış değişikliği yok".
- Burned hours on mechanical work that adds package complexity without
  improving call-site readability for files that are *internally* well
  structured.

The `utils/finding/` split proves the pattern works (façade `__init__.py`
preserves all imports) so a future targeted refactor can apply it
file-by-file when the per-file pressure is justified.

## Cleanup Pass Outcome

- 1 file in the >800-LOC band was split (largest, most cohesion).
- 7 files remain >800 LOC, all documented above with split hints.
- No file went over 800 LOC as a *result* of this cleanup.
