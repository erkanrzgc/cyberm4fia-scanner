# Known Tech Debt — files >800 LOC after cleanup

After the 2026-05-06/07 cleanup pass and follow-up splits, the largest
technical-debt files were converted into façade-preserving packages:

| Old file | LOC | New package | Largest sub-file |
|---|---|---|---|
| `utils/finding.py` | 1169 | `utils/finding/` | `normalization.py` 476 |
| `core/module_runners.py` | 1374 | `core/module_runners/` | `postprocess.py` 382 |
| `core/scan_option_specs.py` | 1057 | `core/scan_option_specs/` | `arguments.py` 382 |
| `core/module_registry.py` | 988 | `core/module_registry/` | `phase_modules.py` 714 |
| `modules/sqli_exploit.py` | 1056 | `modules/sqli_exploit/` | `error_based.py` 563 |
| `utils/ai_exploit_agent.py` | 1024 | `utils/ai_exploit_agent/` | `agent.py` 465 |
| `utils/agent_framework.py` | 1019 | `utils/agent_framework/` | `orchestrator.py` 378 |
| `modules/smart_payload.py` | 942 | `modules/smart_payload/` | `_xss_payloads.py` 487 |
| `utils/exploit_finder.py` | 820 | `utils/exploit_finder/` | `backends.py` 383 |

App-code inventory excludes vendored / imported skill content under
`core/ai_skills/` and governance reference material under
`core/governance/`. **No first-party app-code Python file remains over
the 800-LOC budget.**

## Inventory

_None._

## Why façade packages

Every split preserves the original public-import surface via the new
`__init__.py`. Concretely, before and after:

```python
from utils.finding import Finding, normalize_vuln   # still works
from core.module_runners import _run_recon, _run_xss_postprocess  # still works
from modules.sqli_exploit import run_sqli_exploit  # still works
```

The façade pattern was proven first on the lowest-risk target
(`utils/finding.py`) and then applied uniformly to the rest of the
>800-LOC band.

## Cleanup Pass Outcome

- 9 files in the >800-LOC band were split into façade packages.
- 0 first-party app-code files remain over 800 LOC.
- No file went over 800 LOC as a *result* of this cleanup.
- Smoke verification (compileall + targeted pytest) passed after each
  split commit.
