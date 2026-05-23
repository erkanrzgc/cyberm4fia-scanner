# Contributing

Thanks for considering a contribution. This file covers dev setup, the
expected workflow, and the bar for landing a change.

For the project's structure, read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
first — it'll tell you which layer your change belongs in.

## Dev setup

```bash
git clone https://github.com/erkanrzgc/cyberm4fia-scanner.git
cd cyberm4fia-scanner
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt        # if present; otherwise: pip install pytest pytest-cov

# Run the full test suite (under 4 minutes on a modern laptop):
python3 -m pytest -q
```

If your environment has `HTTP(S)_PROXY=socks5h://...` set, `tests/conftest.py`
strips it before tests run — no action needed.

For AI features, set `NVIDIA_API_KEY` (an NVIDIA NIM build key). Without it
the AI agent stages skip cleanly and tests using a fake client still pass.

## Workflow

The repo follows a **test-first** workflow. The shape of every PR:

1. **Plan, then test (RED).** Write a failing test for the behavior you want.
   For new files: add tests under `tests/test_<feature>.py`.
2. **Implement (GREEN).** Smallest change to make the test pass.
3. **Run the relevant suite + the coverage guards.**
   ```bash
   python3 -m pytest tests/test_<your_file>.py -q
   python3 -m pytest tests/test_skill_coverage.py -q   # if you added a module
   ```
4. **Open a focused PR.** Title format: `<type>: <short description>`
   where `<type>` is one of `feat`, `fix`, `refactor`, `docs`, `test`,
   `chore`, `perf`, `ci`.

A passing suite is required to merge. CI runs `pytest` and a security
linter (see `.github/workflows/`).

## What changes need

### Adding a new attack module
1. `modules/<my_module>.py` with the canonical entry point.
2. `tests/test_<my_module>.py` (production-tier requires this).
3. Register in `core/module_registry/`.
4. **Skill mapping.** Either reuse an existing skill or add a new
   `core/ai_skills/offensive-<slug>/SKILL.md`. Add the keyword(s) to
   `_SKILL_MAP` in `utils/ai.py`. The coverage guard test will fail
   otherwise.
5. Run `python3 -c "from core.documentation import sync_generated_docs; sync_generated_docs()"`
   to refresh the auto-generated tables in README.

### Adding a new external-tool wrapper
1. `utils/external_tools/<tool>.py` subclassing `ExternalTool`. Implement
   `get_command`, `parse_output`, and (if it surfaces vulns) `to_findings`.
2. Tests in `tests/test_external_tools_wrappers.py`.
3. Export from `utils/external_tools/__init__.py`.
4. If it makes sense in the default rotation, append to
   `utils/agent_orchestrator.default_external_tools()`.

### Touching the sandbox
Read [docs/SECURITY_SANDBOX.md](docs/SECURITY_SANDBOX.md) before changing
anything in `utils/code_executor.py` or `utils/docker_executor.py`. Each
hardening (or relaxation) must come with a regression test.

### Touching the orchestrator
`utils/agent_orchestrator.py` has both the fixed pipeline (`run_mission`)
and the adaptive loop (`run_adaptive_mission`). Changes must preserve:
- backwards-compat for `run_mission` (it's an external entry point used by
  the MCP server)
- the `MissionContext.planned_signatures` dedup invariant (no infinite loop)
- scope, budget, and round caps

## Coding standards

- Python 3.11+. Type-annotate public functions.
- Match the surrounding file's style; do not introduce a new formatter.
- Keep functions under ~50 lines; files under ~800. Extract helpers
  instead of growing.
- Explicit error handling — no silent `except:` swallowers, no `pass` on
  errors unless documented.
- No hardcoded credentials anywhere, not even in tests.

## Commit messages

```
<type>: <subject in imperative mood, ~70 chars>

<optional body>
```

Body explains *why*, not *what* (the diff shows what). Reference issues
with `#<num>`. Attribution is configured globally; please do not add
"Co-authored-by" lines.

## Reviewing your own PR

Before requesting review:
- [ ] All new code has tests; tests were RED before they were GREEN
- [ ] `pytest -q` is fully green locally (or notes which suites are
      environment-dependent)
- [ ] No new dependency unless justified in the PR body
- [ ] User-visible CLI/API/config changes documented (README or
      `docs/`)

## License

By contributing you agree that your changes ship under the project's
license (`LICENSE`).
