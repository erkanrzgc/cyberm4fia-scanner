# Cleanup Baseline — 2026-05-06

Branch: `cleanup/codebase-tidy-2026-05-06`
Base: `main` @ `98ef9d9`

## Test Suite (pre-cleanup state)

- **Total collected:** 684
- **Known pre-existing failures (1):**
  - `tests/test_module_registry.py::TestModuleRegistry::test_pre_scan_phase_populates_recon_and_tech_state`
    - Expected `[{type: CVE_Intel, count: 1}]`; got additional `idp_discovery` finding from `osint_identity`.
    - Cause: test does not monkeypatch `modules.osint_identity.scan_identity_fabric`, which is now wired into `pre_scan` phase.
    - Action: fix in Faz 4 (silent-failure / stub cleanup) — extend monkeypatch list.

## Slow Tests (real HTTP — must be mocked, ~190s wall total)

| Test | Duration | Smell |
|---|---|---|
| `test_ssrf.py::TestScanSSRF::test_no_vuln_returns_empty` | 70.4s | real DNS/HTTP probe |
| `test_ssti.py::TestScanSSTI::test_no_vuln_returns_empty` | 44.2s | real HTTP |
| `test_ssti.py::TestScanSSTI::test_ignores_expected_value_in_baseline` | 33.6s | real HTTP |
| `test_ssti.py::TestScanSSTI::test_waf_block_tracked` | 31.7s | real HTTP |
| `test_vuln_checklist.py` | 12s | likely real HTTP |
| `test_xxe.py::TestScanXXE::test_no_vuln_returns_empty` | 5.75s | real HTTP |
| `test_scan_options.py::*::test_cli_builder_preserves_explicit_values_without_all` | HANG offline | sets `proxy_url`, which triggers `utils/proxy_rotator.py` real CDN fetch via `enable_proxy_rotation` |

Action: tracked but DEFERRED. Cleanup project does not modify these tests' production logic; mocking them is a separate "test-quality" task.

## Standard Deselect List (for cleanup-phase regression runs)

Use these exact deselects to keep regression runs <240s:

```
--deselect tests/test_module_registry.py::TestModuleRegistry::test_pre_scan_phase_populates_recon_and_tech_state
--deselect "tests/test_ssrf.py::TestScanSSRF::test_no_vuln_returns_empty"
--deselect "tests/test_ssti.py::TestScanSSTI::test_no_vuln_returns_empty"
--deselect "tests/test_ssti.py::TestScanSSTI::test_ignores_expected_value_in_baseline"
--deselect "tests/test_ssti.py::TestScanSSTI::test_waf_block_tracked"
--deselect "tests/test_xxe.py::TestScanXXE::test_no_vuln_returns_empty"
--deselect "tests/test_scan_options.py::TestScanOptions::test_cli_builder_preserves_explicit_values_without_all"
```

## Codebase Snapshot (pre-cleanup)

| Metric | Value |
|---|---|
| Python files (excl. venv, vendored) | 226 |
| Total LOC | ~66,340 |
| modules/ files | 79 |
| utils/ files | 48 |
| core/ files | 13 |
| tests/ files | 65 |
| Files >800 LOC | 5 |
| Heuristic unused imports | 102 |
| Stub/empty functions | 11 |
| Suspect duplicate pairs | 13 |
| Orphan modules (zero imports) | 3 |

## Cleanup-Pass Criteria

For each phase commit:
1. Test count must remain ≥683 passing (the 1 pre-existing failure is OWNED in Faz 4).
2. `python -c "import scanner; import api_server"` succeeds.
3. `ruff check .` does not introduce NEW errors.

