# Source — reNgine scan profiles

- **Upstream:** https://github.com/yogeshojha/rengine
- **Imported on:** 2026-05-04
- **Files imported:** 4 YAML fixtures (scan engines, keywords, external
  tools, default config)

## Why this was imported

The reNgine framework itself overlaps with our scanner architecture, but
its **6 pre-tuned scan-engine YAML profiles** encode years of bug-bounty
methodology and are directly readable as planning input:

1. **Full Scan** — all phases (subdomain → port scan → OSINT → fuzz → fetch
   URLs → vuln scan → screenshot)
2. **Subdomain Scan** — multi-tool subdomain discovery chain
3. **OSINT** — emails, metainfo, employees + 13 dork categories
4. **Vulnerability Scan** — nuclei + dalfox + crlfuzz, all severities
5. **Port Scan** — top-100 ports, naabu/nmap config knobs
6. **reNgine Recommended** — the maintainer's curated profile

`default_keywords.yaml` is a curated dork keyword library; `external_tools`
documents the upstream tool integrations.

## How to use in cyberm4fia-scanner

Reference for tuning our `core/scan_option_specs.py` profile presets.
Specifically:

- The `gf_patterns` list (`debug_logic, idor, interestingEXT, …`) is a
  great input wordlist for our `param_discovery.py` and `endpoint_fuzzer.py`
- The `dorks` taxonomy (login_pages, admin_panels, dashboard_pages, …) can
  feed `modules/google_dorker.py`
- The phase ordering (subdomain → port → OSINT → fuzz → vuln) validates
  our existing pipeline order

## License

See upstream repository for license terms.
