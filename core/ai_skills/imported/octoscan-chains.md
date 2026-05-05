# Source — OctoScan tool-chain methodology

- **Upstream:** https://github.com/Coucoudb/OctoScan
- **Source file:** `src/profiles.rs`
- **Imported on:** 2026-05-04
- **Note:** OctoScan is a Rust orchestrator wrapping 9 external tools —
  the binary is not portable into our Python stack, but its **tool-chain
  composition** is concrete methodology worth recording.

## Built-in profiles

| Profile | Description | Tool chain |
|---|---|---|
| `quick` | Fast port scan only | Nmap |
| `web` | Web application audit | Nmap → Nuclei → Feroxbuster → ZAP |
| `recon` | Reconnaissance | Subfinder → httpx → Nmap |
| `full` | All scanners | Nmap → Nuclei → ZAP → Feroxbuster → SQLMap → Subfinder → httpx → WPScan → Hydra |

## How to use in cyberm4fia-scanner

Validates and extends our `core/scan_option_specs.py::PROFILE_PRESETS`.
Specifically:

- Our **Profile #1 "Fast Recon"** corresponds roughly to OctoScan's
  `recon` chain. Worth confirming we run subdomain discovery → http probe
  → port scan in that order.
- Our **Profile #4 ALL_ENABLED_OPTION_KEYS** corresponds to OctoScan's
  `full`. The OctoScan order (port scan first, then web fuzz, then
  bruteforce last) is the canonical noisy-but-thorough order.
- We have no direct equivalent of OctoScan's `web` profile (port + nuclei
  + dirfuzz + ZAP-style passive). Consider adding a focused web profile.

OctoScan's source-of-truth for tool registration is `src/scanners/`
(one Rust module per scanner) — useful as a reference list when deciding
which third-party CLIs we may want to wrap next.
