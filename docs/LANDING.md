---
title: scanner
description: AI-powered autonomous penetration testing — verifiable exploits, attack-chain reasoning, native SARIF/Burp/DefectDojo integration.
layout: default
---

<p align="center">
  <img src="https://img.shields.io/badge/AI--augmented-offensive-red?style=for-the-badge" alt="mission">
  <img src="https://img.shields.io/badge/verifiable-exploits-success?style=for-the-badge" alt="verified">
  <img src="https://img.shields.io/badge/python-3.11+-blue?style=for-the-badge&logo=python" alt="python">
  <img src="https://img.shields.io/badge/license-MIT-green?style=for-the-badge" alt="license">
</p>

<h1 align="center">scanner</h1>

<p align="center">
  <b>nuclei-fast scanning · Burp-deep verification · ChatGPT-grade reasoning · in one box.</b>
</p>

<p align="center">
  <a href="#quickstart"><img src="https://img.shields.io/badge/▶_quick_start-60_seconds-blue?style=for-the-badge"></a>
  &nbsp;
  <a href="https://github.com/erkanrzgc/autonomous-scanner"><img src="https://img.shields.io/badge/⭐_star_on-GitHub-181717?style=for-the-badge&logo=github"></a>
  &nbsp;
  <a href="../docs/INTEGRATIONS.md"><img src="https://img.shields.io/badge/🔌_integrations-SARIF·Burp·DefectDojo-blueviolet?style=for-the-badge"></a>
</p>

---

## The 30-second pitch

You already know what's wrong with most web scanners:

* **Template scanners** (nuclei, ZAP) find things, but you still have to read the response by hand to know if it's real.
* **Manual pentesting tools** (Burp Pro) verify properly, but you're driving every click.
* **Commercial scanners** (Acunetix, Netsparker) verify automatically, but they're a black box and your finding feeds aren't yours.
* **GenAI security tools** generate words about findings, not actual exploits, and they hallucinate freely.

**scanner sits in the gap.** It scans at template speed, verifies at browser-level depth (Playwright + heuristic gates + simhash false-positive filtering), reasons through 93 offensive/defensive methodologies the LLM consults per finding, and exports to every tool you already use.

---

## What makes it different

### 1. Verifiable exploits, not just "header missing"

Every `Missing_Security_Header` finding goes through an **active verifier** that re-checks the live target before the report ships:

```
Missing X-Frame-Options found
  → ClickjackingVerifier.verify()
    → re-fetch headers (no XFO + no CSP frame-ancestors)
    → optional Playwright iframe render assertion
    → promote to Clickjacking_Exploitable (CVSS 5.4) + sibling promotion of CSP
```

Five verifiers ship today: **Clickjacking, HSTS, MIME-Confusion, Referrer-Leak, Permissions-Policy**.

### 2. Attack chain reasoning

Findings don't sit in isolation. Deterministic + AI-discovered patterns elevate them:

```
Missing CSP  +  XSS_Param          → Stored XSS Exfil           (HIGH)
Missing HSTS +  Insecure_Cookie    → SSL Strip Session Hijack   (HIGH)
Missing XCT  +  File_Upload        → MIME-Confusion XSS         (HIGH)
Insecure_Cookie + XSS_Param        → Cookie Theft Chain         (CRITICAL)
SSRF + 169.254 hit                 → Cloud Metadata + IAM cred  (CRITICAL)
LFI + log poisoning                → RCE                         (CRITICAL)
```

### 3. Content-fingerprint FP filter

The most common false positive in modern scanners: SPA / catch-all routes that return HTTP 200 + the homepage template for any unknown URL. scanner computes a **64-bit simhash + DOM-skeleton hash + title hash** of every response and drops content-dependent findings whose response matches the calibrated homepage baseline.

Real result from a public Turkish e-commerce target: **38 findings → 19 dropped as SPA fallbacks → 19 real**. Without the filter, every scanner reports "phantom" admin panels and `.env` exposures that don't exist.

### 4. 93 AI-loaded methodologies

`core/ai_skills/` ships a SKILL.md per attack technique — the AI consults the right one per finding type, not generic prompts:

```
core/ai_skills/
  offensive-clickjacking/          ← 5 PoC shapes, frame-buster bypass
  offensive-hsts-downgrade/        ← sslstrip2, bettercap, preload analysis
  offensive-mime-confusion/        ← polyglot construction, CORB bypass
  offensive-referrer-policy-leak/  ← OAuth/reset/share-link historical cases
  offensive-csrf/                  ← SameSite bypass, JSON CSRF
  offensive-sqli/                  ← UNION + blind + 2nd-order
  ...88 more
  defensive-false-positive-filter/ ← decision tree for triage
```

Every skill is an actual playbook with code, not a prompt template.

### 5. Pipeline integration that doesn't fight your tools

| Tool | Format | Import in seconds |
|---|---|---|
| GitHub Code Scanning | SARIF | `upload-sarif@v3` step already shipped in `.github/workflows/security-scan.yml` |
| Burp Suite Pro | Burp Issues XML | *Project → Import issues → `issues.burp.xml`* |
| DefectDojo | SARIF / Burp XML | `POST /api/v2/import-scan/` |
| Jenkins (warnings-ng) | SARIF | `recordIssues(tools: [sarif(...)])` |
| GitLab Ultimate SAST | SARIF | `artifacts.reports.sast` |

### 6. CI-grade exit codes

```bash
$ python3 scanner.py -u https://my-app/ --sarif
$ echo $?
1                           # CRITICAL findings present
```

Codes: `0` clean, `1` critical, `2` high, `3` medium, `4` low/info, `10` internal error. Tune the gate per repo via `SCAN_EXIT_THRESHOLD`.

### 7. Resume from anywhere

Scans crash or get killed. The session JSON now tracks **per-phase completion** + **per-URL completion** + **mid-pipeline finding snapshots**, so:

```bash
$ python3 scanner.py -u https://target/ --all --session scan1.json
^C                           # interrupt mid-AI-analysis
$ python3 scanner.py --resume scan1.json
[resume] Skipping completed phase: pre_scan
[resume] Skipping completed phase: discovery_seed
[resume] Skipping completed phase: scan_urls
[resume] Skipping completed phase: post_scan
[*] Continuing from: analysis
```

No re-running 30 minutes of recon to retry the AI step.

---

<a id="quickstart"></a>
## 60-second quickstart

```bash
git clone https://github.com/erkanrzgc/autonomous-scanner.git
cd scanner
pip install -r requirements.txt

# Full passive + active scan (no AI required)
python3 scanner.py -u https://your-target.example/ --all

# Add AI-driven analysis (optional, needs NVIDIA NIM API key)
export NVIDIA_API_KEY=nvapi-...
python3 scanner.py -u https://your-target.example/ --all --ai

# CI-friendly with all integrations
python3 scanner.py -u https://your-target.example/ --xss --sqli --tech --sarif --json
case $? in
  1) echo "🛑 CRITICAL — block deploy" && exit 1;;
  2) echo "🔴 HIGH — require security review";;
  *) echo "✅ clean or advisory only";;
esac
```

Reports land under `scans/<target>/`:

* `report.html` – styled human-readable
* `report.md` – Markdown summary
* `findings.json` – enhanced JSON with CVSS / CWE / verification state
* `results.sarif` – SARIF 2.1.0
* `issues.burp.xml` – Burp Issues XML
* `pocs/*.html` – self-contained exploit PoC files (clickjacking iframe, CSP XSS, HSTS strip scenario, CSRF auto-submit form, cookie theft, etc.)

---

## Built for authorized testing

scanner ships a **sandboxed exploit runner** (Docker / firejail / WSL fallback), **scope enforcement** (`--scope`, `--exclude`, `--path-blacklist`), **request budget caps**, **WAF auto-calibration** (delay scaling on block), and **per-target session isolation**. The intent is clear: pentests with explicit engagement scope, CTFs, security research, and defensive testing of your own infrastructure.

> **It is not** a "point at any URL" tool. Operators are responsible for authorization. The codebase refuses destructive operations by default, but a scanner is a force multiplier — make sure you're aiming it where you're allowed to.

---

## Where it came from

scanner started as a personal lab project and evolved into a methodology-driven scanner over several iterations. Recent sprints have added:

* **Sprint N (verifiers+ci+exports)** — 5 active verifiers, Burp XML, CI exit codes, GitHub Code Scanning SARIF upload, auth-session audit, integrations docs.
* **Sprint N-1 (fp+headers)** — SPA-fallback simhash filter, `Missing_Security_Header → *_Exploitable` chain promotion, 5 new offensive/defensive skills, 4 new chain patterns.
* **Sprint N-2 (hardening)** — phase-boundary checkpoints, real-binary integration suite for 10 external tools, AI budget enforcement.

Current state: **90+ modules · 93 AI skill methodologies · 1250+ tests passing · 5 active verifiers · 6 report formats · 5 CI/CD integrations.**

---

## Get involved

* **Star the repo** → [github.com/erkanrzgc/autonomous-scanner](https://github.com/erkanrzgc/autonomous-scanner)
* **Read [`docs/INTEGRATIONS.md`](INTEGRATIONS.md)** for the full Burp / SARIF / DefectDojo / Jenkins / GitLab cookbook.
* **Open issues** for bugs, false positives, missing modules, integration requests.
* **Pull requests welcome** — see [`CONTRIBUTING.md`](../CONTRIBUTING.md).

---

<p align="center">
  <sub>Built for authorized offensive security testing.<br>
  © 2026 · MIT License · NVIDIA NIM (default model: <code>meta/llama-3.3-70b-instruct</code>)</sub>
</p>
