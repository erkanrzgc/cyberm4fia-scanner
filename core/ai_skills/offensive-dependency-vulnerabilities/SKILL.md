---
name: offensive-dependency-vulnerabilities
description: "Software composition analysis and known-vulnerability (CVE) testing for third-party dependencies. Covers identifying component versions, matching against vuln databases (OSV/NVD/GHSA), exploitability triage (reachability, public exploit), and dependency-confusion. Use when assessing lockfiles, SBOMs, or fingerprinted library versions."
---

# Dependency Vulnerabilities (SCA) — Offensive Testing Methodology

## Quick Workflow

1. Inventory dependencies + exact versions (lockfiles, headers, JS bundles, SBOM)
2. Match versions against OSV / NVD / GHSA advisories
3. Triage exploitability: is the vulnerable code path reachable? public exploit?
4. Prioritize by severity × reachability × exposure

---

## Identifying Components & Versions

- Lockfiles: `package-lock.json`, `yarn.lock`, `requirements.txt`, `pom.xml`, `Gemfile.lock`, `go.sum`
- Runtime fingerprints: `Server`/`X-Powered-By` headers, JS lib version comments, `/VERSION`
- Client bundles: library banners, sourcemaps
- Container images: OS packages + app deps per layer

---

## Matching Against Advisories

- **OSV** (osv.dev) — multi-ecosystem, machine-readable ranges
- **NVD** — CVE + CVSS
- **GHSA** — GitHub Security Advisories, often with fix versions

Match ecosystem + package + version against affected ranges. Record CVE, CVSS,
fixed version, and whether a public PoC/exploit exists.

---

## Exploitability Triage

A matched CVE is not automatically exploitable. Assess:

- **Reachability** — is the vulnerable function actually called by the app?
- **Preconditions** — config/feature flags, auth, specific input path
- **Exposure** — internet-facing vs internal
- **Public exploit / Metasploit module / nuclei template** availability
- Known-exploited (CISA KEV) → escalate priority

High-value examples: Log4Shell (log4j-core 2.x), Spring4Shell, deserialization
gadgets in vulnerable libs, prototype-pollution in JS deps.

---

## Dependency Confusion

If internal package names leak, publish a higher-version malicious package to a
public registry; misconfigured resolvers may pull the public one (build-time RCE).
Test for: internal scopes referenced in public bundles, missing registry scoping.

---

## Remediation

- Upgrade to fixed versions; pin and lock dependencies
- Continuous SCA in CI (osv-scanner, etc.) with severity gates
- Scope private registries; reserve internal names publicly to block confusion
- Generate and monitor an SBOM; track KEV advisories
