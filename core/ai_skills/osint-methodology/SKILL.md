---
name: osint-methodology
description: "OSINT methodology for external red-team operations and attack-surface assessments. 5-stage recon pipeline, 29 asset types, severity rubric, confidence levels, identity-fabric mapping, breach correlation, and detection-aware probing."
version: 2.1
triggers:
  - external recon
  - attack surface management
  - perimeter recon
  - asset discovery
  - identity fabric
  - SSO discovery
  - IdP fingerprinting
  - M365 enumeration
  - breach correlation
  - OSINT methodology
  - target profiling
  - recon methodology
---

# OSINT Methodology — External Red-Team Edition

> This is the "how to think" skill. Companion skill `offensive-osint` is the "what to reach for."

## When to Use

Use when planning or executing external reconnaissance against an authorized target, mapping an external attack surface, investigating entities, or performing attribution work.

## Authorization & Legal Posture

For assets the operator owns or has written authorization to assess. Soft scope check before acting against unverified third-party assets.

## Confidence Levels

| Level | Meaning |
|---|---|
| **TENTATIVE** | Plausible based on indirect evidence; unverified |
| **FIRM** | Directly observed but uncorroborated |
| **CONFIRMED** | Multiple independent corroborations OR direct verification |

Rule of three for attribution: require three independent weak signals, OR one strong + one weak, before asserting linkage.

## Output Format Conventions

```
Finding:
  id:           <stable hash or UUID>
  module:       <technique name>
  asset_key:    <typed key>
  category:     <SECRET_LEAK, MISSING_HSTS, etc>
  severity:     <info|low|medium|high|critical>
  confidence:   <tentative|firm|confirmed>
  title:        <one-line summary>
  description:  <2-5 sentences>
  evidence:     url + UTC timestamp + sha256 + raw (≤2 KiB)
  references:   []
  remediation:  <action>
```

## Source Hygiene

For every artifact: URL + UTC timestamp + SHA-256 hash + tool version + run_id. PNG screenshots, JSONL run logs, raw HTTP captures capped at 2 KiB.

## 5-Stage Recon Pipeline

### Stage 1 — Seed Discovery
- WHOIS on seed domain
- ASN enumeration
- DNS records (A/AAAA/MX/TXT/NS/SOA/CAA)
- Certificate Transparency (crt.sh, Censys)

### Stage 2 — Asset Expansion
- Subdomain enumeration (passive + active)
- Cloud bucket enumeration
- Typosquat domain generation
- Wayback CDX archive endpoints
- Mobile app discovery
- LinkedIn employee enumeration

### Stage 3 — Enrichment
- Port + service detection
- Live TLS handshakes
- Web tech detection
- WAF/CDN inference
- Email harvesting + security audit
- GitHub code-search dorking
- JavaScript deep analysis
- SSO/IdP tenant fingerprinting
- API & auth-map discovery
- Vendor product fingerprinting
- Container / CI-CD exposure

### Stage 4 — Exposure Analysis
- Targeted misconfiguration probes
- TLS deep audit
- Breach × identity correlation
- Vulnerability prioritization (CVE × EPSS × KEV)

### Stage 5 — Reporting
- Risk scoring + asset graph export
- Client-facing report
- Reproduction package

## Identity Fabric Mapping

Probe SSO prefixes (auth, login, sso, idp, iam, identity, accounts, oauth) against root domain plus `/.well-known/openid-configuration` on every alive subdomain.

### Microsoft Entra (Azure AD)
- OIDC metadata: `https://login.microsoftonline.com/{domain}/.well-known/openid-configuration`
- getuserrealm.srf for managed vs federated
- Autodiscover v2 for tenant membership

### Okta
- Org slug derivation from subdomains + root domain stem
- OIDC fingerprint: `https://<slug>.okta.com/.well-known/openid-configuration`

### ADFS
- `https://{domain}/adfs/idpinitiatedsignon.aspx`

### Google Workspace
- MX records pointing to `aspmx.l.google.com`

## Breach × Identity Correlation

When breach corpus intersects with discovered SSO tenant → SSO_EXPOSURE finding.
≥10 employees compromised → CRITICAL.

## Hard Rules

- Never paste creds/PII/session tokens into cloud LLMs.
- Never run destructive probes outside DEEP/`--aggressive`.
- Never use validated credentials for anything except read-only liveness check.
- Never single-source attribute.
- Don't assume vendor labels are ground truth.
