---
name: offensive-subdomain-takeover
description: "Subdomain takeover testing — claiming dangling DNS records pointing to deprovisioned third-party services (S3, GitHub Pages, Heroku, Azure, etc.). Covers CNAME/A dangling detection, fingerprinting service error pages, and safe claim verification. Use after subdomain enumeration to find hijackable hosts."
---

# Subdomain Takeover — Offensive Testing Methodology

## Quick Workflow

1. Enumerate subdomains and resolve their DNS records (CNAME/A/NS)
2. Find records pointing to third-party services
3. Check whether the target resource is unclaimed (fingerprint error page)
4. Claim it on the provider to prove takeover (in scope only)

---

## Detection

### Dangling CNAME

```
sub.target.com  CNAME  target.s3.amazonaws.com   → bucket does not exist
sub.target.com  CNAME  target.github.io          → no GitHub Pages site
```

Resolve the CNAME, then visit the host. A provider "not found / no such bucket /
no site here" page on a CNAME you don't control = takeover candidate.

### Provider Fingerprints

| Service | Takeover signal |
|---|---|
| AWS S3 | `NoSuchBucket` |
| GitHub Pages | `There isn't a GitHub Pages site here` |
| Heroku | `No such app` / default Heroku 404 |
| Azure | `404 Web Site not found` (azurewebsites/cloudapp) |
| Fastly | `Fastly error: unknown domain` |
| Shopify/Tumblr/Zendesk | service-specific "domain not configured" pages |
| Unbound NS records | delegation to a takeable zone |

---

## Verification

1. Confirm the CNAME/A target is unregistered on the provider
2. Register/claim the exact resource name on that provider
3. Host a benign proof file (e.g. `/<random>.txt`) and fetch it via the subdomain
4. Document — do not host malicious content

Edge cases: `NXDOMAIN` vs claimable, wildcard DNS masking, multiple CNAME hops,
NS-record (full zone) takeover which is highest impact.

---

## Impact

- Serve content/phishing from a trusted subdomain
- Steal cookies scoped to `*.target.com`; bypass CORS/SSO origin trust
- Capture OAuth redirects / receive emails (MX takeover)

---

## Remediation

- Remove DNS records before deprovisioning the backing resource
- Continuously monitor for dangling CNAME/NS records
- Use provider domain-verification (claim tokens) and avoid wildcard CNAMEs
