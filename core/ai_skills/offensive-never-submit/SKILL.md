# SKILL: Never-Submit Validation

## Metadata
- **Skill Name**: never-submit
- **Folder**: offensive-never-submit
- **Source**: pentest-agents rules/never-submit.md

## Description
Instant-kill list of findings that are ALWAYS rejected without a working exploit chain. Also includes conditionally valid findings with the required escalation path. Use during validation to filter weak findings before drafting reports.

## Trigger Phrases
Use this skill when the conversation involves any of:
`never submit, instant kill, not a finding, informational, N/A, reject, auto-close, false positive, needs chain`

## Instructions for Claude

When this skill is active:
1. At the IDEA stage, check every finding against the Never-Submit list
2. If on the never-submit list, only continue if a concrete chain to real impact is buildable within 20 minutes
3. For conditionally valid findings, require the full escalation path before submitting

---

## Never-Submit List (instant kill without chain)

These findings are ALWAYS rejected unless accompanied by a working exploit chain:

- Missing headers (CSP/HSTS/X-Frame-Options)
- Missing SPF/DKIM/DMARC
- GraphQL introspection alone
- Banner/version disclosure without CVE exploit
- Clickjacking without sensitive action PoC
- Self-XSS
- Open redirect alone
- SSRF DNS-only
- CORS wildcard without credentialed exfil PoC
- Logout CSRF
- Rate limit on non-critical forms
- Session not invalidated on logout
- Concurrent sessions allowed
- Internal IP in error message
- Missing cookie flags alone
- OAuth client_secret in mobile app (expected)
- OAuth client_id alone (public by design)
- OIDC discovery endpoint (public by design)
- SPA client-side config (API URLs, Segment keys)
- Subdomain takeover claim on `*.azurewebsites.net` (Microsoft reserves deprovisioned hostnames)

## Conditionally Valid (chain required)

| You Have | Chain Needed | Combined Impact |
|---|---|---|
| Open redirect | + OAuth code theft → token exchange | ATO |
| SSRF DNS-only | + internal service data exfil | Data breach |
| CORS wildcard | + credentialed data theft PoC | Cross-origin data theft |
| GraphQL introspection | + auth bypass on mutations | Unauthorized actions |
| S3 listing | + secrets in bundles → OAuth chain | ATO |
| Prompt injection | + IDOR via chatbot (other user data) | Data breach |
| Subdomain takeover | + OAuth redirect_uri at that subdomain | ATO |
