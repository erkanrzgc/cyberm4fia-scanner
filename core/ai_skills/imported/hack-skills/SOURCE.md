# hack-skills (yaklang) — Selective Import

**Upstream:** https://github.com/yaklang/hack-skills
**Commit imported:** `8b8e5678` (2026-05-01)
**Imported on:** 2026-05-05
**Files copied:** 30 skill directories (out of 101 upstream)

## What this is

`yaklang/hack-skills` is a 101-skill agent knowledge base across 14 security
domains. We import **only the 30 skills** that overlap with our scanner scope
(web vulns, API security, recon, auth/SSO, AI/LLM, container exposure).

Out-of-scope upstream skills (Active Directory attacks, binary
exploitation/Pwn, mobile, cryptography attacks, blockchain, forensics,
AV evasion, sandbox escape) are intentionally **not imported** — they do
not feed any module in this scanner.

## Imported skills (30)

### Web vulnerability methodology (10)
- `web-cache-deception`, `websocket-security`, `http2-specific-attacks`
- `dangling-markup-injection`, `csp-bypass-advanced`
- `prototype-pollution-advanced`, `request-smuggling`
- `waf-bypass-techniques`, `injection-checking`, `http-host-header-attacks`

### API & auth (6)
- `api-sec`, `api-recon-and-docs`, `api-auth-and-jwt-abuse`, `api-authorization-and-bola`
- `oauth-oidc-misconfiguration`, `saml-sso-assertion-attacks`

### Server-side injection (4)
- `xslt-injection`, `expression-language-injection`, `jndi-injection`, `email-header-injection`

### Cloud / container (2)
- `container-escape-techniques`, `kubernetes-pentesting`

### Reconnaissance (2)
- `recon-and-methodology`, `recon-for-sec`

### Bypass / misc (3)
- `401-403-bypass-techniques`, `dependency-confusion`, `type-juggling`, `dns-rebinding-attacks`

### AI / LLM security (2)
- `llm-prompt-injection`, `ai-ml-security`

## Why these and not others

**Imported:** every skill that maps to an existing scanner module
(`forbidden_bypass`, `cors`, `csp_bypass`, `csrf`, `proto_pollution`,
`smuggling`, `cloud_enum`, `recon`, `osint_identity`, `api_scanner`,
`graphql_audit`, `xxe`, `ssti`, `ssrf`, etc.) **or** to a missing capability
the scanner can plausibly grow into (websocket, http/2, web-cache-deception,
container escape, llm prompt injection).

**Skipped:** Active Directory (Kerberos/ACL/ADCS, NTLM relay), Linux/Windows
lateral movement, binary Pwn (heap/stack/ROP, format string, browser V8),
mobile (Android/iOS, SSL pinning), classical/lattice/RSA crypto attacks,
DeFi/smart contracts, memory forensics, traffic-PCAP, steganography,
windows-AV-evasion, code-obfuscation. These are out of scope for a web
vulnerability scanner.

## License & attribution

Upstream license: not declared in repo at import time. Material is
distilled methodology meant for educational use; treat as
attribution-required reference. **Do not redistribute as our own work.**
Each imported `SKILL.md` retains its original frontmatter (`name`,
`description`) so any downstream loader sees the upstream identifier.

## How the scanner uses these

`utils/ai_intent_agent.py`, `utils/ai_exploit_agent.py`, and
`utils/agent_orchestrator.py` may load any of these `SKILL.md` files as
supplementary system context when reasoning about a target or when picking
the next module to run. They complement (not replace) the native
`core/ai_skills/offensive-*` skills.

## Re-importing

```bash
TMP=/tmp/hack-skills-refresh
rm -rf "$TMP" && git clone --depth=1 https://github.com/yaklang/hack-skills.git "$TMP"
# then replace skills under ./skills/ and bump the commit hash above
```
