# SKILL: Chain Methodology

## Metadata
- **Skill Name**: chain-methodology
- **Folder**: offensive-chain-methodology
- **Source**: pentest-agents rules/chain-table.md

## Description
Capability-to-next-bug chain table and methodology for chaining vulnerabilities. Maps primitives to escalation vectors, defines terminal impacts, and provides the Chain Walk Algorithm. Use when building multi-step attack chains or evaluating whether a finding can be escalated.

## Trigger Phrases
Use this skill when the conversation involves any of:
`chain, escalation, attack path, combined impact, A→B, primitive, capability mapping, terminal impact, attack chain`

## Instructions for Claude

When this skill is active:
1. Load and apply the chain methodology below to evaluate escalation paths
2. Start with a confirmed bug A, map what it gives you, then search this table for the next link
3. Test top candidates, confirm, and proceed until terminal impact or exhaustion
4. Each link must be DIFFERENT (endpoint, mechanism, or impact) and PROVABLE

---

## The Chain Walk Algorithm

1. START with confirmed bug A
2. Map what A GIVES you (capabilities/primitives)
3. Search this table for what takes A's output as input
4. Test the top candidate (B)
5. If B confirmed → map combined capabilities → check terminal impact → if not terminal, B becomes new A → go to 3
6. If B fails → try next candidate (max 3 failures per depth)
7. Report chain so far when terminal impact reached or candidates exhausted

## Capability → Next Bug Table

| You Have (Capability) | Look For (Next Link) | Combined Gives You |
|---|---|---|
| **JS execution in victim context** | HttpOnly not set? → cookie theft | Session token |
| | CSRF token accessible → forge requests | Authenticated actions |
| | postMessage listener unchecked → inject messages | Control over app state |
| | DOM access → read sensitive data | PII, tokens, keys |
| **Arbitrary text injection** | Input evaluated/executed → code execution | JS execution |
| | Input rendered in another context → stored XSS | JS execution in other users |
| | Input sent to API → parameter injection | API abuse |
| **Control over URL/redirect** | OAuth redirect_uri → steal auth code | OAuth token |
| | Open redirect → phishing from trusted domain | Credential theft |
| | iframe src control → clickjacking | UI manipulation |
| **Cookie control (set/read)** | Cookie bomb (overflow headers) → block callbacks | Force error pages |
| | Session fixation → set known session ID | Session hijack |
| | Cookie tossing → override subdomain cookies | Auth confusion |
| **Cross-origin window reference** | window.location readable → URL theft | Tokens in URL |
| | postMessage to window → inject data | State manipulation |
| | window.opener control → tabnabbing | Phishing |
| **SSRF (make server requests)** | Hit cloud metadata → IAM credentials | Cloud access |
| | Hit internal services → access admin panels | Internal access |
| | Hit localhost → bypass IP allowlists | Auth bypass |
| **IDOR (read other user's data)** | Read auth tokens → impersonate | ATO |
| | Read PII → data breach | Privacy violation |
| | Write to other user → modify account | Account manipulation |
| **File write/upload** | Write to web root → web shell | RCE |
| | Write SVG → stored XSS | JS execution |
| | Write config → modify app behavior | App takeover |
| **DNS control (subdomain)** | Subdomain is OAuth redirect_uri → token theft | ATO |
| | Subdomain serves content → trusted phishing | Credential theft |
| | Subdomain has wildcard cert → MitM | Traffic interception |

## Terminal Impacts (stop chaining, report)

- **Account Takeover (ATO)**: stolen session, OAuth token, password reset
- **Remote Code Execution (RCE)**: server-side code exec, web shell
- **Mass Data Exfiltration**: bulk PII, financial data, credentials
- **Full Admin Access**: privilege escalation to admin role
- **Infrastructure Compromise**: cloud creds → full environment access

## Process Rules

1. Confirm each link with exact HTTP request/response
2. Map capabilities after each link
3. Search writeup DB at each step for capability escalation
4. 20-minute time box per link
5. Max 3 failed candidates per depth
6. Each link must be DIFFERENT (endpoint, mechanism, or impact)
7. Each link must be PROVABLE (exact request/response)
8. Report the FULL chain as one submission — chains pay more
