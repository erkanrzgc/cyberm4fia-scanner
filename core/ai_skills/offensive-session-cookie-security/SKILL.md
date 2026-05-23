---
name: offensive-session-cookie-security
description: "Session and cookie security testing plus transport hardening review. Covers missing Secure/HttpOnly/SameSite flags, weak/predictable session IDs, session fixation, missing HSTS, cookie scope (Domain/Path) over-sharing, and __Host-/__Secure- prefix misuse. Use when auditing Set-Cookie headers, session lifecycle, and TLS transport headers."
---

# Session & Cookie Security — Offensive Testing Methodology

## Quick Workflow

1. Capture all `Set-Cookie` headers; audit flags and scope
2. Analyze session-ID strength and lifecycle (login/logout/rotation)
3. Test session fixation and idle/absolute timeout
4. Review transport headers (HSTS) and cookie prefixes

---

## Cookie Flag Audit

| Flag | Risk if missing |
|---|---|
| `Secure` | Cookie sent over HTTP → interception |
| `HttpOnly` | Readable by JS → XSS steals session |
| `SameSite` | None/absent → CSRF cross-site sending |
| `Domain` too broad | Shared to siblings/subdomains |
| `Path` too broad | Sent to unrelated app paths |

Session cookies should be `Secure; HttpOnly; SameSite=Lax|Strict`.

### Cookie Prefixes

- `__Secure-` requires `Secure` + HTTPS
- `__Host-` requires `Secure`, no `Domain`, `Path=/` — strongest scoping

---

## Session Lifecycle Flaws

### Session Fixation

1. Obtain a session ID before login
2. Force it on the victim (URL/Set-Cookie)
3. If the ID is **not rotated on login**, attacker shares the authenticated session

### Predictable / Weak IDs

- Short, sequential, timestamp- or counter-derived IDs
- Insufficient entropy (collect many, analyze distribution)

### Timeout / Invalidation

- No idle or absolute timeout
- Session still valid after logout / password change
- Tokens not revoked server-side (only client cookie cleared)

---

## Transport (HSTS)

- Missing `Strict-Transport-Security` → SSL-strip / downgrade
- No `includeSubDomains` / `preload` where appropriate
- HTTP not redirected to HTTPS

```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```

---

## Remediation

- Set `Secure; HttpOnly; SameSite` on all session cookies; use `__Host-` prefix
- High-entropy random session IDs (CSPRNG); rotate on login & privilege change
- Server-side invalidation on logout/password change; idle + absolute timeouts
- Enforce HSTS and HTTP→HTTPS redirect; scope `Domain`/`Path` tightly
