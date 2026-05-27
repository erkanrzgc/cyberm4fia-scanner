---
name: offensive-authz-bypass-systematic
description: "Systematic authorization enforcement testing — replay high-privileged traffic as low-privileged and unauthenticated, compare responses. Detects IDOR, vertical/horizontal privilege escalation, broken access control on state-changing endpoints. Adapted from PortSwigger Autorize."
---

# Systematic Authorization Bypass

## When to Use

The target has authenticated functionality (admin panel, user dashboard,
API with bearer tokens) and you want to test whether *every* endpoint
enforces authorization, not just login itself.

This is the #1 bug class in OWASP Top 10 (Broken Access Control) and
the most frequent finding in real-world pentests.

## Workflow (Autorize-Style)

1. **Capture high-priv traffic** — log in as an admin / power user,
   navigate through the app, intercept every request via the proxy.
2. **Provision a low-priv account** — a normal user / read-only role.
   Capture their session cookie or Bearer token.
3. **Replay each high-priv request** three times:
   - **As-is** (high-priv): baseline response
   - **Swap auth headers** → low-priv: same endpoint, weaker context
   - **Strip auth headers** → unauthenticated: no auth at all
4. **Compare responses.** Authorization is broken when:
   - low-priv response is *equivalent* to high-priv (status + body
     within ±5% length), OR
   - unauth response is equivalent to high-priv

## What the Scanner Does

`modules/authz_audit.py` exposes `scan_authz(requests, low_priv_headers=…)`.
Input: a list of `AuthzProbeRequest(method, url, headers, body)`. Output:
finding dicts of type:

* `Broken_Access_Control_NoAuth` — endpoint accepts unauthenticated
  request and serves the privileged response (CRITICAL)
* `Broken_Access_Control_LowPriv` — endpoint serves the same privileged
  response when called by a low-priv role (HIGH)

Auth headers stripped/swapped:
```
authorization, cookie, x-api-key, x-auth-token,
x-access-token, x-csrf-token, bearer
```

## Equivalence Heuristic

Two responses are "the same" for authz purposes when:

* Status codes match, AND
* Body length differs by ≤5% (default — tunable via
  `length_tolerance` parameter)

For richer comparison, replace `_responses_equivalent()` with the SPA
fingerprint utility from `utils.response_fingerprint` — it computes
simhash + DOM-skeleton + title hashes and tolerates dynamic content
(timestamps, CSRF tokens) without false-flagging.

## Common Authz Bypass Patterns (Manual Escalation After Audit)

Once the audit flags an endpoint, escalate by hand for these primitives:

### A. IDOR (Insecure Direct Object Reference)

The endpoint accepts an ID in the URL or body — try other IDs:

```
GET /api/users/123/profile      # your ID = 123
GET /api/users/124/profile      # neighbouring ID — 200? → IDOR
GET /api/users/-1/profile       # negative
GET /api/users/0/profile        # zero
GET /api/users/admin/profile    # string instead of int
```

### B. Vertical Privilege Escalation

* Send admin-only endpoints with a normal user's token
* Try `/api/v1/admin/users` while authenticated as `user`
* Try POST/DELETE on endpoints that only show GET in the UI

### C. Forced Browsing

Hidden / unlinked endpoints discoverable through the API spec:

```
/api/internal/                  # admin reflection panel
/api/_debug/                    # debug toggle
/api/admin/impersonate          # session takeover
/.well-known/internal/          # service-mesh control
```

`modules/forbidden_bypass.py` already tries 30+ tricks to bypass 403
on these (Host header tricks, path normalization, X-Original-URL, etc.)

### D. HTTP Method Confusion

If `GET /resource` is 200 and `DELETE /resource` is 403, try:

```
POST   /resource  + X-HTTP-Method-Override: DELETE
GET    /resource?_method=DELETE
GET    /resource?action=delete
```

### E. JWT Claim Tampering

Audit captured tokens for:

* `alg: none` accepted? → forge any user
* Weak HMAC secret crackable offline? (modules/jwt_attack.py)
* `kid` parameter injectable? → SQL / path traversal in JWT header
* `role: user` → swap to `role: admin` and re-sign

## What the Audit *Doesn't* Catch (Run Hand-In-Hand)

* **Stateful access control** — endpoint correctly returns 403 the
  first time but accepts a follow-up request that establishes state
  (look at multi-step flows manually)
* **Approval workflows** — endpoint accepts the request but queues it
  for admin approval; from a black-box perspective the response looks
  identical
* **Soft denials** — endpoint returns 200 with a different body shape
  (e.g. empty list) instead of 403. Equivalence check catches body
  length difference, but reviewers should inspect a sample of "200 but
  not equivalent" verdicts.

## Reporting

For each broken-access finding include:

* Method + URL
* High-priv response: status + length
* Low-priv response: status + length
* No-auth response: status + length
* The equivalence reason (e.g. "low-priv body length within 5%")
* Reproduction curl one-liner with the captured headers removed

## References

* PortSwigger Autorize: https://github.com/PortSwigger/autorize
* OWASP Top 10: Broken Access Control (A01:2021)
