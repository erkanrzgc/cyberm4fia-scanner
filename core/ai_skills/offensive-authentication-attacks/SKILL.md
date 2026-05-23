---
name: offensive-authentication-attacks
description: "Authentication attacks covering credential brute force, password spraying, account takeover (ATO), authentication bypass, MFA flaws, and credential-stuffing. Includes login rate-limit testing, response-discrepancy user enumeration, password-reset abuse, and session weaknesses. Use when assessing login, registration, MFA, and password-reset flows."
---

# Authentication Attacks — Offensive Testing Methodology

## Quick Workflow

1. Map all auth surfaces: login, register, reset, MFA, OAuth, API token
2. Enumerate valid users (response/timing discrepancies)
3. Test brute force and password spraying within scope/rate
4. Hunt logic flaws enabling bypass / takeover (reset, MFA, session)

---

## User Enumeration

- Different message for "user not found" vs "wrong password"
- Timing difference (bcrypt only runs for valid users)
- Registration "email already taken"
- Password-reset "we sent an email" vs "no such account"

---

## Brute Force & Password Spraying

- **Brute force**: many passwords against one account — triggers lockout
- **Spraying**: one common password against many accounts — evades lockout

```
Top spray passwords: Season+Year! (Spring2025!), Company123!, Welcome1, Password1!
```

Test for: missing rate limits, lockout bypass via `X-Forwarded-For` rotation,
case/whitespace variants, and login via alternate endpoints (mobile/API) lacking
the same throttling.

---

## Authentication Bypass Patterns

- SQL/NoSQL/LDAP injection in login (see related injection skills)
- Response tampering: `{"success":false}` → `true` when client trusts it
- Forced browsing past login to authenticated pages (broken access control)
- JWT/`alg:none`, weak secret, or unsigned token acceptance (see offensive-jwt)
- "Remember me" / persistent cookie predictable or unsigned

---

## Account Takeover (ATO) Chains

### Password Reset Abuse

- **Host header poisoning**: reset link built from `Host:` → attacker domain captures token
- **Token leakage** in `Referer` to third-party resources
- **Predictable/short tokens**, no expiry, reusable tokens
- **Response leaks token** in the reset-request reply
- **Email parameter pollution**: `email=victim@x&email=attacker@y`

### MFA Flaws

- MFA step skippable by navigating directly to post-MFA endpoint
- OTP brute force (no rate limit / no attempt cap)
- OTP reuse / not invalidated; backup-code enumeration
- "Remember device" token forgeable
- Race condition on OTP verification

### Pre-Account-Takeover

Register victim's email before they do (no verification), or merge OAuth identity
to an unverified local account.

---

## Remediation

- Generic auth error messages; constant-time comparisons
- Rate limit + lockout keyed on account AND IP; CAPTCHA after N failures
- Cryptographically random, single-use, short-TTL reset/OTP tokens
- Build reset URLs from server config, never the `Host` header
- Enforce MFA server-side at every protected step; cap OTP attempts
