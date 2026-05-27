---
name: offensive-cache-poisoning
description: "Web cache poisoning via unkeyed header injection (X-Forwarded-Host, X-Original-URL, etc.). Covers detection of cache layers, unkeyed input discovery, reflection probing, cache key bypass, and DOS-by-poisoning. Adapted from PortSwigger param-miner methodology."
---

# Web Cache Poisoning

## Quick Workflow

1. Identify whether a cache layer is between you and the origin (Vercel,
   Cloudflare, Fastly, CloudFront, Varnish, Akamai, nginx_cache).
2. Find headers that are *reflected* into the response body but *not*
   part of the cache key.
3. Inject a malicious value via that header; the origin reflects it,
   the cache stores the poisoned response, and the next user receives
   it.

## Cache-Layer Fingerprinting

Response headers that reveal a cache exists:

| Header | Vendor |
|---|---|
| `X-Cache: HIT \| MISS` | generic / Varnish / CloudFront |
| `X-Cache-Status` | nginx_cache |
| `CF-Cache-Status` | Cloudflare |
| `X-Vercel-Cache` | Vercel |
| `X-Fastly-Cache` | Fastly |
| `X-Amz-Cf-Pop` | CloudFront |
| `Age: <seconds>` | RFC 7234 (any HTTP cache) |

The scanner's `modules/cache_poisoning.py` already parses these
(`_CACHE_STATUS_HEADERS`) — its `_looks_cached()` helper returns
`(is_cached, evidence)` for any response.

## Unkeyed Input Catalogue (the 25 we probe)

These headers are *usually* not part of the cache key on default
CDN configurations but are commonly reflected by origin servers:

```
X-Forwarded-Host        X-Original-URL        Forwarded
X-Forwarded-Server      X-Rewrite-URL         X-Real-IP
X-Forwarded-Scheme      X-Override-URL        X-Backend-Server
X-Forwarded-Port        X-Original-Host       X-Wap-Profile
X-Forwarded-Proto       X-HTTP-Host-Override  X-Pingback
X-Forwarded-Ssl         X-Host                Via
X-Forwarded-For         True-Client-IP        Profile
X-Originating-IP        X-Remote-IP           Client-IP
X-Client-IP
```

Plus dynamic ones worth fuzzing per-target:

```
Via, X-Server-Name, X-Cluster-Client-IP, Surrogate-Capability,
Surrogate-Control, X-Edge-Location, Akamai-User-Agent
```

## Detection Decision Tree

```
1. Fetch baseline (no extra headers) → record body + cache state
2. For each candidate header:
   a. Send same URL + header set to a unique random token
   b. Token appears in response body?
      - No  → header not reflected, skip
      - Yes → header reflected, continue
   c. Fetch baseline URL again (no headers)
   d. Token appears in this clean response?
      - Yes → CACHE_POISONING_VERIFIED (cache layer served poison
              to a clean client — HIGH severity)
      - No  → CACHE_POISONING_REFLECTION (reflected but cache key
              includes this header — MEDIUM)
3. Once verified, STOP — do not poison further so real users aren't
   served the attacker payload.
```

## Common Reflection Sinks

* **Password reset links** — origin builds the link from
  `X-Forwarded-Host`. Poison once, every reset email becomes an
  attacker-controlled URL.
* **Canonical / Open Graph URLs** — `<link rel="canonical" href="…">`
  built from forwarded headers. Cached HTML serves attacker domain to
  every search engine + social card.
* **Redirect targets** — `Location: https://{X-Forwarded-Host}/foo`
  redirects every cached miss to attacker.
* **Asset URLs** — `<script src="//{X-Forwarded-Host}/app.js">` is the
  highest-impact: cache layer serves attacker JS to every visitor.

## Cache Key Bypass Tricks

If the obvious header is keyed, try:

* **Header value case manipulation:** `X-Forwarded-Host: ATTACKER.tld` —
  cache keys are case-sensitive on some CDNs.
* **Cookie poisoning:** `Cookie: session=abc; debug=1` — the `debug=1`
  segment isn't part of the cache key but the origin may switch into
  debug mode and leak.
* **Param cloaking:** `?cache_buster=1` + a duplicate of the keyed
  query param at the end forces a cache miss but the duplicate may
  override server-side parsing.
* **Fat GET:** include a request body on a GET request — most caches
  ignore the body, but the origin honours it (see Web Cache
  Entanglement, 2020).

## DoS-by-Poisoning

Cache a deliberately broken response (e.g. `400 Bad Request` triggered
by oversized header) → every subsequent request gets 400 until TTL
expires. Cheap denial of service.

```
GET /path HTTP/1.1
Host: target.tld
X-Forwarded-Host: AAAAAAAAAAAAAA…  (8000 bytes — triggers WAF/server 4xx)
```

The CDN caches the 4xx + serves it to everyone.

## Safety Notes (this is destructive)

* The scanner stops probing after the first verified poisoning to limit
  blast radius.
* `scan_cache_poisoning()` should only run against systems where you
  have explicit authorization — a successful poisoning serves the
  attacker payload to real users until the TTL expires.
* For production-impact testing, coordinate with the CDN team to
  shorten TTL or use a dedicated test-only cache key.

## References

* PortSwigger 2018: https://portswigger.net/research/practical-web-cache-poisoning
* PortSwigger 2020: https://portswigger.net/research/web-cache-entanglement
* param-miner: https://github.com/portswigger/param-miner
