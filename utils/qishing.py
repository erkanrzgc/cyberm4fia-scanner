"""
cyberm4fia-scanner - Qishing (QR Phishing) Detection Module
"""
import re
import io
from urllib.parse import urlparse, urljoin
from utils.colors import log_info, log_warning

# We encapsulate imports in a try-except block so the scanner doesn't crash 
# if the user hasn't installed pyzbar/pillow yet.
try:
    from PIL import Image
    from pyzbar.pyzbar import decode
    QR_MODULES_AVAILABLE = True
except ImportError:
    QR_MODULES_AVAILABLE = False

def extract_qr_from_image(image_bytes):
    """
    Decodes QR codes from raw image bytes.
    Returns a list of decoded URLs/text strings.
    """
    if not QR_MODULES_AVAILABLE:
        return []
        
    try:
        # Load image from bytes
        image = Image.open(io.BytesIO(image_bytes))
        
        # Decode any QR codes found
        decoded_objects = decode(image)
        
        results = []
        for obj in decoded_objects:
            if obj.type == 'QRCODE':
                # pyzbar returns bytes, decode to string
                results.append(obj.data.decode('utf-8'))
                
        return results
    except Exception:
        # Image might be corrupted, unsupported format, or pyzbar failed
        return []

def analyze_image_for_qishing(image_url, image_bytes, target_domain):
    """
    Analyzes an image for QR codes. If a QR code is found and it points to 
    an external domain, returns a vulnerability finding.
    """
    findings = []
    
    if not QR_MODULES_AVAILABLE:
        return findings
        
    decoded_urls = extract_qr_from_image(image_bytes)
    
    for qr_url in decoded_urls:
        # Basic check if the decoded text looks like a URL
        if qr_url.startswith("http://") or qr_url.startswith("https://"):
            try:
                parsed_qr = urlparse(qr_url)
                qr_domain = parsed_qr.netloc.split(':')[0]
                
                # Check if it redirects away from the target domain
                if qr_domain and not qr_domain.endswith(target_domain):
                    findings.append({
                        "type": "Qishing_Vulnerability",
                        "variant": "External QR Code Redirect",
                        "url": image_url,
                        "description": (
                            f"Image contains a QR code that redirects to an external domain ({qr_domain}). "
                            "This could be a Qishing (QR Phishing) attempt if the image was uploaded by a user "
                            "or if the site has been compromised."
                        ),
                        "severity": "HIGH",
                        "evidence": f"QR Code decodes to: {qr_url}"
                    })
                else:
                    findings.append({
                        "type": "Qishing_Vulnerability",
                        "variant": "Internal QR Code (Safe)",
                        "url": image_url,
                        "description": "Image contains a QR code, but it safely redirects back to the internal domain.",
                        "severity": "INFO",
                        "evidence": f"QR Code decodes to: {qr_url}"
                    })
            except Exception:
                pass
                
    return findings
