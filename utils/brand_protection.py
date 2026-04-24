"""
cyberm4fia-scanner - Brand Protection (Typosquatting & Phishing DNS) Module
"""
import socket
from urllib.parse import urlparse
import itertools

# Common homoglyphs for typosquatting
HOMOGLYPHS = {
    'a': ['4', '@', 'ä', 'á', 'à'],
    'b': ['8', '6'],
    'c': ['(', 'k', 'ç'],
    'e': ['3', 'é', 'è', 'ê'],
    'g': ['q', '9'],
    'i': ['1', 'l', '!', 'í'],
    'l': ['1', 'i', 'I'],
    'o': ['0', 'ö', 'ó'],
    's': ['5', '$', 'z', 'ş'],
    't': ['7', '+'],
    'u': ['v', 'ü', 'ú'],
    'w': ['vv'],
    'y': ['v', 'j']
}

def generate_typosquatting_domains(domain):
    """
    Generate a small set of highly-likely typosquatting domains.
    1. Omission (removing one character)
    2. Repetition (doubling a character)
    3. Homoglyphs (replacing a character with a visually similar one)
    4. TLD Swap (.com -> .net, .co, .io)
    """
    if not domain:
        return []
        
    parts = domain.split('.')
    if len(parts) < 2:
        return []
        
    base_name = parts[-2]
    tld = parts[-1]
    
    variations = set()
    
    # 1. Omission
    for i in range(len(base_name)):
        var = base_name[:i] + base_name[i+1:]
        if var:
            variations.add(f"{var}.{tld}")
            
    # 2. Repetition
    for i in range(len(base_name)):
        var = base_name[:i] + base_name[i] + base_name[i] + base_name[i+1:]
        variations.add(f"{var}.{tld}")
        
    # 3. Homoglyphs (only 1 character replacement to prevent explosion)
    for i, char in enumerate(base_name):
        if char in HOMOGLYPHS:
            for glyph in HOMOGLYPHS[char]:
                var = base_name[:i] + glyph + base_name[i+1:]
                variations.add(f"{var}.{tld}")
                
    # 4. TLD Swap (Common phishing TLDs)
    common_tlds = ['co', 'net', 'io', 'biz', 'info', 'xyz', 'online']
    for alt_tld in common_tlds:
        if alt_tld != tld:
            variations.add(f"{base_name}.{alt_tld}")
            
    # Return max 100 variations to avoid taking too long
    return list(variations)[:100]

def check_phishing_domains(target_url):
    """
    Check if typosquatting domains are registered and point to a different IP.
    Returns findings.
    """
    findings = []
    try:
        parsed = urlparse(target_url)
        target_domain = parsed.netloc.split(':')[0]
        
        # Remove www.
        if target_domain.startswith("www."):
            target_domain = target_domain[4:]
            
        try:
            # Get original IP to compare against
            target_ip = socket.gethostbyname(target_domain)
        except socket.gaierror:
            return findings # Target is unreachable
            
        domains_to_test = generate_typosquatting_domains(target_domain)
        
        for alt_domain in domains_to_test:
            try:
                # Fast timeout for DNS
                socket.setdefaulttimeout(1)
                alt_ip = socket.gethostbyname(alt_domain)
                
                # If it resolves to a different IP, it's highly suspicious!
                if alt_ip != target_ip:
                    findings.append({
                        "type": "Brand_Protection_Phishing",
                        "variant": "Typosquatting Domain",
                        "url": f"http://{alt_domain}",
                        "description": (
                            f"Suspicious domain registered: {alt_domain}. "
                            f"Resolves to {alt_ip} (Target IP is {target_ip}). "
                            "May be used for phishing/Qishing campaigns against your customers."
                        ),
                        "severity": "HIGH",
                        "evidence": f"{alt_domain} -> {alt_ip}"
                    })
            except socket.gaierror:
                pass # Domain not registered or no A record
            except socket.timeout:
                pass
                
    except Exception:
        pass
        
    return findings
