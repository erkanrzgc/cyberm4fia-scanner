"""
cyberm4fia-scanner - Google OSV-Scanner Integration (SCA)
Uses OSV.dev REST API to find vulnerabilities in detected software versions
and exposed manifest files.
"""

import json
import re

from utils.request import increment_vulnerability_count
from utils.colors import log_info, log_vuln, log_warning

OSV_API_URL = "https://api.osv.dev/v1/query"

# Mapping common tech stack names to OSV Ecosystems
ECOSYSTEM_MAP = {
    "node.js": "npm",
    "express": "npm",
    "react": "npm",
    "php": "Packagist",
    "laravel": "Packagist",
    "symfony": "Packagist",
    "python": "PyPI",
    "django": "PyPI",
    "flask": "PyPI",
    "ruby": "RubyGems",
    "rails": "RubyGems",
    "java": "Maven",
    "spring": "Maven",
    "go": "Go",
    "rust": "crates.io",
}

def query_osv_api(package_name, version, ecosystem=None):
    """
    Query OSV.dev API for vulnerabilities in a specific package and version.
    """
    payload = {
        "version": version,
        "package": {
            "name": package_name
        }
    }
    
    if ecosystem:
        payload["package"]["ecosystem"] = ecosystem
    
    try:
        # We use a direct requests call here to avoid our smart_request's 
        # anti-evasion/WAF tampering since we are talking to a legitimate API
        import requests
        resp = requests.post(OSV_API_URL, json=payload, timeout=10)
        
        if resp.status_code == 200:
            data = resp.json()
            vulns = data.get("vulns", [])
            return vulns
    except Exception as e:
        log_warning(f"OSV API query failed for {package_name} v{version}: {e}")
        
    return []

def extract_cve_info(osv_vuln):
    """Extract human-readable info from an OSV vulnerability record."""
    cve_id = "Unknown"
    for alias in osv_vuln.get("aliases", []):
        if alias.startswith("CVE-"):
            cve_id = alias
            break
            
    summary = osv_vuln.get("summary", "No summary provided")
    details = osv_vuln.get("details", "")
    severity = "high" # Default if not found
    cvss = 7.0
    
    # Try to extract severity from CVSS
    severity_data = osv_vuln.get("severity", [])
    for sev in severity_data:
        if sev.get("type") == "CVSS_V3":
            score_str = sev.get("score", "")
            # Basic parsing of CVSS string or just assume HIGH/CRITICAL if it has CVSS
            if "CRITICAL" in details.upper() or "HIGH" in details.upper():
                pass # Not perfectly parsing CVSS string here, fallback to textual clues
            
    # Simple keyword heuristic if CVSS isn't easily parsed
    text_to_check = (summary + " " + details).upper()
    if "CRITICAL" in text_to_check or "RCE" in text_to_check or "REMOTE CODE EXECUTION" in text_to_check:
        severity = "critical"
        cvss = 9.8
    elif "MEDIUM" in text_to_check:
        severity = "medium"
        cvss = 5.5
    elif "LOW" in text_to_check:
        severity = "low"
        cvss = 3.0
        
    return {
        "cve": cve_id,
        "summary": summary,
        "severity": severity,
        "cvss": cvss,
        "url": osv_vuln.get("id", "")
    }

def check_tech_stack_vulns(url, tech_stack):
    """
    Given a target URL and a dictionary of tech_stack (name -> version),
    queries OSV API and returns findings.
    """
    findings = []
    
    if not tech_stack:
        return findings
        
    log_info(f"📦 Checking OSV database for {len(tech_stack)} detected technologies...")
    
    for tech_name, version in tech_stack.items():
        if not version or version == "unknown":
            continue
            
        ecosystem = ECOSYSTEM_MAP.get(tech_name.lower())
        
        # In OSV, package names are usually exact. We might need to guess or use the tech_name directly.
        # This is a best-effort approach.
        vulns = query_osv_api(tech_name.lower(), version, ecosystem)
        
        if vulns:
            log_vuln(f"Found {len(vulns)} known vulnerabilities for {tech_name} v{version}!")
            
            for vuln in vulns[:5]:  # Limit to top 5 to avoid spam
                info = extract_cve_info(vuln)
                increment_vulnerability_count()
                findings.append({
                    "type": "Known_Vulnerability_SCA",
                    "url": url,
                    "component": tech_name,
                    "version": version,
                    "cve": info["cve"],
                    "description": f"OSV/CVE found in {tech_name} {version}: {info['summary']}",
                    "severity": info["severity"],
                    "cvss": info["cvss"],
                    "evidence": info["url"]
                })
                
    return findings

def analyze_exposed_manifest(url, manifest_content, manifest_type):
    """
    Parse an exposed package.json or composer.json and check all dependencies against OSV.
    """
    findings = []
    log_info(f"📦 Analyzing exposed {manifest_type} for vulnerable dependencies...")
    
    try:
        data = json.loads(manifest_content)
    except json.JSONDecodeError:
        return findings
        
    dependencies = {}
    ecosystem = None
    
    if manifest_type == "package.json":
        ecosystem = "npm"
        dependencies.update(data.get("dependencies", {}))
        # Optional: check devDependencies too, though they are usually not deployed
        
    elif manifest_type == "composer.json":
        ecosystem = "Packagist"
        dependencies.update(data.get("require", {}))
        
    if not dependencies:
        return findings
        
    # Clean up versions (remove ^, ~, >=, etc. to get base version)
    clean_deps = {}
    for pkg, ver in dependencies.items():
        # Very basic semver cleanup for OSV lookup
        clean_ver = re.sub(r'[^\d\.]', '', ver)
        if clean_ver:
            clean_deps[pkg] = clean_ver
            
    # Check max 10 dependencies to avoid hitting API limits too hard
    # In a real enterprise version, we'd batch this or use the OSV /querybatch endpoint
    import itertools
    for pkg, ver in itertools.islice(clean_deps.items(), 10):
        vulns = query_osv_api(pkg, ver, ecosystem)
        if vulns:
            log_vuln(f"Dependency {pkg} v{ver} has {len(vulns)} known vulnerabilities!")
            for vuln in vulns[:3]:
                info = extract_cve_info(vuln)
                increment_vulnerability_count()
                findings.append({
                    "type": "Vulnerable_Dependency",
                    "url": url,
                    "component": pkg,
                    "version": ver,
                    "cve": info["cve"],
                    "description": f"Exposed manifest uses vulnerable {pkg} {ver}: {info['summary']}",
                    "severity": info["severity"],
                    "cvss": info["cvss"],
                    "evidence": info["url"]
                })
                
    return findings
