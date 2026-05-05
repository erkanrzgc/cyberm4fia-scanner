"""
cyberm4fia-scanner - OSINT Identity / SSO Mapping
Fingerprints identity providers (Entra ID, Okta, Google Workspace, ADFS)
and their tenant configurations for attack-surface mapping.
"""

import re
import time
from urllib.parse import urlparse

from utils.colors import log_info, log_success, log_warning, log_error, Colors
from utils.request import smart_request, ScanExceptions


SSO_PREFIXES = [
    "auth", "login", "sso", "idp", "iam",
    "identity", "accounts", "oauth",
]

SAML_PATHS = [
    "/saml/metadata",
    "/FederationMetadata/2007-06/FederationMetadata.xml",
    "/federationmetadata/2007-06/federationmetadata.xml",
    "/simplesaml/saml2/idp/metadata.php",
    "/auth/saml2/metadata",
]

ADFS_PATHS = [
    "/adfs/idpinitiatedsignon.aspx",
    "/adfs/Services/Trust/mex",
]

VENDOR_IDP_PATTERNS = {
    "Entra ID (Azure AD)": {
        "discovery": "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
        "issuer_pattern": r"login\.microsoftonline\.com/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
    },
    "Okta": {
        "discovery": "https://{slug}.okta.com/.well-known/openid-configuration",
        "preview_discovery": "https://{slug}.oktapreview.com/.well-known/openid-configuration",
    },
    "Auth0": {
        "issuer_pattern": r"https://[^.]+\.auth0\.com",
    },
    "OneLogin": {
        "issuer_pattern": r"https://[^.]+\.onelogin\.com",
    },
    "Ping Identity": {
        "issuer_pattern": r"https://[^.]+\.(?:pingone|pingidentity)\.com",
    },
    "Duo": {
        "issuer_pattern": r"https://[^.]+\.duosecurity\.com",
    },
}

M365_ENDPOINTS = {
    "getuserrealm": "https://login.microsoftonline.com/getuserrealm.srf?login=probe@{domain}",
    "autodiscover": "https://autodiscover-s.outlook.com/autodiscover/metadata/json/1",
    "tenant_oidc": "https://login.microsoftonline.com/{domain}/.well-known/openid-configuration",
    "v2_oidc": "https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration",
}

MS_EXCHANGE_IP_RANGES = [
    ("40.96.0.0", "40.111.255.255"),
    ("52.96.0.0", "52.105.255.255"),
    ("13.107.6.0", "13.107.19.255"),
    ("40.99.0.0", "40.105.255.255"),
    ("52.98.0.0", "52.101.255.255"),
]


def _ip_in_ms_range(ip_str):
    try:
        parts = [int(p) for p in ip_str.split(".")]
        ip_int = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]
        for lo, hi in MS_EXCHANGE_IP_RANGES:
            lo_parts = [int(p) for p in lo.split(".")]
            hi_parts = [int(p) for p in hi.split(".")]
            lo_int = (lo_parts[0] << 24) | (lo_parts[1] << 16) | (lo_parts[2] << 8) | lo_parts[3]
            hi_int = (hi_parts[0] << 24) | (hi_parts[1] << 16) | (hi_parts[2] << 8) | hi_parts[3]
            if lo_int <= ip_int <= hi_int:
                return True
    except (ValueError, IndexError):
        pass
    return False


def _probe_oidc(url, delay, timeout=10):
    try:
        resp = smart_request("get", url, delay=delay, timeout=timeout)
        if resp.status_code == 200:
            data = resp.json()
            issuer = data.get("issuer", "")
            return {
                "status": resp.status_code,
                "issuer": issuer,
                "auth_endpoint": data.get("authorization_endpoint", ""),
                "token_endpoint": data.get("token_endpoint", ""),
                "jwks_uri": data.get("jwks_uri", ""),
            }
    except ScanExceptions:
        pass
    except Exception:
        pass
    return None


def _probe_entra(domain, delay):
    findings = []
    tenant_guid = None
    ns_type = None

    # OIDC metadata + tenant GUID
    oidc_url = f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration"
    oidc = _probe_oidc(oidc_url, delay)
    if oidc and oidc.get("issuer"):
        match = re.search(VENDOR_IDP_PATTERNS["Entra ID (Azure AD)"]["issuer_pattern"], oidc["issuer"])
        if match:
            tenant_guid = match.group(1)
            findings.append({
                "type": "idp_discovery",
                "provider": "Entra ID (Azure AD)",
                "tenant_id": tenant_guid,
                "domain": domain,
                "confidence": "firm",
                "endpoint": oidc_url,
                "details": oidc,
            })
            log_success(f"[Entra ID] Tenant discovered: {tenant_guid}")

    # getuserrealm.srf
    try:
        realm_url = f"https://login.microsoftonline.com/getuserrealm.srf?login=probe@{domain}"
        resp = smart_request("get", realm_url, delay=delay, timeout=10)
        if resp.status_code == 200:
            realm_data = resp.json()
            ns_type = realm_data.get("NameSpaceType", "")
            findings.append({
                "type": "idp_discovery",
                "provider": "Entra ID (Azure AD)",
                "domain": domain,
                "namespace_type": ns_type,
                "confidence": "firm",
                "endpoint": realm_url,
                "details": realm_data,
            })
            log_success(f"[Entra ID] NameSpaceType: {ns_type}")
    except ScanExceptions:
        pass
    except Exception:
        pass

    # V2 OIDC (device_code check)
    try:
        v2_url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
        v2_oidc = _probe_oidc(v2_url, delay)
        if v2_oidc and v2_oidc.get("device_authorization_endpoint"):
            findings.append({
                "type": "idp_misconfig",
                "provider": "Entra ID (Azure AD)",
                "domain": domain,
                "finding": "device_authorization_endpoint_enabled",
                "severity": "medium",
                "description": "Device code phishing surface enabled",
                "confidence": "firm",
            })
            log_warning(f"[Entra ID] Device code endpoint enabled — phishing target")
    except Exception:
        pass

    # M365 SharePoint subdomain probe
    stem = domain.split(".")[0]
    for sub in ["", "-my", "-admin"]:
        try:
            sharepoint_url = f"https://{stem}{sub}.sharepoint.com/"
            resp = smart_request("head", sharepoint_url, delay=delay, timeout=8)
            if resp.status_code in (200, 401, 403, 302):
                findings.append({
                    "type": "m365_tenancy",
                    "provider": "Microsoft 365",
                    "domain": domain,
                    "sharepoint_host": f"{stem}{sub}.sharepoint.com",
                    "status": resp.status_code,
                    "confidence": "firm" if resp.status_code in (200, 302) else "tentative",
                })
                log_success(f"[M365] SharePoint exists: {stem}{sub}.sharepoint.com → {resp.status_code}")
        except ScanExceptions:
            pass

    # Autodiscover IP correlation
    try:
        import socket
        autod_host = f"autodiscover.{domain}"
        ip = socket.gethostbyname(autod_host)
        if ip and _ip_in_ms_range(ip):
            findings.append({
                "type": "m365_confirmed",
                "provider": "Microsoft 365",
                "domain": domain,
                "autodiscover_ip": ip,
                "confidence": "confirmed",
                "description": "Autodiscover resolves to Microsoft IP space — M365 confirmed",
            })
            log_success(f"[M365] Autodiscover IP {ip} in MS range — confirmed tenant")
    except Exception:
        pass

    return findings


def _probe_okta(domain, delay):
    findings = []
    stem = domain.split(".")[0]
    slugs = [stem]

    # Also check subdomain-based slugs
    parts = domain.split(".")
    if len(parts) >= 2:
        slugs.append(parts[-2])

    for slug in slugs:
        for tpl, label in [
            ("https://{s}.okta.com/.well-known/openid-configuration", "okta.com"),
            ("https://{s}.oktapreview.com/.well-known/openid-configuration", "oktapreview.com"),
        ]:
            url = tpl.format(s=slug)
            oidc = _probe_oidc(url, delay)
            if oidc and oidc.get("issuer"):
                findings.append({
                    "type": "idp_discovery",
                    "provider": "Okta",
                    "slug": slug,
                    "domain": domain,
                    "endpoint": url,
                    "confidence": "firm",
                    "details": oidc,
                })
                log_success(f"[Okta] Tenant discovered: {slug}.{label}")

    return findings


def _probe_adfs(domain, delay):
    findings = []
    for path in ADFS_PATHS:
        try:
            url = f"https://{domain}{path}"
            resp = smart_request("get", url, delay=delay, timeout=8)
            if resp.status_code == 200:
                findings.append({
                    "type": "idp_discovery",
                    "provider": "ADFS",
                    "domain": domain,
                    "endpoint": url,
                    "confidence": "firm",
                })
                log_success(f"[ADFS] Endpoint accessible: {url}")
        except ScanExceptions:
            pass
    return findings


def _probe_saml(domain, delay):
    findings = []
    for path in SAML_PATHS:
        try:
            url = f"https://{domain}{path}"
            resp = smart_request("get", url, delay=delay, timeout=8)
            if resp.status_code == 200 and resp.text:
                text_lower = resp.text.lower()
                if any(tag in text_lower for tag in ["entityid", "entitydescriptor", "singlesignonservice", "signingcertificate"]):
                    findings.append({
                        "type": "idp_discovery",
                        "provider": "SAML IdP",
                        "domain": domain,
                        "endpoint": url,
                        "confidence": "firm",
                        "description": "SAML metadata XML exposed",
                    })
                    log_success(f"[SAML] Metadata exposed: {url}")
                    break
        except ScanExceptions:
            pass
    return findings


def _probe_google_workspace(domain, delay):
    findings = []
    oidc_url = f"https://{domain}/.well-known/openid-configuration"
    oidc = _probe_oidc(oidc_url, delay)
    if oidc and oidc.get("issuer") and "accounts.google.com" in oidc.get("issuer", ""):
        findings.append({
            "type": "idp_discovery",
            "provider": "Google Workspace",
            "domain": domain,
            "endpoint": oidc_url,
            "confidence": "firm",
            "details": oidc,
        })
        log_success(f"[Google Workspace] Domain-hosted OIDC confirmed")
    return findings


def _probe_generic_oidc(domain, delay):
    findings = []
    oidc_url = f"https://{domain}/.well-known/openid-configuration"
    oidc = _probe_oidc(oidc_url, delay)
    if oidc and oidc.get("issuer"):
        issuer = oidc["issuer"]
        for vendor, patterns in VENDOR_IDP_PATTERNS.items():
            if vendor in ("Entra ID (Azure AD)", "Okta"):
                continue
            ipat = patterns.get("issuer_pattern")
            if ipat and re.search(ipat, issuer):
                findings.append({
                    "type": "idp_discovery",
                    "provider": vendor,
                    "domain": domain,
                    "issuer": issuer,
                    "endpoint": oidc_url,
                    "confidence": "firm",
                    "details": oidc,
                })
                log_success(f"[{vendor}] Discovered via OIDC: {issuer}")
                break
        else:
            if "realms/" in issuer:
                findings.append({
                    "type": "idp_discovery",
                    "provider": "Keycloak",
                    "domain": domain,
                    "issuer": issuer,
                    "endpoint": oidc_url,
                    "confidence": "firm",
                    "details": oidc,
                })
                log_success(f"[Keycloak] Discovered: {issuer}")
    return findings


def _probe_sso_prefixes(domain, subdomains, delay):
    findings = []
    base = domain.split(".")[-2] if domain.count(".") >= 1 else domain
    root = domain

    for prefix in SSO_PREFIXES:
        host = f"{prefix}.{root}"
        if host in (s.get("host", "") for s in subdomains):
            oidc_url = f"https://{host}/.well-known/openid-configuration"
            oidc = _probe_oidc(oidc_url, delay)
            if oidc:
                findings.append({
                    "type": "idp_discovery",
                    "provider": "Unknown OIDC",
                    "host": host,
                    "endpoint": oidc_url,
                    "confidence": "firm",
                    "details": oidc,
                })
                log_success(f"[OIDC] {host} exposes OIDC config")
    return findings


def scan_identity_fabric(url, subdomains=None, delay=0):
    """
    Scan target for identity provider (IdP) and SSO infrastructure.

    Maps Entra ID tenants, Okta orgs, Google Workspace, ADFS, SAML
    metadata, and generic OIDC endpoints.

    Args:
        url: Target URL
        subdomains: Optional list of known subdomain dicts
        delay: Request delay

    Returns:
        list of findings dicts
    """
    parsed = urlparse(url)
    domain = parsed.hostname or ""
    if domain.startswith("www."):
        domain = domain[4:]

    print(f"\n{Colors.BOLD}{Colors.CYAN}──── IDENTITY FABRIC MAPPING ────{Colors.END}")
    log_info(f"Mapping identity fabric for {domain}...")

    all_findings = []

    # 1. Probe Entra ID (Azure AD) + M365 deep
    log_info("[*] Probing Microsoft Entra / M365...")
    entra_findings = _probe_entra(domain, delay)
    all_findings.extend(entra_findings)

    # 2. Probe Okta
    log_info("[*] Probing Okta...")
    okta_findings = _probe_okta(domain, delay)
    all_findings.extend(okta_findings)

    # 3. Probe ADFS
    log_info("[*] Probing ADFS...")
    adfs_findings = _probe_adfs(domain, delay)
    all_findings.extend(adfs_findings)

    # 4. Probe SAML metadata
    log_info("[*] Probing SAML metadata...")
    saml_findings = _probe_saml(domain, delay)
    all_findings.extend(saml_findings)

    # 5. Probe Google Workspace
    log_info("[*] Probing Google Workspace...")
    gw_findings = _probe_google_workspace(domain, delay)
    all_findings.extend(gw_findings)

    # 6. Probe generic OIDC
    log_info("[*] Probing generic OIDC...")
    generic_findings = _probe_generic_oidc(domain, delay)
    all_findings.extend(generic_findings)

    # 7. Probe SSO prefix subdomains
    if subdomains:
        log_info("[*] Probing SSO subdomain prefixes...")
        sso_findings = _probe_sso_prefixes(domain, subdomains, delay)
        all_findings.extend(sso_findings)

    # Print summary
    providers_found = set(f.get("provider", "Unknown") for f in all_findings)
    log_success(f"Identity fabric mapping complete. {len(all_findings)} finding(s).")
    if providers_found:
        log_success(f"Discovered providers: {', '.join(providers_found)}")

    print(f"{Colors.BOLD}{Colors.CYAN}──── IDENTITY MAPPING COMPLETE ────{Colors.END}\n")
    return all_findings
