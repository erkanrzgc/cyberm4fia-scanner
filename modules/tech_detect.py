"""
cyberm4fia-scanner - Technology Fingerprinter
Wappalyzer-style detection of frameworks, CMS, servers, and libraries
"""

import re
from urllib.parse import urljoin

from utils.colors import log_info, log_success, log_error
from utils.request import smart_request
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Technology Fingerprint Database
# ─────────────────────────────────────────────────────
TECHNOLOGIES = [
    # ── Web Servers ──
    {
        "name": "Nginx",
        "category": "Web Server",
        "headers": {"server": r"nginx/?(\S+)?"},
    },
    {
        "name": "Apache",
        "category": "Web Server",
        "headers": {"server": r"Apache/?(\S+)?"},
    },
    {
        "name": "IIS",
        "category": "Web Server",
        "headers": {"server": r"Microsoft-IIS/?(\S+)?"},
    },
    {
        "name": "LiteSpeed",
        "category": "Web Server",
        "headers": {"server": r"LiteSpeed"},
    },
    {
        "name": "Caddy",
        "category": "Web Server",
        "headers": {"server": r"Caddy"},
    },
    {
        "name": "Cloudflare",
        "category": "CDN/WAF",
        "headers": {"server": r"cloudflare", "cf-ray": r".*"},
    },
    {
        "name": "Vercel",
        "category": "PaaS",
        "headers": {"x-vercel-id": r".*", "server": r"Vercel"},
    },
    {
        "name": "Netlify",
        "category": "PaaS",
        "headers": {"server": r"Netlify", "x-nf-request-id": r".*"},
    },
    # ── Programming Languages ──
    {
        "name": "PHP",
        "category": "Language",
        "headers": {"x-powered-by": r"PHP/?(\S+)?"},
    },
    {
        "name": "ASP.NET",
        "category": "Language",
        "headers": {"x-aspnet-version": r"(\S+)", "x-powered-by": r"ASP\.NET"},
    },
    {
        "name": "Python",
        "category": "Language",
        "headers": {"x-powered-by": r"(Python|Flask|Django|Gunicorn)"},
    },
    {
        "name": "Express.js",
        "category": "Framework",
        "headers": {"x-powered-by": r"Express"},
    },
    # ── CMS ──
    {
        "name": "WordPress",
        "category": "CMS",
        "body_patterns": [
            r"/wp-content/",
            r"/wp-includes/",
            r'<meta name="generator" content="WordPress\s*([\d.]+)?"',
        ],
        "paths": ["/wp-login.php", "/wp-admin/", "/xmlrpc.php"],
    },
    {
        "name": "Joomla",
        "category": "CMS",
        "body_patterns": [
            r"/media/jui/",
            r"/components/com_",
            r'<meta name="generator" content="Joomla',
        ],
        "paths": ["/administrator/"],
    },
    {
        "name": "Drupal",
        "category": "CMS",
        "body_patterns": [
            r"Drupal\.settings",
            r"/sites/default/files/",
            r'<meta name="Generator" content="Drupal',
        ],
        "paths": ["/user/login", "/core/misc/drupal.js"],
    },
    {
        "name": "Magento",
        "category": "CMS",
        "body_patterns": [r"/skin/frontend/", r"Mage\.Cookies"],
    },
    # ── JavaScript Frameworks ──
    {
        "name": "React",
        "category": "JS Framework",
        "body_patterns": [
            r"data-reactroot",
            r"__NEXT_DATA__",
            r"react\.production\.min\.js",
            r'"react-dom"',
        ],
    },
    {
        "name": "Next.js",
        "category": "JS Framework",
        "body_patterns": [r"__NEXT_DATA__", r"/_next/static/"],
        "headers": {"x-powered-by": r"Next\.js"},
    },
    {
        "name": "Vue.js",
        "category": "JS Framework",
        "body_patterns": [r"vue\.runtime", r"data-v-[a-f0-9]", r"__vue__"],
    },
    {
        "name": "Nuxt.js",
        "category": "JS Framework",
        "body_patterns": [r"__NUXT__", r"/_nuxt/"],
    },
    {
        "name": "Angular",
        "category": "JS Framework",
        "body_patterns": [r"ng-version", r"ng-app", r"angular\.min\.js"],
    },
    {
        "name": "Svelte",
        "category": "JS Framework",
        "body_patterns": [r"__svelte", r"svelte-"],
    },
    {
        "name": "jQuery",
        "category": "JS Library",
        "body_patterns": [r"jquery[.-](\d[\d.]+)\.min\.js", r"jquery\.min\.js"],
    },
    # ── Security / Auth ──
    {
        "name": "Firebase",
        "category": "Backend",
        "body_patterns": [r"firebaseapp\.com", r"firebase\.js"],
    },
    {
        "name": "Supabase",
        "category": "Backend",
        "body_patterns": [r"supabase\.co", r"supabase"],
    },
    # ── Analytics ──
    {
        "name": "Google Analytics",
        "category": "Analytics",
        "body_patterns": [
            r"google-analytics\.com/analytics\.js",
            r"gtag\('config'",
            r"googletagmanager\.com",
        ],
    },
    {
        "name": "Hotjar",
        "category": "Analytics",
        "body_patterns": [r"static\.hotjar\.com"],
    },
    # ── Security Headers ──
    {
        "name": "HSTS",
        "category": "Security",
        "headers": {"strict-transport-security": r".*"},
    },
    {
        "name": "CSP",
        "category": "Security",
        "headers": {"content-security-policy": r".*"},
    },
    {
        "name": "X-Frame-Options",
        "category": "Security",
        "headers": {"x-frame-options": r".*"},
    },
    # ── Vendor / Edge Appliances ──
    {
        "name": "Citrix NetScaler/Gateway",
        "category": "Vendor Appliance",
        "body_patterns": [
            r"NetScaler", r"Citrix Gateway", r"Citrix Access Gateway",
        ],
        "paths": [
            "/vpn/index.html", "/logon/LogonPoint/tmindex.html",
            "/citrix/", "/vpn/logon_point/",
        ],
    },
    {
        "name": "F5 BIG-IP",
        "category": "Vendor Appliance",
        "body_patterns": [r"BIG-IP", r"bigip", r"F5 Networks"],
        "paths": ["/tmui/login.jsp", "/mgmt/tm/sys/"],
    },
    {
        "name": "Cisco ASA / AnyConnect",
        "category": "Vendor Appliance",
        "body_patterns": [
            r"Cisco ASA", r"AnyConnect", r"webvpn", r"\+CSCOE\+",
        ],
        "paths": ["/+CSCOE+/", "/CSCOE/index.html", "/webvpn.html"],
    },
    {
        "name": "Pulse Secure / Ivanti Connect",
        "category": "Vendor Appliance",
        "body_patterns": [
            r"Pulse Secure", r"Ivanti Connect Secure", r"dana-na",
        ],
        "paths": ["/dana-na/", "/dana-na/auth/url_default/welcome.cgi"],
    },
    {
        "name": "FortiGate / FortiOS",
        "category": "Vendor Appliance",
        "body_patterns": [r"FortiGate", r"FortiOS", r"forti"],
        "paths": ["/remote/login", "/remote/info", "/api/v2/"],
    },
    {
        "name": "PaloAlto GlobalProtect",
        "category": "Vendor Appliance",
        "body_patterns": [r"GlobalProtect", r"Palo Alto Networks"],
        "paths": [
            "/global-protect/", "/global-protect/portal/css/login.css",
            "/api/?type=keygen",
        ],
    },
    {
        "name": "VMware Horizon",
        "category": "Vendor Appliance",
        "body_patterns": [r"VMware Horizon", r"horizon"],
        "paths": ["/portal/info.jsp", "/broker/xml", "/login.jsp"],
    },
    {
        "name": "VMware vCenter",
        "category": "Vendor Appliance",
        "body_patterns": [r"VMware vCenter", r"vsphere-client"],
        "paths": ["/sdk", "/ui/", "/vsphere-client/", "/websso/SAML2/"],
    },
    {
        "name": "VMware ESXi",
        "category": "Vendor Appliance",
        "body_patterns": [r"VMware ESXi", r"esxi"],
        "paths": ["/sdk", "/ui/", "/folder"],
    },
    {
        "name": "Microsoft Exchange OWA",
        "category": "Vendor Appliance",
        "body_patterns": [
            r"Exchange", r"Outlook Web App", r"owa",
            r"expiredpassword", r"expired\s+password",
        ],
        "paths": ["/owa/", "/ews/exchange.asmx", "/ecp/"],
    },
    {
        "name": "WatchGuard Firebox",
        "category": "Vendor Appliance",
        "body_patterns": [r"WatchGuard", r"Firebox"],
        "paths": ["/auth/", "/wgcgi.cgi"],
    },
    {
        "name": "SonicWall SMA",
        "category": "Vendor Appliance",
        "body_patterns": [r"SonicWall", r"SonicWALL"],
        "paths": ["/cgi-bin/welcome", "/__api__/v1/", "/diagnostics/"],
    },
    {
        "name": "Sophos UTM/XG/XGS",
        "category": "Vendor Appliance",
        "body_patterns": [r"Sophos", r"UTM"],
        "paths": ["/userportal/", "/webconsole/", "/cgi-bin/"],
    },
    {
        "name": "Check Point Firewall",
        "category": "Vendor Appliance",
        "body_patterns": [r"Check Point", r"check_point"],
        "paths": ["/sslvpn/portal/", "/clients/"],
    },
    {
        "name": "Zoho ManageEngine",
        "category": "Vendor Appliance",
        "body_patterns": [r"ManageEngine", r"Zoho"],
        "paths": ["/RestAPI/Login", "/api/json/v2/"],
    },
    {
        "name": "Atlassian Confluence",
        "category": "Vendor Appliance",
        "body_patterns": [r"Confluence", r"confluence-server"],
        "paths": ["/confluence/", "/login.action", "/rest/api/space"],
    },
    {
        "name": "Atlassian Jira",
        "category": "Vendor Appliance",
        "body_patterns": [r"Jira", r"jira-project"],
        "paths": ["/secure/Dashboard.jspa", "/rest/api/2/serverInfo"],
    },
    {
        "name": "GitLab Self-Hosted",
        "category": "Vendor Appliance",
        "body_patterns": [r"GitLab", r"gitlab-ee", r"gitlab-ce"],
        "paths": ["/users/sign_in", "/help", "/explore", "/api/v4/version"],
    },
    {
        "name": "SolarWinds Orion",
        "category": "Vendor Appliance",
        "body_patterns": [r"SolarWinds", r"Orion"],
        "paths": ["/Orion/Login.aspx"],
    },
    {
        "name": "ConnectWise ScreenConnect",
        "category": "Vendor Appliance",
        "body_patterns": [r"ScreenConnect", r"ConnectWise"],
        "paths": ["/SetupWizard.aspx", "/Bin/SetupWizard.aspx"],
    },
    {
        "name": "Telerik UI",
        "category": "Vendor Appliance",
        "body_patterns": [r"Telerik\.Web\.UI", r"WebResource\.axd"],
    },
    # ── Cloud-Native Service Fingerprints ──
    {
        "name": "AWS Lambda Function URL",
        "category": "Cloud Native",
        "headers": {"server": r".*"},
        "body_patterns": [r"lambda-url\..+\.on\.aws"],
    },
    {
        "name": "AWS API Gateway",
        "category": "Cloud Native",
        "body_patterns": [r"execute-api\..+\.amazonaws\.com"],
    },
    {
        "name": "AWS App Runner",
        "category": "Cloud Native",
        "body_patterns": [r"awsapprunner\.com"],
    },
    {
        "name": "AWS Amplify",
        "category": "Cloud Native",
        "body_patterns": [r"amplifyapp\.com"],
    },
    {
        "name": "Google Cloud Run",
        "category": "Cloud Native",
        "body_patterns": [r"\.run\.app\b"],
        "headers": {"server": r"Google Frontend"},
    },
    {
        "name": "Google Cloud Functions",
        "category": "Cloud Native",
        "body_patterns": [r"cloudfunctions\.net"],
    },
    {
        "name": "Google App Engine",
        "category": "Cloud Native",
        "body_patterns": [r"appspot\.com"],
    },
    {
        "name": "Azure Functions / App Service",
        "category": "Cloud Native",
        "body_patterns": [r"azurewebsites\.net"],
        "headers": {"server": r"Microsoft-IIS"},
    },
    {
        "name": "Azure Container Apps",
        "category": "Cloud Native",
        "body_patterns": [r"azurecontainerapps\.io"],
    },
    {
        "name": "Heroku",
        "category": "Cloud Native",
        "body_patterns": [r"herokuapp\.com"],
        "headers": {"via": r".*vegur.*"},
    },
    {
        "name": "Fly.io",
        "category": "Cloud Native",
        "body_patterns": [r"fly\.dev"],
        "headers": {"server": r"Fly/.*"},
    },
    {
        "name": "Render",
        "category": "Cloud Native",
        "body_patterns": [r"onrender\.com"],
    },
    {
        "name": "Railway",
        "category": "Cloud Native",
        "body_patterns": [r"railway\.app"],
    },
    {
        "name": "DigitalOcean App Platform",
        "category": "Cloud Native",
        "body_patterns": [r"ondigitalocean\.app"],
    },
    # ── CI/CD Platform Fingerprints ──
    {
        "name": "Jenkins",
        "category": "CI/CD",
        "body_patterns": [r"Jenkins", r"jenkins", r"Dashboard \[Jenkins\]"],
        "paths": ["/script", "/asynchPeople/", "/computer/", "/login"],
    },
    {
        "name": "TeamCity",
        "category": "CI/CD",
        "body_patterns": [r"TeamCity", r"teamcity"],
        "paths": ["/login.html", "/agent.html", "/admin/admin.html"],
    },
    {
        "name": "Argo CD",
        "category": "CI/CD",
        "body_patterns": [r"Argo CD", r"argocd"],
        "paths": ["/api/version", "/applications"],
    },
    {
        "name": "Drone CI",
        "category": "CI/CD",
        "body_patterns": [r"Drone", r"drone"],
        "paths": ["/api/info", "/login"],
    },
    {
        "name": "Spinnaker",
        "category": "CI/CD",
        "body_patterns": [r"Spinnaker", r"spinnaker"],
        "paths": ["/gate/info", "/applications"],
    },
    {
        "name": "Travis CI",
        "category": "CI/CD",
        "body_patterns": [r"travis-ci", r"travis"],
        "paths": ["/repos/"],
    },
    {
        "name": "Bamboo (Atlassian)",
        "category": "CI/CD",
        "body_patterns": [r"Bamboo", r"bamboo"],
        "paths": ["/userlogin.action", "/rest/api/latest/info"],
    },
]

def fingerprint_headers(headers, tech):
    """Check response headers against technology fingerprints."""
    results = {}
    tech_headers = tech.get("headers", {})

    for header_name, pattern in tech_headers.items():
        header_value = headers.get(header_name, "")
        if header_value:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                version = match.group(1) if match.lastindex else None
                results["matched"] = True
                results["version"] = version
                return results

    return results

def fingerprint_body(body, tech):
    """Check response body against technology fingerprints."""
    patterns = tech.get("body_patterns", [])
    for pattern in patterns:
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            version = match.group(1) if match.lastindex else None
            return {"matched": True, "version": version}
    return {}

def check_paths(url, tech, delay):
    """Check specific paths that indicate a technology."""
    paths = tech.get("paths", [])
    for path in paths:
        try:
            check_url = urljoin(url, path)
            resp = smart_request("get", check_url, delay=delay, timeout=5)
            if resp.status_code == 200:
                return {"matched": True, "evidence": path}
        except ScanExceptions:
            pass
    return {}

def check_security_posture(headers):
    """Analyze missing security headers."""
    issues = []
    critical_headers = {
        "strict-transport-security": "No HSTS — vulnerable to SSL stripping",
        "content-security-policy": "No CSP — vulnerable to XSS",
        "x-frame-options": "No X-Frame-Options — vulnerable to clickjacking",
        "x-content-type-options": "No X-Content-Type-Options — MIME sniffing possible",
        "x-xss-protection": "No X-XSS-Protection header",
        "referrer-policy": "No Referrer-Policy — information leakage risk",
        "permissions-policy": "No Permissions-Policy — feature access not restricted",
    }

    for header, message in critical_headers.items():
        if header not in headers:
            issues.append({"header": header, "issue": message, "severity": "MEDIUM"})

    # Check for information disclosure
    dangerous_headers = ["server", "x-powered-by", "x-aspnet-version"]
    for h in dangerous_headers:
        if h in headers:
            issues.append(
                {
                    "header": h,
                    "issue": f"Information disclosure via {h}: {headers[h]}",
                    "severity": "LOW",
                }
            )

    return issues

def scan_technology(url, delay=0):
    """Main entry point for technology fingerprinting."""
    log_info(f"Starting Technology Fingerprinting on {url}...")

    detected = []

    try:
        resp = smart_request("get", url, delay=delay, timeout=10)
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.text[:50000]  # Limit body analysis to first 50KB

        for tech in TECHNOLOGIES:
            result = {}

            # Check headers
            if "headers" in tech:
                header_result = fingerprint_headers(headers, tech)
                if header_result.get("matched"):
                    result = header_result

            # Check body patterns
            if not result.get("matched") and "body_patterns" in tech:
                body_result = fingerprint_body(body, tech)
                if body_result.get("matched"):
                    result = body_result

            # Check specific paths
            if not result.get("matched") and "paths" in tech:
                path_result = check_paths(url, tech, delay)
                if path_result.get("matched"):
                    result = path_result

            if result.get("matched"):
                version = result.get("version", "")
                evidence = result.get("evidence", "")
                version_str = f" v{version}" if version else ""

                detected.append(
                    {
                        "type": "technology",
                        "name": tech["name"],
                        "category": tech["category"],
                        "version": version,
                        "evidence": evidence,
                    }
                )

                log_success(f"[{tech['category']}] {tech['name']}{version_str}")

        # Security posture analysis
        security_issues = check_security_posture(headers)
        for issue in security_issues:
            detected.append(
                {
                    "type": "security_header",
                    "name": issue["header"],
                    "category": "Security",
                    "issue": issue["issue"],
                    "severity": issue["severity"],
                }
            )

    except ScanExceptions as e:
        log_error(f"Technology fingerprinting failed: {e}")

    log_success(f"Tech detection complete. {len(detected)} item(s) identified.")
    return detected
