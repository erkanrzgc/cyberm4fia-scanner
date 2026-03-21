"""
cyberm4fia-scanner - Recon Module
Port scanning and server reconnaissance
"""

import socket
import ssl
import asyncio
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import _get_session
from utils.request import ScanExceptions

WEB_PORTS = [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]

PORT_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    111: "RPCBind",
    135: "MSRPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP/TLS",
    631: "CUPS",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel-SSL",
    2222: "SSH-Alt",
    3000: "Dev-Server",
    3306: "MySQL",
    3389: "RDP",
    4443: "HTTPS-Alt",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM-SSL",
    6379: "Redis",
    6667: "IRC",
    8000: "HTTP-Alt",
    8008: "HTTP-Alt2",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    8888: "HTTP-Alt3",
    9000: "PHP-FPM",
    9090: "Web-Admin",
    9200: "Elasticsearch",
    9300: "ES-Transport",
    11211: "Memcached",
    27017: "MongoDB",
    27018: "MongoDB-Alt",
    2375: "Docker",
    2376: "Docker-TLS",
    5601: "Kibana",
    6443: "K8s-API",
    7001: "WebLogic",
    8834: "Nessus",
    9042: "Cassandra",
    9092: "Kafka",
    10000: "Webmin",
    15672: "RabbitMQ-Mgmt",
    50000: "SAP",
}

# Ports that indicate high-risk security issues
DANGEROUS_PORTS = {
    21: "FTP often allows anonymous login",
    23: "Telnet sends credentials in plaintext",
    445: "SMB is frequently targeted (EternalBlue)",
    2375: "Docker API without TLS = full host compromise",
    3389: "RDP is a common attack vector",
    6379: "Redis often has no authentication",
    9200: "Elasticsearch often has no authentication",
    11211: "Memcached can be used for DDoS amplification",
    27017: "MongoDB often has no authentication",
}

# SSL ports for certificate inspection
SSL_PORTS = (443, 465, 636, 993, 995, 2083, 4443, 5986, 8443)

def _init_extended_ports():
    """Build extended port list for deep scans."""
    ports = set()
    for p in range(1, 1024):
        ports.add(p)
    for p in PORT_SERVICES.keys():
        ports.add(p)
    return list(sorted(ports))

EXTENDED_PORTS = _init_extended_ports()

async def async_scan_port(ip, port, semaphore, timeout=1.0):
    """Scan a single port asynchronously with banner grabbing."""
    async with semaphore:
        try:
            conn = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)

            # Try to grab banner
            banner = ""
            try:
                # Some services send banner on connect (SSH, FTP, SMTP)
                data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                if data:
                    banner = data.decode("utf-8", errors="ignore").strip()
                    banner = banner.split("\n")[0][:200]
            except (asyncio.TimeoutError, Exception):
                pass

            writer.close()
            try:
                await writer.wait_closed()
            except ScanExceptions:
                pass

            service = PORT_SERVICES.get(port, "Unknown")
            return {"port": port, "service": service, "banner": banner}
        except Exception:
            # Catch TimeoutError, ConnectionRefusedError, CancelledError and others
            return None

async def run_async_scanner(ip, ports_to_scan, concurrency=1000, timeout=1.0):
    """Run concurrent port scans using asyncio."""
    semaphore = asyncio.Semaphore(concurrency)
    tasks = [async_scan_port(ip, port, semaphore, timeout) for port in ports_to_scan]
    results = await asyncio.gather(*tasks)
    return [r for r in results if r is not None]

def scan_port(ip, port):
    """Legacy synchronous scan with banner grabbing (fallback)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex((ip, port))

        if result == 0:
            banner = ""
            try:
                sock.settimeout(3)
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="ignore").strip()
                banner = banner.split("\n")[0][:200]
            except ScanExceptions:
                pass

            sock.close()
            service = PORT_SERVICES.get(port, "Unknown")
            return {"port": port, "service": service, "banner": banner}

        sock.close()
    except ScanExceptions:
        pass
    return None

def get_server_info(url):
    """Get server information from headers"""
    info = {}
    try:
        resp = _get_session().get(url, timeout=10)
        headers = resp.headers

        info["server"] = headers.get("Server", "Unknown")
        info["powered_by"] = headers.get("X-Powered-By", "")
        info["all_headers"] = dict(headers)

        # Detect technologies
        techs = []
        content = resp.text.lower()

        if "wp-content" in content or "wordpress" in content:
            techs.append("WordPress")
        if "joomla" in content:
            techs.append("Joomla")
        if "drupal" in content:
            techs.append("Drupal")
        if "laravel" in resp.headers.get("Set-Cookie", "").lower():
            techs.append("Laravel")
        if "django" in content or "csrfmiddlewaretoken" in content:
            techs.append("Django")
        if "react" in content or "reactroot" in content:
            techs.append("React")
        if "vue" in content or "v-app" in content:
            techs.append("Vue.js")

        info["technologies"] = techs

        # WAF detection
        waf = None
        if "cloudflare" in str(headers).lower():
            waf = "Cloudflare"
        elif "akamai" in str(headers).lower():
            waf = "Akamai"
        elif "sucuri" in str(headers).lower():
            waf = "Sucuri"
        elif "mod_security" in str(headers).lower():
            waf = "ModSecurity"

        info["waf"] = waf

    except ScanExceptions as e:
        log_warning(f"Error getting server info: {e}")

    return info

def check_security_headers(headers):
    """Audit HTTP security headers"""
    results = []

    checks = {
        "X-Frame-Options": {
            "desc": "Clickjacking koruması",
            "good": ["DENY", "SAMEORIGIN"],
        },
        "X-Content-Type-Options": {
            "desc": "MIME sniffing koruması",
            "good": ["nosniff"],
        },
        "X-XSS-Protection": {
            "desc": "XSS filtresi",
            "good": ["1; mode=block", "1"],
        },
        "Strict-Transport-Security": {
            "desc": "HTTPS zorunlu (HSTS)",
            "good": None,  # Any value is good
        },
        "Content-Security-Policy": {
            "desc": "İçerik güvenlik politikası (CSP)",
            "good": None,
        },
        "Referrer-Policy": {
            "desc": "Referer bilgisi kontrolü",
            "good": None,
        },
        "Permissions-Policy": {
            "desc": "Tarayıcı izinleri kontrolü",
            "good": None,
        },
    }

    for header, info in checks.items():
        value = headers.get(header, "")
        if value:
            results.append(
                {
                    "header": header,
                    "value": value[:60],
                    "status": "set",
                    "desc": info["desc"],
                }
            )
        else:
            results.append(
                {
                    "header": header,
                    "value": "MISSING",
                    "status": "missing",
                    "desc": info["desc"],
                }
            )

    return results

def get_ssl_info(hostname, port=443):
    """Get SSL/TLS certificate information"""
    info = {}
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                info["protocol"] = ssock.version()

                if cert:
                    # Subject
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    info["cn"] = subject.get("commonName", "N/A")

                    # Issuer
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    info["issuer"] = issuer.get("organizationName", "N/A")

                    # Dates
                    info["not_before"] = cert.get("notBefore", "N/A")
                    info["not_after"] = cert.get("notAfter", "N/A")

                    # SANs
                    sans = []
                    for type_name, value in cert.get("subjectAltName", ()):
                        if type_name == "DNS":
                            sans.append(value)
                    info["san"] = sans[:5]  # Max 5
                else:
                    info["cn"] = "Could not parse cert"
    except ScanExceptions:
        info["error"] = "SSL connection failed or no SSL"

    return info

def fetch_robots_sitemap(url):
    """Fetch robots.txt and sitemap.xml"""
    results = {}
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    session = _get_session()

    # robots.txt
    try:
        resp = session.get(f"{base}/robots.txt", timeout=5)
        if resp.status_code == 200 and "user-agent" in resp.text.lower():
            lines = resp.text.strip().split("\n")
            disallow = [
                line.strip()
                for line in lines
                if line.strip().lower().startswith("disallow")
            ]
            results["robots"] = disallow[:10]
        else:
            results["robots"] = None
    except ScanExceptions:
        results["robots"] = None

    # sitemap.xml
    try:
        resp = session.get(f"{base}/sitemap.xml", timeout=5)
        if resp.status_code == 200 and "<urlset" in resp.text.lower():
            import re

            urls = re.findall(r"<loc>(.*?)</loc>", resp.text)
            results["sitemap"] = urls[:10]
        else:
            results["sitemap"] = None
    except ScanExceptions:
        results["sitemap"] = None

    return results

def get_dns_records(hostname):
    """Get DNS records"""
    records = {}
    try:
        # A record
        ips = socket.gethostbyname_ex(hostname)
        records["A"] = ips[2]

        # Try reverse DNS (best-effort, many hosts lack PTR)
        try:
            rdns = socket.gethostbyaddr(ips[2][0])
            records["PTR"] = rdns[0]
        except (OSError, socket.herror, socket.gaierror):
            pass

    except (OSError, socket.herror, socket.gaierror):
        pass

    return records

def scan_subdomains(domain):
    """
    Subdomain enumeration via Certificate Transparency logs (crt.sh).
    Finds subdomains (e.g. dev.target.com) that were issued SSL certificates.
    """
    if not domain or domain.replace(".", "").isnumeric():
        log_warning("Subdomain scan skipped (target is an IP address)")
        return []

    print(
        f"\n{Colors.BOLD}{Colors.CYAN}──── SUBDOMAIN ENUMERATION (crt.sh) ────{Colors.END}"
    )
    log_info(f"Querying crt.sh for {domain}...")

    url = f"https://crt.sh/?q=%.{domain}&output=json"
    subdomains = set()

    try:
        resp = _get_session().get(url, timeout=20)
        if resp.status_code == 200:
            data = resp.json()
            for cert in data:
                name_value = cert.get("name_value", "")
                if name_value:
                    # name_value can contain multiple domains separated by newlines
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        if name.endswith(domain) and name != domain:
                            # Remove wildcard prefix if present
                            if name.startswith("*."):
                                name = name[2:]
                            subdomains.add(name)

            if subdomains:
                log_success(
                    f"Found {len(subdomains)} unique subdomains via certificates:"
                )
                # Sort for clean output
                for sub in sorted(list(subdomains)):
                    print(f"  {Colors.GREEN}→ {sub}{Colors.END}")
            else:
                log_info("No subdomains found in certificate logs.")
        else:
            log_warning(f"crt.sh returned status {resp.status_code}")
    except ScanExceptions as e:
        log_error(f"Error querying crt.sh: {e}")

    print(f"{Colors.BOLD}{'=' * 50}{Colors.END}\n")
    return list(subdomains)

def run_recon(url, deep=False):
    """Run recon on target. If deep=True, run extended checks."""
    parsed = urlparse(url)
    hostname = parsed.netloc.split(":")[0]

    print(f"\n{Colors.BOLD}{'=' * 50}{Colors.END}")
    print(f"{Colors.BOLD}[*] TARGET RECONNAISSANCE{Colors.END}")
    print(f"{'=' * 50}")

    # Resolve IP
    try:
        ip = socket.gethostbyname(hostname)
        log_info(f"IP Address: {ip}")
    except ScanExceptions:
        ip = hostname
        log_warning(f"Could not resolve IP for {hostname}")

    # Get server info
    log_info("Gathering server information...")
    info = get_server_info(url)

    log_info(f"Server: {info.get('server', 'Unknown')}")
    if info.get("powered_by"):
        log_info(f"Powered By: {info['powered_by']}")
    if info.get("technologies"):
        log_info(f"Technologies: {', '.join(info['technologies'])}")
    if info.get("waf"):
        log_warning(f"WAF Detected: {info['waf']}")

    open_ports = []
    if deep:
        ports_to_scan = EXTENDED_PORTS
        log_info(
            f"Scanning extended ports: {len(ports_to_scan)} ports (Async/Fast)..."
        )

        try:
            # Use a high concurrency value to make it "RustScan" speed
            open_ports = asyncio.run(
                run_async_scanner(ip, ports_to_scan, concurrency=2000, timeout=1.0)
            )
        except ScanExceptions as e:
            log_warning(f"Async port scan failed ({e}), falling back to slow scan...")
            with ThreadPoolExecutor(max_workers=50) as executor:
                futures = {
                    executor.submit(scan_port, ip, port): port for port in ports_to_scan
                }
                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        open_ports.append(result)

        # Sort and display
        open_ports.sort(key=lambda x: x["port"])
        for p in open_ports:
            banner_str = f" | {p['banner']}" if p.get("banner") else ""
            log_success(f"Port {p['port']}: OPEN ({p['service']}){banner_str}")

            # Warn about dangerous ports
            if p["port"] in DANGEROUS_PORTS:
                log_warning(f"  ⚠ {DANGEROUS_PORTS[p['port']]}")

        if not open_ports:
            log_info("No open ports found")
    else:
        log_info("Light recon only: skipping port scan. Use --recon for deep recon.")

    # ──── DEEP RECON ────
    if deep:
        print(f"\n{Colors.BOLD}{Colors.CYAN}──── DEEP RECON ────{Colors.END}")

        # 1. Security Headers
        print(f"\n{Colors.BOLD}[*] Security Headers Audit{Colors.END}")
        headers = info.get("all_headers", {})
        sec_results = check_security_headers(headers)
        missing_count = 0
        for r in sec_results:
            if r["status"] == "set":
                print(f"  {Colors.GREEN}✅ {r['header']}: {r['value']}{Colors.END}")
            else:
                missing_count += 1
                print(
                    f"  {Colors.RED}❌ {r['header']}: EKSİK — {r['desc']}{Colors.END}"
                )
        if missing_count > 0:
            log_warning(f"{missing_count}/{len(sec_results)} güvenlik header'ı eksik!")

        # 2. SSL/TLS Info (if HTTPS or 443 open)
        has_ssl = any(p["port"] == 443 for p in open_ports)
        if parsed.scheme == "https" or has_ssl:
            print(f"\n{Colors.BOLD}[*] SSL/TLS Certificate{Colors.END}")
            ssl_port = 443
            ssl_info = get_ssl_info(hostname, ssl_port)
            if "error" in ssl_info:
                log_warning(f"  SSL: {ssl_info['error']}")
            else:
                log_info(f"  Protocol: {ssl_info.get('protocol', 'N/A')}")
                log_info(f"  CN: {ssl_info.get('cn', 'N/A')}")
                log_info(f"  Issuer: {ssl_info.get('issuer', 'N/A')}")
                log_info(f"  Valid Until: {ssl_info.get('not_after', 'N/A')}")
                if ssl_info.get("san"):
                    log_info(f"  SANs: {', '.join(ssl_info['san'])}")

        # 3. robots.txt & sitemap
        print(f"\n{Colors.BOLD}[*] robots.txt & sitemap.xml{Colors.END}")
        rs = fetch_robots_sitemap(url)
        if rs.get("robots"):
            log_success(f"robots.txt found ({len(rs['robots'])} rules):")
            for rule in rs["robots"][:5]:
                print(f"    {Colors.GREY}{rule}{Colors.END}")
        else:
            log_info("robots.txt: Not found or empty")

        if rs.get("sitemap"):
            log_success(f"sitemap.xml found ({len(rs['sitemap'])} URLs):")
            for s_url in rs["sitemap"][:3]:
                print(f"    {Colors.GREY}{s_url}{Colors.END}")
        else:
            log_info("sitemap.xml: Not found")

        # 4. DNS records (only for domains, not IPs)
        is_ip = all(c.isdigit() or c == "." for c in hostname)
        if not is_ip:
            print(f"\n{Colors.BOLD}[*] DNS Records{Colors.END}")
            dns = get_dns_records(hostname)
            if dns.get("A"):
                log_info(f"  A Records: {', '.join(dns['A'])}")
            if dns.get("PTR"):
                log_info(f"  PTR (Reverse): {dns['PTR']}")
            if not dns:
                log_info("  No DNS records found")

        # 5. Interesting headers
        print(f"\n{Colors.BOLD}[*] All Response Headers{Colors.END}")
        for h_name, h_val in headers.items():
            color = Colors.YELLOW if h_name.lower().startswith("x-") else Colors.GREY
            print(f"    {color}{h_name}: {str(h_val)[:70]}{Colors.END}")

        print(f"\n{Colors.BOLD}{Colors.CYAN}──── DEEP RECON COMPLETE ────{Colors.END}")

    print(f"{Colors.BOLD}{'=' * 50}{Colors.END}\n")

    result = {"ip": ip, "info": info, "open_ports": open_ports}
    headers = info.get("all_headers", {})
    sec_results = check_security_headers(headers)
    result["missing_headers"] = sum(
        1 for r in sec_results if r["status"] == "missing"
    )
    result["total_headers"] = len(sec_results)

    return result
