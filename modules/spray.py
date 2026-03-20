"""
cyberm4fia-scanner - Credential Sprayer
Default credential testing for SSH, FTP, MySQL, PostgreSQL, Redis, MongoDB
Integrates with port scanner results
"""

import socket

from utils.colors import log_info, log_success, log_warning
from utils.request import ScanExceptions

# ─────────────────────────────────────────────────────
# Default Credentials Database
# ─────────────────────────────────────────────────────
DEFAULT_CREDS = {
    "ftp": {
        "port": 21,
        "credentials": [
            ("anonymous", ""),
            ("anonymous", "anonymous@"),
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("root", "root"),
            ("root", "toor"),
            ("ftp", "ftp"),
            ("user", "user"),
            ("test", "test"),
        ],
    },
    "ssh": {
        "port": 22,
        "credentials": [
            ("root", "root"),
            ("root", "toor"),
            ("root", "password"),
            ("root", "123456"),
            ("admin", "admin"),
            ("admin", "password"),
            ("admin", "123456"),
            ("ubuntu", "ubuntu"),
            ("user", "user"),
            ("test", "test"),
            ("pi", "raspberry"),
            ("vagrant", "vagrant"),
            ("deploy", "deploy"),
            ("ec2-user", ""),
        ],
    },
    "mysql": {
        "port": 3306,
        "credentials": [
            ("root", ""),
            ("root", "root"),
            ("root", "password"),
            ("root", "mysql"),
            ("root", "123456"),
            ("admin", "admin"),
            ("mysql", "mysql"),
            ("dbadmin", "dbadmin"),
            ("test", "test"),
            ("root", "toor"),
        ],
    },
    "postgresql": {
        "port": 5432,
        "credentials": [
            ("postgres", "postgres"),
            ("postgres", "password"),
            ("postgres", ""),
            ("admin", "admin"),
            ("root", "root"),
            ("pgsql", "pgsql"),
        ],
    },
    "redis": {
        "port": 6379,
        "credentials": [
            ("", ""),  # No auth
            ("", "redis"),
            ("", "password"),
            ("", "admin"),
            ("default", ""),
        ],
    },
    "mongodb": {
        "port": 27017,
        "credentials": [
            ("", ""),  # No auth
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "password"),
            ("mongo", "mongo"),
        ],
    },
    "mssql": {
        "port": 1433,
        "credentials": [
            ("sa", ""),
            ("sa", "sa"),
            ("sa", "password"),
            ("sa", "Password1"),
            ("sa", "123456"),
            ("admin", "admin"),
        ],
    },
}

def try_ftp(host, port, username, password, timeout=5):
    """Try FTP login."""
    try:
        import ftplib

        ftp = ftplib.FTP()
        ftp.connect(host, port, timeout=timeout)
        ftp.login(username, password)
        ftp.quit()
        return True
    except ScanExceptions:
        return False

def try_ssh(host, port, username, password, timeout=5):
    """Try SSH login using paramiko if available, else socket banner."""
    try:
        import paramiko

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            port=port,
            username=username,
            password=password,
            timeout=timeout,
            allow_agent=False,
            look_for_keys=False,
        )
        client.close()
        return True
    except ImportError:
        # paramiko not installed, skip SSH
        log_warning(
            "paramiko not installed. SSH brute force skipped. (pip install paramiko)"
        )
        return False
    except ScanExceptions:
        return False

def try_mysql(host, port, username, password, timeout=5):
    """Try MySQL login."""
    try:
        import pymysql

        conn = pymysql.connect(
            host=host,
            port=port,
            user=username,
            password=password,
            connect_timeout=timeout,
        )
        conn.close()
        return True
    except ImportError:
        log_warning(
            "pymysql not installed. MySQL brute force skipped. (pip install pymysql)"
        )
        return False
    except ScanExceptions:
        return False

def try_redis(host, port, username, password, timeout=5):
    """Try Redis connection."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))

        if password:
            sock.sendall(f"AUTH {password}\r\n".encode())
        else:
            sock.sendall(b"PING\r\n")

        resp = sock.recv(1024).decode("utf-8", errors="ignore")
        sock.close()

        if "+PONG" in resp or "+OK" in resp:
            return True
    except ScanExceptions:
        pass
    return False

def try_mongodb(host, port, username, password, timeout=5):
    """Try MongoDB connection (no auth check)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        if result == 0:
            # If connection succeeds without auth, it's open
            if not username and not password:
                sock.close()
                return True
        sock.close()
    except ScanExceptions:
        pass
    return False

# Map service names to login functions
LOGIN_FUNCTIONS = {
    "ftp": try_ftp,
    "ssh": try_ssh,
    "mysql": try_mysql,
    "redis": try_redis,
    "mongodb": try_mongodb,
}

def spray_service(host, service, port=None, timeout=5):
    """Spray default credentials against a specific service."""
    if service not in DEFAULT_CREDS:
        return []

    config = DEFAULT_CREDS[service]
    actual_port = port or config["port"]
    login_fn = LOGIN_FUNCTIONS.get(service)

    if not login_fn:
        return []

    findings = []

    for username, password in config["credentials"]:
        try:
            success = login_fn(host, actual_port, username, password, timeout)
            if success:
                cred_display = (
                    f"{username}:{password}" if password else f"{username}:(empty)"
                )
                findings.append(
                    {
                        "type": "Default Credentials",
                        "service": service.upper(),
                        "host": host,
                        "port": actual_port,
                        "username": username,
                        "password": password,
                        "severity": "CRITICAL",
                        "description": (
                            f"Default credentials work on {service.upper()} "
                            f"({host}:{actual_port}): {cred_display}"
                        ),
                    }
                )
                log_success(
                    f"[CRITICAL] {service.upper()} login: "
                    f"{cred_display} @ {host}:{actual_port}"
                )
                return findings  # One valid cred is enough
        except ScanExceptions:
            pass

    return findings

def scan_spray(host, open_ports=None, timeout=5):
    """
    Main credential sprayer entry point.
    open_ports: list of dicts with 'port' and 'service' keys from port scanner
    """
    log_info(f"Starting Credential Sprayer on {host}...")
    all_findings = []

    # Map port numbers to services
    port_to_service = {
        21: "ftp",
        22: "ssh",
        3306: "mysql",
        5432: "postgresql",
        6379: "redis",
        27017: "mongodb",
        1433: "mssql",
    }

    if open_ports:
        # Only spray services that are actually open
        for port_info in open_ports:
            port_num = port_info.get("port", 0)
            service = port_to_service.get(port_num)
            if service:
                log_info(f"Spraying {service.upper()} on port {port_num}...")
                results = spray_service(host, service, port_num, timeout)
                all_findings.extend(results)
    else:
        # No port info — try common services
        for service in ["ftp", "ssh", "mysql", "redis", "mongodb"]:
            port = DEFAULT_CREDS[service]["port"]
            log_info(f"Trying {service.upper()} on default port {port}...")
            results = spray_service(host, service, port, timeout)
            all_findings.extend(results)

    log_success(f"Credential spray complete. Found {len(all_findings)} valid login(s).")
    return all_findings
