"""
cyberm4fia-scanner — SSH/FTP Brute-Force Module
Tests default and common credentials against SSH and FTP services.
"""

import ftplib
import socket
from datetime import datetime

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import ScanExceptions

# Default credentials to test (common admin/default pairs)
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("root", "root"),
    ("root", "toor"),
    ("root", "password"),
    ("root", "123456"),
    ("root", "admin"),
    ("test", "test"),
    ("user", "user"),
    ("user", "password"),
    ("guest", "guest"),
    ("guest", ""),
    ("administrator", "administrator"),
    ("administrator", "password"),
    ("ftp", "ftp"),
    ("ftp", ""),
    ("anonymous", ""),
    ("anonymous", "anonymous"),
    ("pi", "raspberry"),
    ("ubuntu", "ubuntu"),
    ("oracle", "oracle"),
    ("postgres", "postgres"),
    ("mysql", "mysql"),
    ("tomcat", "tomcat"),
    ("tomcat", "s3cret"),
    ("jenkins", "jenkins"),
    ("nagios", "nagios"),
    ("cisco", "cisco"),
    ("admin", ""),
    ("root", ""),
    ("daemon", ""),
    ("bin", ""),
    ("www-data", "www-data"),
    ("backup", "backup"),
    ("operator", "operator"),
    ("deploy", "deploy"),
    ("vagrant", "vagrant"),
    ("ansible", "ansible"),
    ("ec2-user", ""),
    ("www", "www"),
    ("svn", "svn"),
    ("git", "git"),
    ("ftpuser", "ftpuser"),
    ("ftpuser", "ftp123"),
    ("webmaster", "webmaster"),
    ("support", "support"),
]


class BruteForcer:
    """Credential brute-force tester for SSH and FTP services."""

    def __init__(self, timeout=5, max_attempts=50):
        self.timeout = timeout
        self.max_attempts = max_attempts

    def brute_ftp(self, host, port=21, creds=None):
        """
        Test FTP credentials.
        
        Args:
            host: Target hostname/IP.
            port: FTP port.
            creds: List of (user, pass) tuples. Defaults to DEFAULT_CREDS.
            
        Returns:
            List of successful credential dicts.
        """
        creds = creds or DEFAULT_CREDS
        results = []
        tested = 0

        log_info(f"Testing FTP credentials on {host}:{port}...")

        for username, password in creds:
            if tested >= self.max_attempts:
                log_warning(f"Max attempt limit ({self.max_attempts}) reached")
                break

            tested += 1
            try:
                ftp = ftplib.FTP()
                ftp.connect(host, port, timeout=self.timeout)
                ftp.login(username, password)

                # Success!
                log_success(f"FTP login success: {username}:{password or '(empty)'}")

                # Try to list directory for evidence
                dir_listing = []
                try:
                    ftp.dir(dir_listing.append)
                except Exception:  # ftplib errors during listing
                    pass

                results.append({
                    "service": "ftp",
                    "host": host,
                    "port": port,
                    "username": username,
                    "password": password,
                    "evidence": f"Directory listing: {len(dir_listing)} entries",
                    "dir_sample": dir_listing[:5],
                    "timestamp": datetime.now().isoformat(),
                })

                try:
                    ftp.quit()
                except Exception:  # ftplib errors during disconnect
                    pass

            except ftplib.error_perm:
                # Login failed — expected
                pass
            except (socket.timeout, ConnectionRefusedError, OSError):
                log_warning(f"FTP connection failed to {host}:{port}")
                break
            except ScanExceptions:
                pass

        if not results:
            log_info(f"No default FTP credentials found ({tested} tested)")

        return results

    def brute_ssh(self, host, port=22, creds=None):
        """
        Test SSH credentials (requires paramiko).
        
        Args:
            host: Target hostname/IP.
            port: SSH port.
            creds: List of (user, pass) tuples.
            
        Returns:
            List of successful credential dicts.
        """
        try:
            import paramiko
        except ImportError:
            log_warning("paramiko not installed — SSH brute-force skipped.")
            log_info("Install with: pip install paramiko")
            return []

        creds = creds or DEFAULT_CREDS
        results = []
        tested = 0

        log_info(f"Testing SSH credentials on {host}:{port}...")

        for username, password in creds:
            if tested >= self.max_attempts:
                log_warning(f"Max attempt limit ({self.max_attempts}) reached")
                break

            if not password:  # Skip empty password for SSH
                continue

            tested += 1
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

            try:
                client.connect(
                    host, port=port,
                    username=username, password=password,
                    timeout=self.timeout,
                    allow_agent=False, look_for_keys=False,
                )

                # Success!
                log_success(f"SSH login success: {username}:{password}")

                # Get system info for evidence
                evidence = ""
                try:
                    _, stdout, _ = client.exec_command("whoami && hostname && uname -a", timeout=5)
                    evidence = stdout.read().decode("utf-8", errors="replace").strip()
                except Exception:  # paramiko/SSH errors + unpacking issues
                    pass

                results.append({
                    "service": "ssh",
                    "host": host,
                    "port": port,
                    "username": username,
                    "password": password,
                    "evidence": evidence,
                    "timestamp": datetime.now().isoformat(),
                })

                client.close()

            except paramiko.AuthenticationException:
                # Login failed — expected
                pass
            except (paramiko.SSHException, socket.timeout, ConnectionRefusedError, OSError):
                log_warning(f"SSH connection failed to {host}:{port}")
                break
            except ScanExceptions:
                pass
            finally:
                client.close()

        if not results:
            log_info(f"No default SSH credentials found ({tested} tested)")

        return results

    def auto_brute(self, host, open_ports=None):
        """
        Automatically brute-force supported services based on open ports.
        
        Args:
            host: Target hostname/IP.
            open_ports: List of open port numbers. If None, tests default ports.
            
        Returns:
            List of all successful credential findings.
        """
        if open_ports is None:
            open_ports = [21, 22]

        all_results = []

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'═' * 50}")
        print(f"  🔓 Credential Brute-Force Scanner")
        print(f"{'═' * 50}{Colors.END}")
        print(f"  Target: {host}")
        print(f"  Ports:  {open_ports}")
        print()

        if 21 in open_ports:
            results = self.brute_ftp(host)
            all_results.extend(results)

        if 22 in open_ports:
            results = self.brute_ssh(host)
            all_results.extend(results)

        # Summary
        if all_results:
            print(f"\n{Colors.BOLD}{Colors.RED}⚠️  FOUND {len(all_results)} DEFAULT CREDENTIAL(S)!{Colors.END}")
            for r in all_results:
                print(f"  🔑 {r['service'].upper()} {r['host']}:{r['port']} → "
                      f"{r['username']}:{r['password'] or '(empty)'}")
        else:
            log_info("No default credentials found.")

        return all_results

    def results_to_findings(self, results):
        """Convert brute-force results to vulnerability finding dicts."""
        findings = []
        for r in results:
            findings.append({
                "type": "Default_Credentials",
                "url": f"{r['service']}://{r['host']}:{r['port']}",
                "severity": "critical",
                "param": "credentials",
                "payload": f"{r['username']}:{r['password'] or '(empty)'}",
                "evidence": r.get("evidence", "Login successful"),
                "description": (
                    f"Default {r['service'].upper()} credentials found: "
                    f"{r['username']}:{r['password'] or '(empty)'}. "
                    f"This allows unauthorized access to the {r['service'].upper()} service."
                ),
                "service": r["service"],
                "confidence": "confirmed",
                "exploit_data": {
                    "username": r["username"],
                    "password": r["password"],
                    "evidence": r.get("evidence", ""),
                },
            })
        return findings
