"""
cyberm4fia-scanner - Color and Logging Utilities
"""


class Colors:
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    GREY = "\033[90m"
    BOLD = "\033[1m"
    END = "\033[0m"


# Quiet mode: suppress info messages, only show vulns/errors
QUIET_MODE = False


def set_quiet(enabled=True):
    """Enable/disable quiet mode"""
    global QUIET_MODE
    QUIET_MODE = enabled


def print_gradient_banner():
    """Print the scanner banner with gradient colors"""
    if QUIET_MODE:
        return
    banner = r"""
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗██╗  ██╗███████╗██╗ █████╗ 
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██║  ██║██╔════╝██║██╔══██╗
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║███████║█████╗  ██║███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║╚════██║██╔══╝  ██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║     ██║██║     ██║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝╚═╝  ╚═╝
"""
    lines = banner.strip().split("\n")
    start, end = (230, 230, 230), (40, 40, 40)
    for i, line in enumerate(lines):
        ratio = i / max(len(lines) - 1, 1)
        r, g, b = [int(start[j] + (end[j] - start[j]) * ratio) for j in range(3)]
        print(f"\033[38;2;{r};{g};{b}m{line}\033[0m")
    print(f"\033[38;2;100;100;100m{'─' * 80}\033[0m\n")


# Logging functions
LOG_FILE = None


def set_log_file(filepath):
    """Set the log file path"""
    global LOG_FILE
    LOG_FILE = filepath


def _write_log(level, msg):
    """Write message to log file"""
    if LOG_FILE:
        try:
            with open(LOG_FILE, "a") as f:
                f.write(f"[{level}] {msg}\n")
        except Exception:
            pass


def log_info(msg):
    if not QUIET_MODE:
        print(f"{Colors.WHITE}{Colors.BOLD}[*]{Colors.END} {msg}")
    _write_log("INFO", msg)


def log_success(msg):
    print(f"{Colors.GREEN}[+]{Colors.END} {msg}")
    _write_log("SUCCESS", msg)


def log_warning(msg):
    print(f"{Colors.YELLOW}[!]{Colors.END} {msg}")
    _write_log("WARNING", msg)


def log_error(msg):
    print(f"{Colors.RED}[-]{Colors.END} {msg}")
    _write_log("ERROR", msg)


def log_vuln(msg):
    print(f"{Colors.RED}{Colors.BOLD}[!!!]{Colors.END} {Colors.RED}{msg}{Colors.END}")
    _write_log("VULN", msg)
