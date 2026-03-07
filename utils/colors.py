"""
cyberm4fia-scanner - Color and Logging Utilities
"""

from rich.console import Console

console = Console(record=True)

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
        hex_color = f"#{r:02x}{g:02x}{b:02x}"
        console.print(f"[{hex_color}]{line}[/]")
    console.print(f"[#646464]{'─' * 80}[/]\n")


# Logging functions
LOG_FILE = None


def set_log_file(filepath):
    """Set the log file path"""
    global LOG_FILE
    LOG_FILE = filepath


def save_console_log():
    """Export recorded console output to log file"""
    if LOG_FILE:
        import re
        try:
            with open(LOG_FILE, "w", encoding="utf-8") as f:
                raw_text = console.export_text(clear=False)
                clean_text = re.sub(r'\x1b\[[0-9;]*m', '', raw_text)
                f.write(clean_text)
        except Exception:
            pass

def _write_log(level, msg):
    """Write message to log file (Deprecated, using save_console_log at end)"""
    pass


def log_info(msg):
    if not QUIET_MODE:
        console.print(f"[white bold][*][/] {msg}")

def log_success(msg):
    console.print(f"[green][+][/] {msg}")

def log_warning(msg):
    console.print(f"[yellow][!][/] {msg}")

def log_error(msg):
    console.print(f"[red][-][/] {msg}")

def log_vuln(msg):
    console.print(f"[red bold][!!!][/] [red]{msg}[/]")
