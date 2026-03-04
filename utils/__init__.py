"""
cyberm4fia-scanner Utilities
"""

from .colors import (
    Colors, print_gradient_banner,
    log_info, log_success, log_warning, log_error, log_vuln,
    set_log_file, LOG_FILE
)

from .request import (
    Config, Stats, smart_request, set_cookie, set_proxy,
    _get_session, _global_headers, lock, USER_AGENTS
)
