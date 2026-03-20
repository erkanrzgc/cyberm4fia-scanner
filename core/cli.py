"""
CLI argument parsing and basic input helpers for cyberm4fia-scanner.
Extracted from scanner.py to keep the main entry-point lean.
"""

import sys
import argparse

from utils.colors import console
from rich.markup import escape
from core.scan_options import add_parser_arguments


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="cyberm4fia-scanner")
    add_parser_arguments(parser)
    effective_argv = list(sys.argv[1:] if argv is None else argv)
    args = parser.parse_args(effective_argv)
    provided_dests = set()
    for token in effective_argv:
        option_token = token.split("=", 1)[0]
        action = parser._option_string_actions.get(option_token)
        if action:
            provided_dests.add(action.dest)
    setattr(args, "_provided_dests", provided_dests)
    return args


def get_input(prompt, default=""):
    """Get user input with default value using rich Console to record it"""
    try:
        val = console.input(f"[bold white]{escape(prompt)}[/] ").strip()
        return val if val else default
    except EOFError:
        return default
