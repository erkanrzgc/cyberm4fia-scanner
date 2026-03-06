"""
Example custom tamper script.

Place .py files in this directory. Each file must have a tamper(payload) function.

Usage:
    python3 scanner.py -u https://target.com --xss --tamper example_reverse

File: payloads/tampers/example_reverse.py
"""


def tamper(payload: str) -> str:
    """Reverse the payload string — just an example, not practical."""
    return payload[::-1]
