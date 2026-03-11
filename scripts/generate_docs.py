#!/usr/bin/env python3
"""
Update generated markdown sections from scanner metadata.
"""

import os
import sys


ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from core.documentation import sync_generated_docs  # noqa: E402


def main():
    updated_paths = sync_generated_docs()
    for path in updated_paths:
        print(f"Updated {path.relative_to(ROOT_DIR)}")


if __name__ == "__main__":
    main()
