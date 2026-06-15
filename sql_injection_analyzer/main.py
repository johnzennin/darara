#!/usr/bin/env python3
"""
SQL Injection Security Analysis and Audit Platform
Main Entry Point

SECURITY NOTE: This is a passive analysis tool only.
No exploits are generated. No network requests are made.
Designed for authorized penetration test log analysis only.
"""

import sys
import os

# Add the package to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def main():
    """Launch the application."""
    # Direct import for standalone execution
    from ui.main_window import main as ui_main
    ui_main()


if __name__ == "__main__":
    main()
