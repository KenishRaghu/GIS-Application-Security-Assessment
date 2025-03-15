"""
Trigger and orchestrate vulnerability scans for the GIS application.
Designed to work with BurpSuite (manual proxy or Burp Suite Enterprise API).
"""

import argparse
import sys


def run_scan(target_url: str, config_path: str = None) -> int:
    """
    Run vulnerability scan against target.
    In practice: start Burp scan via API or export results for processing by vulnerability_scanner.py.
    """
    print(f"Scan target: {target_url}")
    if config_path:
        print(f"Config: {config_path}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Run GIS application vulnerability scan")
    parser.add_argument("target", help="Target GIS application URL")
    parser.add_argument("-c", "--config", help="Scan configuration path")
    args = parser.parse_args()
    return run_scan(args.target, args.config)


if __name__ == "__main__":
    sys.exit(main())
