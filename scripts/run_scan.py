"""
Orchestrate vulnerability scans for the GIS application.
Works with BurpSuite (manual proxy or Burp Suite Pro/Enterprise API).
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

# Optional: Burp Suite Pro/Enterprise REST API base (set in config or env)
BURP_API_BASE = "http://127.0.0.1:1337"


def load_config(config_path: str | None) -> dict:
    """Load scan configuration from JSON file."""
    if not config_path:
        return {}
    p = Path(config_path)
    if not p.exists():
        return {}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def run_burp_api_scan(target_url: str, config: dict) -> dict | None:
    """
    Start a scan via Burp Suite Pro/Enterprise REST API.
    Returns scan ID or None if API is not available.
    """
    try:
        import requests
    except ImportError:
        return None

    api_key = config.get("burp_api_key") or config.get("api_key")
    if not api_key:
        return None

    base = config.get("burp_api_base", BURP_API_BASE)
    url = f"{base.rstrip('/')}/v0.1/scan"
    payload = {
        "urls": [target_url],
        "scan_configurations": config.get("scan_configurations", []),
        "scope": config.get("scope", {}),
    }
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}

    try:
        r = requests.post(url, json=payload, headers=headers, timeout=30)
        if r.status_code in (200, 201, 202):
            return r.json()
    except Exception:
        pass
    return None


def run_recon_and_print(target_url: str) -> None:
    """Run reconnaissance and print guidance."""
    try:
        from reconnaissance import run_reconnaissance, export_attack_surface
        surface = run_reconnaissance(target_url)
        out_dir = Path(__file__).parent.parent / "results"
        out_path = out_dir / "attack_surface.json"
        export_attack_surface(surface, out_path)
        print(f"Recon complete. Attack surface saved to {out_path}")
    except Exception as e:
        print(f"Recon note: {e}")


def run_scan(target_url: str, config_path: str | None = None) -> int:
    """
    Run vulnerability scan against target.
    If Burp API is configured, triggers scan. Otherwise prints manual steps.
    """
    config = load_config(config_path or "")
    result = run_burp_api_scan(target_url, config)

    if result:
        scan_id = result.get("task_id") or result.get("id") or "unknown"
        print(f"Scan started: {scan_id}")
        print("Poll Burp dashboard for completion, then export results and run:")
        print(f"  python vulnerability_scanner.py results/burp_scan.json")
        return 0

    # Manual workflow
    print("Burp API not configured or unavailable. Use manual workflow:")
    print("1. Configure Burp proxy (see docs/burpsuite-config.md)")
    print("2. Browse the app through Burp to populate target scope")
    print("3. Run Burp Scanner on your target URL(s)")
    print("4. Export scan results as JSON")
    print("5. Run: python vulnerability_scanner.py <path-to-export.json>")
    print()
    run_recon_and_print(target_url)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run GIS application vulnerability scan")
    parser.add_argument("target", help="Target GIS application URL")
    parser.add_argument("-c", "--config", help="Scan configuration JSON path")
    parser.add_argument("--depth", type=int, default=5, help="Scan depth (passed to config)")
    parser.add_argument("--tests", nargs="+", help="Specific test names (if supported)")
    args = parser.parse_args()

    config = load_config(args.config) if args.config else {}
    if args.depth:
        config.setdefault("scan_depth", args.depth)
    if args.tests:
        config.setdefault("scan_tests", args.tests)

    return run_scan(args.target, args.config if args.config else None)


if __name__ == "__main__":
    sys.exit(main())
