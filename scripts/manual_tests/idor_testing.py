"""
Manual IDOR (Insecure Direct Object Reference) testing.
Tests: layer ID, project ID, resource ID enumeration.
"""

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import requests
except ImportError:
    requests = None


def probe_idor(
    base_url: str,
    id_param: str,
    id_values: list[int | str],
    headers: dict | None = None,
) -> list[dict]:
    """
    Probe URLs with different IDs. Returns list of {id, status, accessible}.
    """
    findings = []
    ses = requests.Session() if requests else None
    if not ses:
        return findings

    ses.headers.update(headers or {})

    for vid in id_values:
        # Support /layer/123 and /layer?id=123
        if "?" in base_url:
            url = f"{base_url}&{id_param}={vid}"
        else:
            sep = "?" if "?" not in base_url else "&"
            url = f"{base_url}{sep}{id_param}={vid}"

        try:
            r = ses.get(url, timeout=10)
            accessible = r.status_code == 200
            # Heuristic: 403/404 = no access, 200 might mean access
            if r.status_code == 200 and len(r.content) > 100:
                accessible = True
            findings.append({
                "id": vid,
                "status": r.status_code,
                "accessible": accessible,
                "url": url,
            })
        except Exception as e:
            findings.append({"id": vid, "error": str(e)})

    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe IDOR on GIS endpoints")
    parser.add_argument("url", help="Base URL (e.g. https://app/layer or https://app/api/project)")
    parser.add_argument("-p", "--param", default="id", help="ID parameter name")
    parser.add_argument("-i", "--ids", default="1,2,3,100,456", help="Comma-separated IDs to try")
    args = parser.parse_args()

    if not requests:
        print("Install requests: pip install requests")
        return 1

    ids = []
    for x in args.ids.split(","):
        x = x.strip()
        try:
            ids.append(int(x))
        except ValueError:
            ids.append(x)

    results = probe_idor(args.url, args.param, ids)
    for r in results:
        if "error" in r:
            print(f"ID {r['id']}: Error - {r['error']}")
        else:
            acc = "ACCESSIBLE" if r.get("accessible") else "blocked"
            print(f"ID {r['id']}: {r['status']} - {acc}")

    accessible = [x for x in results if x.get("accessible")]
    if accessible:
        print(f"\nPossible IDOR: {len(accessible)} IDs returned data. Verify manually.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
