"""
Manual API endpoint testing.
Find map/data APIs, test unauthenticated access, auth bypass.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import requests
except ImportError:
    requests = None

# Common GIS REST path patterns
GIS_API_PATTERNS = [
    "/rest/services",
    "/arcgis/rest/services",
    "/geoserver/rest",
    "/api/v1",
    "/api/v2",
    "/api/layers",
    "/api/maps",
    "/api/projects",
]


def probe_api_unauthenticated(base_url: str, paths: list[str] | None = None) -> list[dict]:
    """
    Probe API endpoints without auth. Returns list of {url, status, has_data}.
    """
    paths = paths or GIS_API_PATTERNS
    results = []
    ses = requests.Session() if requests else None
    if not ses:
        return results

    base = base_url.rstrip("/")
    for p in paths:
        url = base + p if p.startswith("/") else base + "/" + p
        try:
            r = ses.get(url, timeout=10)
            has_data = False
            if r.status_code == 200:
                try:
                    data = r.json()
                    has_data = bool(data)
                except Exception:
                    has_data = len(r.content) > 100
            results.append({
                "url": url,
                "status": r.status_code,
                "has_data": has_data,
                "finding": "Unauthenticated API access" if (r.status_code == 200 and has_data) else None,
            })
        except Exception as e:
            results.append({"url": url, "error": str(e)})

    return results


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe GIS API endpoints for unauthenticated access")
    parser.add_argument("url", help="Base URL of GIS application")
    parser.add_argument("-p", "--paths", nargs="+", help="Additional paths to probe")
    args = parser.parse_args()

    if not requests:
        print("Install requests: pip install requests")
        return 1

    paths = list(GIS_API_PATTERNS)
    if args.paths:
        paths.extend(args.paths)

    results = probe_api_unauthenticated(args.url, paths)
    for r in results:
        if "error" in r:
            print(f"{r['url']}: Error - {r['error']}")
        else:
            flag = " [UNAUTH ACCESS?]" if r.get("finding") else ""
            print(f"{r['url']}: {r['status']} (data={r.get('has_data')}){flag}")

    findings = [x for x in results if x.get("finding")]
    if findings:
        print(f"\n{len(findings)} endpoints may allow unauthenticated access. Verify manually.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
