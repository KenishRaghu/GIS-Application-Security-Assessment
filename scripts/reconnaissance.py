"""
Reconnaissance and attack surface mapping for GIS applications.
Maps URLs, APIs, map layers, features, and authentication methods.
"""

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    requests = None


@dataclass
class AuthMethod:
    """Discovered authentication mechanism."""
    type: str  # username_password, ldap, ad, sso, oauth, api_key
    location: str
    notes: str = ""


@dataclass
class Endpoint:
    """Discovered URL or API endpoint."""
    url: str
    method: str = "GET"
    category: str = "unknown"  # page, api, map_layer, static, admin
    requires_auth: bool = False
    notes: str = ""


@dataclass
class AttackSurface:
    """Collected reconnaissance data."""
    base_url: str
    urls: list[Endpoint] = field(default_factory=list)
    api_endpoints: list[Endpoint] = field(default_factory=list)
    map_layers: list[Endpoint] = field(default_factory=list)
    auth_methods: list[AuthMethod] = field(default_factory=list)
    static_assets: list[Endpoint] = field(default_factory=list)
    admin_endpoints: list[Endpoint] = field(default_factory=list)
    notes: str = ""


# Common GIS URL patterns
GIS_URL_PATTERNS = [
    (r"/rest/services", "api"),
    (r"/arcgis/rest", "api"),
    (r"/geoserver", "api"),
    (r"/map/", "map_layer"),
    (r"/layer/", "map_layer"),
    (r"/layers", "map_layer"),
    (r"/project/", "map_layer"),
    (r"/admin", "admin"),
    (r"/login", "auth"),
    (r"/signin", "auth"),
    (r"/sso", "auth"),
    (r"/oauth", "auth"),
    (r"/api/", "api"),
    (r"/v1/", "api"),
    (r"/v2/", "api"),
]

# Common admin paths to probe
ADMIN_PATHS = [
    "/admin", "/administrator", "/manage", "/console",
    "/dashboard", "/backend", "/cpanel", "/control",
    "/admin/login", "/admin/dashboard", "/debug", "/trace",
]


def _get_session(timeout: int = 10) -> "requests.Session | None":
    """Build a session with retries for reconnaissance requests."""
    if requests is None:
        return None
    session = requests.Session()
    retries = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503])
    session.mount("https://", HTTPAdapter(max_retries=retries))
    session.mount("http://", HTTPAdapter(max_retries=retries))
    session.headers.update({
        "User-Agent": "GIS-Security-Assessment/1.0 (Reconnaissance)",
        "Accept": "text/html,application/json,*/*",
    })
    return session


def _categorize_url(url: str) -> str:
    """Classify URL by GIS pattern."""
    path = urlparse(url).path.lower()
    for pattern, category in GIS_URL_PATTERNS:
        if re.search(pattern, path):
            return category
    if any(x in path for x in [".js", ".css", ".png", ".jpg", ".ico", ".woff"]):
        return "static"
    return "page"


def discover_urls_from_sitemap(base_url: str, session: Optional["requests.Session"] = None) -> list[Endpoint]:
    """Try to fetch sitemap.xml and extract URLs."""
    endpoints = []
    ses = session or _get_session()
    if ses is None:
        return endpoints

    for path in ["/sitemap.xml", "/sitemap_index.xml", "/sitemap-index.xml"]:
        try:
            u = urljoin(base_url, path)
            r = ses.get(u, timeout=10)
            if r.status_code != 200:
                continue
            # Simple regex for loc tags
            for m in re.finditer(r"<loc>([^<]+)</loc>", r.text, re.I):
                url = m.group(1).strip()
                if url.startswith(base_url.rstrip("/")) or urlparse(base_url).netloc in url:
                    cat = _categorize_url(url)
                    endpoints.append(Endpoint(url=url, category=cat))
        except Exception:
            pass
    return endpoints


def discover_urls_from_robots(base_url: str, session: Optional["requests.Session"] = None) -> list[Endpoint]:
    """Parse robots.txt for disallowed paths (often interesting for security)."""
    endpoints = []
    ses = session or _get_session()
    if ses is None:
        return endpoints

    try:
        u = urljoin(base_url, "/robots.txt")
        r = ses.get(u, timeout=10)
        if r.status_code != 200:
            return endpoints
        for line in r.text.splitlines():
            line = line.strip()
            if line.lower().startswith("disallow:") and ":" in line:
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    full = urljoin(base_url, path)
                    endpoints.append(Endpoint(url=full, category="discovered", notes="robots.txt"))
    except Exception:
        pass
    return endpoints


def probe_admin_paths(base_url: str, session: Optional["requests.Session"] = None) -> list[Endpoint]:
    """Probe common admin paths."""
    endpoints = []
    ses = session or _get_session()
    if ses is None:
        return endpoints

    for path in ADMIN_PATHS:
        try:
            u = urljoin(base_url, path)
            r = ses.get(u, timeout=5, allow_redirects=True)
            if r.status_code in (200, 401, 403):
                endpoints.append(Endpoint(
                    url=u,
                    category="admin",
                    requires_auth=r.status_code == 401,
                    notes=f"status={r.status_code}",
                ))
        except Exception:
            pass
    return endpoints


def infer_auth_from_response(url: str, session: Optional["requests.Session"] = None) -> list[AuthMethod]:
    """Infer auth type from login page or response headers."""
    methods = []
    ses = session or _get_session()
    if ses is None:
        return methods

    try:
        r = ses.get(urljoin(url, "/"), timeout=10, allow_redirects=True)
        headers = {k.lower(): v for k, v in r.headers.items()}
        body = (r.text or "").lower()

        if "www-authenticate" in headers:
            val = headers["www-authenticate"]
            if "basic" in val:
                methods.append(AuthMethod("username_password", "HTTP Basic", "Basic auth header"))
            if "bearer" in val or "oauth" in val:
                methods.append(AuthMethod("oauth", "Header", "Bearer/OAuth in WWW-Authenticate"))
            if "negotiate" in val or "ntlm" in val:
                methods.append(AuthMethod("ad", "Kerberos/NTLM", "Windows integrated auth"))

        if "/login" in r.url or "login" in body:
            if "saml" in body or "sso" in body or "oidc" in body:
                methods.append(AuthMethod("sso", "Login page", "SAML/OIDC/SSO indicators"))
            elif "ldap" in body:
                methods.append(AuthMethod("ldap", "Login page", "LDAP indicators in page"))
            else:
                methods.append(AuthMethod("username_password", "Login page", "Standard login form"))
    except Exception:
        pass
    return methods


def run_reconnaissance(
    base_url: str,
    probe_admin: bool = True,
    use_requests: bool = True,
) -> AttackSurface:
    """Run full reconnaissance against base URL."""
    base_url = base_url.rstrip("/")
    surface = AttackSurface(base_url=base_url)
    ses = _get_session() if use_requests and requests else None

    # Discover URLs
    surface.urls.extend(discover_urls_from_sitemap(base_url, ses))
    surface.urls.extend(discover_urls_from_robots(base_url, ses))
    if probe_admin:
        surface.admin_endpoints.extend(probe_admin_paths(base_url, ses))

    # Categorize
    for ep in surface.urls:
        if ep.category == "api":
            surface.api_endpoints.append(ep)
        elif ep.category == "map_layer":
            surface.map_layers.append(ep)

    # Auth inference
    surface.auth_methods.extend(infer_auth_from_response(base_url, ses))

    # Dedupe
    seen = set()
    for lst in [surface.urls, surface.api_endpoints, surface.map_layers]:
        out = []
        for e in lst:
            k = (e.url, e.method)
            if k not in seen:
                seen.add(k)
                out.append(e)
        lst.clear()
        lst.extend(out)

    return surface


def export_attack_surface(surface: AttackSurface, out_path: Path) -> None:
    """Export attack surface to JSON for documentation."""
    data = {
        "base_url": surface.base_url,
        "urls": [asdict(e) for e in surface.urls],
        "api_endpoints": [asdict(e) for e in surface.api_endpoints],
        "map_layers": [asdict(e) for e in surface.map_layers],
        "admin_endpoints": [asdict(e) for e in surface.admin_endpoints],
        "auth_methods": [asdict(a) for a in surface.auth_methods],
        "notes": surface.notes,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def main() -> int:
    parser = argparse.ArgumentParser(description="Reconnaissance and attack surface mapping for GIS apps")
    parser.add_argument("target", help="Base URL of GIS application")
    parser.add_argument("-o", "--output", help="Output JSON path for attack surface")
    parser.add_argument("--no-probe", action="store_true", help="Skip admin path probing")
    args = parser.parse_args()

    surface = run_reconnaissance(args.target, probe_admin=not args.no_probe)
    print(f"Base URL: {surface.base_url}")
    print(f"URLs: {len(surface.urls)}")
    print(f"API endpoints: {len(surface.api_endpoints)}")
    print(f"Map layers: {len(surface.map_layers)}")
    print(f"Admin endpoints: {len(surface.admin_endpoints)}")
    print(f"Auth methods: {len(surface.auth_methods)}")
    for a in surface.auth_methods:
        print(f"  - {a.type}: {a.location} ({a.notes})")

    if args.output:
        export_attack_surface(surface, Path(args.output))
        print(f"Exported to {args.output}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
