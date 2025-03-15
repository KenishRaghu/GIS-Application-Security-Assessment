"""
Manual authentication testing helpers.
Tests: default credentials, password complexity, brute-force lockouts.
"""

import argparse
import sys
from pathlib import Path

# Add parent for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

try:
    import requests
except ImportError:
    requests = None

# Common default credentials
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "password123"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("guest", "guest"),
    ("test", "test"),
    ("user", "user"),
]


def test_default_credentials(
    login_url: str,
    username_param: str = "username",
    password_param: str = "password",
    creds: list[tuple[str, str]] | None = None,
    success_indicator: str | None = None,
    session: "requests.Session | None" = None,
) -> list[dict]:
    """
    Try default credentials. Returns list of findings.
    success_indicator: substring in response that suggests success (e.g. "Dashboard", "logout")
    """
    creds = creds or DEFAULT_CREDS
    ses = session
    if ses is None and requests:
        ses = requests.Session()
    findings = []

    for user, pwd in creds:
        try:
            if not ses:
                break
            r = ses.post(
                login_url,
                data={username_param: user, password_param: pwd},
                allow_redirects=True,
                timeout=10,
            )
            success = False
            if success_indicator and success_indicator.lower() in (r.text or "").lower():
                success = True
            elif r.status_code == 200 and "login" not in (r.url or "").lower():
                success = True
            if success:
                findings.append({
                    "type": "default_credentials",
                    "severity": "critical",
                    "username": user,
                    "password": pwd,
                    "url": login_url,
                    "description": f"Default credentials accepted: {user}/{pwd}",
                })
        except Exception as e:
            findings.append({
                "type": "test_error",
                "severity": "info",
                "username": user,
                "error": str(e),
            })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Test default credentials on GIS login")
    parser.add_argument("url", help="Login URL (POST endpoint)")
    parser.add_argument("-u", "--username-param", default="username")
    parser.add_argument("-p", "--password-param", default="password")
    parser.add_argument("-s", "--success", help="Response substring indicating success")
    args = parser.parse_args()

    if not requests:
        print("Install requests: pip install requests")
        return 1

    findings = test_default_credentials(
        args.url,
        username_param=args.username_param,
        password_param=args.password_param,
        success_indicator=args.success,
    )
    for f in findings:
        if f.get("type") == "default_credentials":
            print(f"[CRITICAL] {f['description']}")
        elif f.get("type") == "test_error":
            print(f"[INFO] Error testing {f.get('username')}: {f.get('error')}")

    if not any(f.get("type") == "default_credentials" for f in findings):
        print("No default credentials accepted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
