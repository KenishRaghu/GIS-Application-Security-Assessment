"""
LDAP integration testing for GIS applications.
Checks: LDAPS vs LDAP, certificate validation, service account permissions.
"""

# LDAP testing requires ldap3 or python-ldap. This script provides
# a checklist and optional connection checks.

LDAP_CHECKLIST = [
    {
        "id": "L1",
        "name": "Encryption: LDAPS (636) vs plain LDAP (389)",
        "steps": [
            "Identify LDAP config (app config, env vars, vault)",
            "Check if port 636 (LDAPS) or 389 (LDAP) is used",
            "Plain LDAP = passwords in clear text = CRITICAL",
        ],
        "finding_plain": "LDAP over port 389 - credentials transmitted in clear text",
        "severity": "critical",
    },
    {
        "id": "L2",
        "name": "Certificate validation",
        "steps": [
            "Check if SSL/TLS cert is validated (no 'ignore cert' or similar)",
            "Test with self-signed cert - app should reject or warn",
        ],
        "finding": "LDAP connection does not validate server certificate - MITM possible",
        "severity": "high",
    },
    {
        "id": "L3",
        "name": "Service account permissions",
        "steps": [
            "Identify bind DN used by GIS app",
            "Verify it can only read user/group data, not create/delete",
            "Principle of least privilege",
        ],
        "finding": "LDAP bind account has excessive permissions",
        "severity": "medium",
    },
]


def check_ldap_port(host: str, port: int = 389) -> dict:
    """Try to connect to LDAP port. Returns dict with status."""
    try:
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        result = s.connect_ex((host, port))
        s.close()
        return {
            "host": host,
            "port": port,
            "open": result == 0,
            "warning": "Plain LDAP (389) - unencrypted" if port == 389 and result == 0 else None,
        }
    except Exception as e:
        return {"host": host, "port": port, "error": str(e)}


def print_checklist() -> None:
    for item in LDAP_CHECKLIST:
        print(f"\n[{item['id']}] {item['name']} [{item['severity']}]")
        for step in item["steps"]:
            print(f"  - {step}")
        print(f"  Finding: {item.get('finding') or item.get('finding_plain')}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("host", nargs="?", help="LDAP host to probe (optional)")
    parser.add_argument("-p", "--port", type=int, default=389)
    args = parser.parse_args()

    print("LDAP testing checklist")
    print("=" * 50)
    print_checklist()

    if args.host:
        print("\nPort check:")
        r = check_ldap_port(args.host, args.port)
        for k, v in r.items():
            print(f"  {k}: {v}")
