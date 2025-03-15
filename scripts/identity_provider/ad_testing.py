"""
Active Directory integration testing for GIS applications.
Checks: Kerberos/NTLM, group mapping, password policies, hardcoded creds.
"""

AD_CHECKLIST = [
    {
        "id": "AD1",
        "name": "Kerberos/NTLM authentication",
        "steps": [
            "Verify AD auth works (Kerberos or NTLM)",
            "Check secure channel (LDAPS or integrated auth over HTTPS)",
        ],
        "severity": "high",
    },
    {
        "id": "AD2",
        "name": "Group-to-role mapping",
        "steps": [
            "Map AD groups to GIS roles (viewer, editor, admin)",
            "Change user's AD group - does GIS permission update immediately?",
            "Test with user removed from admin group - old session should lose access",
        ],
        "finding": "Group membership change not reflected - stale permissions",
        "severity": "high",
    },
    {
        "id": "AD3",
        "name": "Password policies",
        "steps": [
            "Verify password policy matches org standards",
            "Complexity, expiry, lockout",
        ],
        "severity": "medium",
    },
    {
        "id": "AD4",
        "name": "No hardcoded credentials",
        "steps": [
            "Search config files for LDAP/AD bind credentials",
            "Check for plaintext passwords in app config, env, or code",
            "Use managed identities or vault where applicable",
        ],
        "finding": "LDAP/AD credentials stored in config",
        "severity": "critical",
    },
]


def grep_hardcoded_config(config_paths: list[str]) -> list[str]:
    """Search config files for potential credential patterns."""
    import re
    import os
    patterns = [
        r"password\s*=\s*['\"][^'\"]+['\"]",
        r"bindPassword\s*=\s*['\"][^'\"]+['\"]",
        r"ldap\.password\s*[:=]\s*['\"][^'\"]+['\"]",
        r"secret\s*[:=]\s*['\"][^'\"]+['\"]",
    ]
    found = []
    for path in config_paths:
        if not os.path.exists(path):
            continue
        try:
            with open(path) as f:
                text = f.read()
            for pat in patterns:
                for m in re.finditer(pat, text, re.I):
                    found.append(f"{path}: {m.group(0)[:80]}...")
        except Exception:
            pass
    return found


def print_checklist() -> None:
    for item in AD_CHECKLIST:
        print(f"\n[{item['id']}] {item['name']} [{item['severity']}]")
        for step in item["steps"]:
            print(f"  - {step}")
        if item.get("finding"):
            print(f"  Finding: {item['finding']}")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--config-paths", nargs="+", help="Config files to scan for hardcoded creds")
    args = parser.parse_args()

    print("Active Directory testing checklist")
    print("=" * 50)
    print_checklist()

    if args.config_paths:
        print("\nHardcoded credential scan:")
        matches = grep_hardcoded_config(args.config_paths)
        for m in matches or ["None found"]:
            print(f"  {m}")
