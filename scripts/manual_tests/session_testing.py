"""
Manual session management testing.
Tests: session fixation, role change invalidation.
"""

# Session testing is largely manual (intercept cookies, replay, modify).
# This module provides a checklist and helper to document findings.

SESSION_CHECKLIST = [
    {
        "id": "S1",
        "name": "Session fixation",
        "steps": [
            "Capture session ID before login (e.g. JSESSIONID, PHPSESSID)",
            "Log in as victim (or use same browser)",
            "Check if session ID changed after login (it should)",
            "If unchanged, try reusing old session ID in another browser",
        ],
        "finding_if_pass": "Session fixation: app accepts pre-auth session ID after login",
        "severity": "high",
    },
    {
        "id": "S2",
        "name": "Session invalidation on role change",
        "steps": [
            "Log in as regular user, capture session cookie",
            "Admin elevates user to admin (or change role in DB)",
            "Replay same session cookie without re-login",
            "Check if old session still has new privileges (it should not)",
        ],
        "finding_if_pass": "Session not invalidated on privilege change",
        "severity": "high",
    },
    {
        "id": "S3",
        "name": "Secure/HttpOnly cookie flags",
        "steps": [
            "Inspect Set-Cookie headers on login response",
            "Verify Secure flag on cookies over HTTPS",
            "Verify HttpOnly on session cookie",
        ],
        "finding_if_pass": "Session cookie missing Secure or HttpOnly",
        "severity": "medium",
    },
    {
        "id": "S4",
        "name": "Session timeout",
        "steps": [
            "Log in and leave session idle",
            "After expected timeout, perform privileged action",
            "Session should be invalidated",
        ],
        "finding_if_pass": "Session does not expire or timeout too long",
        "severity": "low",
    },
]


def print_checklist() -> None:
    for item in SESSION_CHECKLIST:
        print(f"\n[{item['id']}] {item['name']} [{item['severity']}]")
        for step in item["steps"]:
            print(f"  - {step}")
        print(f"  Finding if vulnerable: {item['finding_if_pass']}")


if __name__ == "__main__":
    print("Session management testing checklist")
    print("=" * 50)
    print_checklist()
