"""
Manual authorization testing.
Tests: parameter tampering (userId, role, tenant), privilege escalation.
"""

# Authorization testing is manual (intercept and modify requests).
# This module provides test cases and parameter suggestions.

AUTHZ_TEST_CASES = [
    {
        "id": "A1",
        "name": "User ID tampering",
        "params": ["userId", "user_id", "uid", "id"],
        "example": "?userId=100 -> ?userId=1 (view admin data)",
        "severity": "critical",
    },
    {
        "id": "A2",
        "name": "Role tampering",
        "params": ["role", "user_role", "type", "level"],
        "example": "?role=user -> ?role=admin",
        "severity": "critical",
    },
    {
        "id": "A3",
        "name": "Tenant/org ID tampering",
        "params": ["tenantId", "tenant_id", "orgId", "organization", "org"],
        "example": "Switch tenant in request to access other org data",
        "severity": "critical",
    },
    {
        "id": "A4",
        "name": "API request modification",
        "steps": [
            "Capture API request as regular user",
            "Modify JSON body or headers (e.g. add isAdmin: true)",
            "Replay and check response",
        ],
        "severity": "high",
    },
]


def print_test_cases() -> None:
    for tc in AUTHZ_TEST_CASES:
        print(f"\n[{tc['id']}] {tc['name']} [{tc['severity']}]")
        if "params" in tc:
            print("  Params to try:", ", ".join(tc["params"]))
            print("  Example:", tc.get("example", ""))
        if "steps" in tc:
            for s in tc["steps"]:
                print(f"  - {s}")


if __name__ == "__main__":
    print("Authorization testing cases")
    print("=" * 50)
    print_test_cases()
