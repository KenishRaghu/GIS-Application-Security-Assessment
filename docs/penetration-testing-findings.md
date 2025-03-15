# GIS Web Application — Penetration Testing Findings

## Scope

Penetration testing performed on the GIS web application with focus on authentication and authorization.

## Authentication & Authorization Vulnerabilities Identified

- Weak or default credentials on administrative endpoints
- Session fixation and insufficient session invalidation on role change
- Privilege escalation via parameter tampering (e.g., role/tenant ID)
- Missing or inconsistent authorization checks on map/data APIs
- Insecure direct object references (IDOR) on layer and project resources

## Recommendations

- Enforce MFA for admin and elevated roles
- Implement consistent RBAC and server-side authorization checks
- Invalidate sessions on privilege change and use secure session binding
