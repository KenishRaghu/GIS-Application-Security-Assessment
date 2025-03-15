# Identity Provider Integration — LDAP & Active Directory

## Scope

Validation of identity provider integration with LDAP and Active Directory and review of security hardening configurations.

## Validation Activities

- Verified LDAP bind and search base configuration; confirmed use of dedicated service account with minimal privileges
- Validated Active Directory integration (Kerberos/NTLM) and secure channel requirements
- Reviewed and validated security hardening: LDAPS only, certificate validation, lockout and password policy alignment
- Confirmed group-to-role mapping and that GIS application respects AD/LDAP group membership for access control

## Security Hardening Configurations Validated

- LDAPS (port 636) enforced; StartTLS where applicable
- Certificate chain validation enabled
- Account lockout and password policy consistent with organizational standards
- No storage of LDAP/AD credentials in application config; use of managed identities or vault where applicable
