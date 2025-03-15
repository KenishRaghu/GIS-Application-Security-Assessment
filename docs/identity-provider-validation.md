# Identity provider integration — LDAP & Active Directory

## Scope

Validation of identity provider integration with LDAP and Active Directory and security hardening.

## LDAP testing

### Encryption

| Check | Expected | Result |
|-------|----------|--------|
| LDAPS (port 636) | Use 636, not 389 | |
| Plain LDAP (389) | Avoid; passwords in clear text | |

### Certificate validation

| Check | Expected | Result |
|-------|----------|--------|
| SSL/TLS cert validated | No "ignore cert" | |
| Self-signed rejection | App rejects or warns | |

### Service account

| Check | Expected | Result |
|-------|----------|--------|
| Bind DN permissions | Read-only user/group data | |
| Principle of least privilege | No create/delete users | |

## Active Directory testing

### Authentication

| Check | Expected | Result |
|-------|----------|--------|
| Kerberos/NTLM | Works over secure channel | |
| Secure channel | HTTPS or LDAPS | |

### Group mapping

| Check | Expected | Result |
|-------|----------|--------|
| AD groups → GIS roles | Correct mapping | |
| Role change propagation | Immediate effect on GIS permissions | |
| Session invalidation | Old session loses access on group change | |

### Password policies

| Check | Expected | Result |
|-------|----------|--------|
| Complexity | Matches org standards | |
| Expiry, lockout | Aligned | |

### Credential storage

| Check | Expected | Result |
|-------|----------|--------|
| No hardcoded creds | Use vault or managed identity | |
| Config files | No plaintext LDAP/AD passwords | |

## Security hardening validated

- LDAPS (port 636) enforced; StartTLS where applicable
- Certificate chain validation enabled
- Account lockout and password policy consistent with organizational standards
- No storage of LDAP/AD credentials in application config; use managed identities or vault where applicable
