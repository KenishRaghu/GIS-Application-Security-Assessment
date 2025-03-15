# Vulnerability scan report

## Summary

- Critical: 0
- High: 1
- Medium: 0
- Low: 1
- Info: 0

## Findings

### 1. SQL injection [HIGH] (CVSS: 9.8)

- **URL:** https://example.com/api/search
- **Confidence:** certain
- **Risk:** Data theft or session compromise. Exploitability: medium to high.

**Description:**
> Parameter q is vulnerable to SQL injection.

**Remediation:**
> Use parameterized queries.

---

### 2. Missing X-Content-Type-Options header [LOW]

- **URL:** https://example.com/
- **Confidence:** certain
- **Risk:** Minor information disclosure or best-practice gaps. Exploitability: low.

**Description:**


**Remediation:**


---
