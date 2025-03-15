# GIS Application Security Assessment

Penetration testing and vulnerability assessment for GIS web applications. Supports automated scanning with BurpSuite, manual testing checklists, identity provider validation (LDAP/AD), and report compilation.

## Contents

- `docs/` — Attack surface template, BurpSuite config, penetration findings, identity provider validation
- `scripts/` — Reconnaissance, scan orchestration, vulnerability processing, manual tests, IDP tests
- `results/` — Scan outputs, metrics (gitignored for sensitive data)

## Workflow

### Phase 1: Reconnaissance & setup

1. Map the GIS application like a detective: URLs, APIs, map layers, features.
2. Identify authentication: username/password, LDAP, AD, SSO.
3. Document everything in `docs/attack-surface.md`.

```bash
cd scripts
python reconnaissance.py https://your-gis-app.example.com -o ../results/attack_surface.json
```

### Phase 2: Automated scanning

1. Configure BurpSuite (see `docs/burpsuite-config.md`): proxy, scope, auth.
2. Run scan orchestration:

```bash
python run_scan.py https://your-gis-app.example.com
```

3. If Burp API is not configured, follow the manual workflow printed by the script.
4. Export Burp scan results as JSON, then process:

```bash
python vulnerability_scanner.py ../results/burp_scan.json -o ../results/scan_report.md
```

### Phase 3: Manual penetration testing

| Test | Script / checklist |
|------|--------------------|
| Default credentials | `python manual_tests/auth_testing.py https://app/login` |
| Session management | `python manual_tests/session_testing.py` |
| Authorization / param tampering | `python manual_tests/authorization_testing.py` |
| API unauthenticated access | `python manual_tests/api_testing.py https://app` |
| IDOR | `python manual_tests/idor_testing.py https://app/layer -p id -i 1,2,3,100` |

Document manual findings in `results/manual_findings.json` (see `manual_findings_example.json`).

### Phase 4: Identity provider testing

- LDAP: `python identity_provider/ldap_testing.py` (checklist) or `python identity_provider/ldap_testing.py ldap.example.com`
- AD: `python identity_provider/ad_testing.py` (checklist) or `python identity_provider/ad_testing.py --config-paths /path/to/config`

Fill in `docs/identity-provider-validation.md` with results.

### Phase 5: Reporting

Merge automated and manual findings:

```bash
python compile_report.py -b ../results/burp_scan.json -m ../results/manual_findings.json -o ..
```

Generates:

- `docs/penetration-testing-findings.md` — Consolidated findings
- `results/metrics.json` — Automation time-saved metrics

## Requirements

```bash
pip install -r scripts/requirements.txt
```

- `requests` — Reconnaissance, API/IDOR probes, auth testing

## Vulnerability categories

Risk = Impact × Likelihood. Severities:

- **Critical:** SQL injection, default credentials, full data access
- **High:** XSS, session fixation, privilege escalation
- **Medium:** CSRF, missing security headers, cookie flags
- **Low:** Info disclosure, best-practice gaps
- **Info:** FYI items (e.g. X-Powered-By)

## Metrics

Manual testing estimate: ~20 hours. With automation: ~10 hours (scans run overnight). Automation saves ~50% of testing time.
