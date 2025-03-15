# BurpSuite configuration for GIS security assessment

## Proxy setup

1. Open BurpSuite and go to **Proxy > Options**.
2. Ensure proxy listener is on (e.g. `127.0.0.1:8080`).
3. In your browser, set HTTP/HTTPS proxy to `127.0.0.1:8080`.
4. Install Burp’s CA certificate so HTTPS traffic can be inspected (Proxy > Options > Import/Export CA certificate).

## Scan scope

1. Go to **Target > Scope**.
2. Add your GIS app base URL(s) under “Include in scope.”
3. Exclude third‑party domains or large CDNs you don’t need to test.
4. In **Scanner > Options > Scan speed**, choose a level (e.g. “Normal”).

## Authentication (if required)

1. **Proxy > Options:** Ensure traffic to the app goes through Burp.
2. **Scanner > Options > Session handling:**
   - Add “Login request” to record the login flow.
   - Configure credentials (username/password or API key) if using “Prompt for credentials.”
3. For session-based auth, log in in the browser with Burp as proxy, then start the scan so it reuses the session.

## Tests to run

BurpScanner typically checks:

- SQL injection
- Cross-site scripting (XSS)
- CSRF
- Security misconfigurations:
  - Missing Strict-Transport-Security (HSTS)
  - Missing X-Content-Type-Options
  - Missing Content-Security-Policy
  - Exposed X-Powered-By and similar headers

## Exporting results

1. After the scan, go to **Dashboard** (or the scan’s **Issues** tab).
2. Export in **JSON** (or the format supported by `vulnerability_scanner.py`).
3. Save the file and pass it to `vulnerability_scanner.py`.

## Example export path

```
./results/burp_scan_YYYYMMDD.json
```
