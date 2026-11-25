# SENTINEL — Testing Strategy & Verification Report

## 1. Automated Test Suites

Run all automated tests with:

```bash
cd backend
npm test
```

### Summary of Executed Automated Tests (`34 / 34 Passed`)

1. **Unit Tests (`backend/tests/unit/providers.test.js` & `risk_and_discovery.test.js`)**:
   - Domain validation, wildcard stripping, subdomain verification, and allowlist enforcement.
   - SSRF & private/loopback/link-local/CGNAT/multicast IPv4 and IPv6 rejection.
   - CVE identifier format validation.
   - `crt.sh` JSON normalization, SAN deduplication, and malformed HTML/502 graceful fallback.
   - Cloudflare DoH JSON normalization across `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `CAA`, `SOA`.
   - Shodan InternetDB payload normalization and private IP pre-request rejection.
   - NIST NVD CVSS v3.1/v3.0/v4.0/v2.0 parsing and `CVE_ASSOCIATION_OBSERVED` verification status labeling.
   - Passive Subdomain Takeover analyzer confidence categories (`Informational` through `Verified misconfiguration`).
   - Deterministic Risk Classification Engine and missing-provider-data transparency.
   - Scan-to-scan drift comparison (`compareScanResults`).
2. **Integration & Security Tests (`backend/tests/integration/api_and_security.test.js`)**:
   - `/api/v1/health`, `/api/v1/ready`, `/api/v1/version`, `/api/v1/providers/status` and security headers (`X-Content-Type-Options`, `X-Frame-Options`, `X-Sentinel-Server`).
   - Authentication flow (`POST /api/v1/auth/login`), invalid credential rejection (`401`), `HttpOnly; SameSite=Strict` session cookies, and CSRF token issuance.
   - CSRF protection enforcement (`403 CSRFValidationFailed` when `X-CSRF-Token` is omitted).
   - Role-Based Access Control (`403 Forbidden` when `Read-only Auditor` attempts to start a scan).
   - Authorized domain allowlist enforcement (`403 OutOfScopeDomain`).
   - SQL injection resilience on search/filter query parameters.
3. **End-to-End (E2E) Workflow Tests (`backend/tests/e2e/e2e_workflow.test.js`)**:
   - Full scan persistence across all relational tables, dashboard telemetry verification, asset/DNS/exposure/vulnerability filtering, CSV & JSON report generation (`SENTINEL_example.com_Asset-Inventory_YYYY-MM-DD.csv`), and multi-scan comparison.

## 2. Real External Provider Verification Procedure

To run a live integration verification against `crt.sh`, Cloudflare DoH, Shodan InternetDB, and NIST NVD:

```bash
cd backend
node -e "const { executeDomainDiscoveryPipeline } = require('./src/services/discovery/discovery.orchestrator'); (async () => { const res = await executeDomainDiscoveryPipeline({ domain: 'iana.org', authorizationConfirmed: true, maxSubdomainsToResolve: 6, maxCvesToEnrich: 3 }); console.log(JSON.stringify(res.summary, null, 2)); })()"
```
