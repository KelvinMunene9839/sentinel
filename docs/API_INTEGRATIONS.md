# SENTINEL — External REST API Integrations

## 1. crt.sh — Certificate Transparency Discovery
- **Service Module**: `backend/src/services/providers/crtsh.service.js`
- **Endpoint**: `https://crt.sh/?q=%25.{domain}&output=json`
- **Retrieved Fields**: Common Name (`common_name`), Subject Alternative Names (`name_value`), Certificate ID (`id`), Issuer (`issuer_name`), Serial Number, Validity Period (`not_before`, `not_after`).
- **Resilience**: Validates target domain, strips `*.` wildcards, filters out-of-scope domains and emails, deduplicates subdomains across certificates, enforces configurable timeout (`15000ms`), bounded retries with exponential backoff, and falls back gracefully to the root domain if `crt.sh` returns `502`/`503`.

## 2. Cloudflare DNS-over-HTTPS (DoH)
- **Service Module**: `backend/src/services/providers/cloudflare.service.js`
- **Endpoint**: `https://cloudflare-dns.com/dns-query?name={hostname}&type={type}`
- **Headers**: `Accept: application/dns-json`
- **Supported Record Types**: `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `CAA`, `SOA`
- **Resilience**: Normalizes DNS type codes and RCODEs (`NOERROR`, `NXDOMAIN`, `SERVFAIL`), verifies whether CNAME targets themselves resolve or are dangling (`DANGLING_CNAME`), and caches responses for 15 minutes.

## 3. Shodan InternetDB
- **Service Module**: `backend/src/services/providers/shodan.service.js`
- **Endpoint**: `https://internetdb.shodan.io/{ip}`
- **Retrieved Fields**: `ports`, `hostnames`, `cpes`, `vulns` (CVE IDs), `tags`.
- **Security & Validation**: Every IP is validated through `validatePublicIp()` before querying. Private, loopback, link-local (`169.254.0.0/16`), CGNAT, multicast, and documentation IPs are rejected immediately. HTTP `404` responses are normalized as `not_indexed`.
- **Licensing Condition**: Shodan InternetDB is free for non-commercial use only. Commercial deployment requires a separate commercial license from Shodan. This notice is surfaced in `/api/v1/providers/status`, `/api/v1/exposures`, the UI, and exported JSON reports.

## 4. NIST National Vulnerability Database (NVD API v2.0)
- **Service Module**: `backend/src/services/providers/nvd.service.js`
- **Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cveId}`
- **Authentication**: Optional `NVD_API_KEY` environment variable sent strictly from the backend via the `apiKey` request header. Never exposed to frontend JavaScript.
- **Rate Limiting & Deduplication**: Deduplicates CVE identifiers across all IPs in a scan and enforces request throttling (`NVD_RATE_LIMIT_DELAY_MS`).
- **Evidence Discipline**: Every enriched CVE record is explicitly marked `verificationStatus: "CVE_ASSOCIATION_OBSERVED"` to distinguish passive IP/CPE association from verified vulnerable software versions.
