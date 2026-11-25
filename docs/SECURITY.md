# SENTINEL — Security Architecture & Controls

## 1. Mandatory Security Controls Implemented

- **Authorized-Domain Allowlisting & Scope Validation**: Every scan request verifies both explicit operator confirmation (`authorizationConfirmed: true`) and membership in the `authorized_domains` allowlist (`isDomainAuthorized()`).
- **SSRF & DNS Rebinding Prevention**:
  - The backend never accepts arbitrary user-supplied URLs to fetch.
  - All external requests use hardcoded provider base URLs (`crt.sh`, `cloudflare-dns.com`, `internetdb.shodan.io`, `services.nvd.nist.gov`) with URL-encoded domain/IP/CVE parameters.
  - `validatePublicIp()` (`backend/src/validators/ip.validator.js`) rejects RFC 1918 private ranges (`10/8`, `172.16/12`, `192.168/16`), loopback (`127/8`, `::1`), link-local / cloud metadata (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), multicast, and documentation IPs before any IP enrichment call.
- **Authentication, Password Hashing & Session Security**:
  - Passwords are hashed using `crypto.scryptSync` with 16-byte cryptographic random salts and verified using constant-time `crypto.timingSafeEqual`.
  - Session tokens are 256-bit random values stored as SHA-256 hashes in PostgreSQL (`user_sessions`) and delivered via `HttpOnly; SameSite=Strict` cookies.
- **CSRF Protection**: State-changing requests (`POST`, `PUT`, `DELETE`) require a valid `X-CSRF-Token` header matching the session's cryptographic CSRF token.
- **Role-Based Access Control (RBAC)**:
  - `Administrator` & `Security Analyst`: Can launch scans and add authorized domains.
  - `Read-only Auditor`: Can view dashboards, inspect assets/CVEs/findings, and export reports, but is blocked (`403 Forbidden`) from initiating scans or modifying scope.
- **SQL Injection & CSV Formula Injection Prevention**:
  - All SQL queries use parameterized `$1, $2` placeholders.
  - CSV exports sanitize cells starting with `=`, `+`, `-`, or `@` (`escapeCsvCell`).
- **API Key Confidentiality**: `NVD_API_KEY` is read strictly on the backend and never sent to the browser or included in exports.
