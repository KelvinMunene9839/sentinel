# SENTINEL — System Architecture

## 1. Architectural Overview

SENTINEL is an API-first, passive cybersecurity reconnaissance and attack-surface intelligence platform. It follows a strict pipeline architecture:

```text
External Intelligence Providers (Real REST APIs)
  ├── crt.sh (Certificate Transparency JSON API)
  ├── Cloudflare DNS-over-HTTPS (https://cloudflare-dns.com/dns-query)
  ├── Shodan InternetDB (https://internetdb.shodan.io/{ip})
  └── NIST NVD CVE API v2.0 (https://services.nvd.nist.gov/rest/json/cves/2.0)
          │
          ▼
Backend Integration Layer (Node.js / Express.js — Web01 & Web02)
  ├── Independent Provider Services (Timeouts, Bounded Retries, Backoff, Rate-Limiting, Caching)
  ├── Input & Scope Validators (Authorized Domain Allowlist, SSRF / Private IP Rejection)
  ├── Discovery & Correlation Orchestrator (Subdomains → DNS → Public IPs → Exposures → CVEs)
  ├── Deterministic Risk Classification Engine & Passive Subdomain Takeover Analyzer
  └── Shared PostgreSQL Persistence (13 Relational Tables + Session Store + Audit Logs)
          │
          ▼
Versioned Internal REST API (/api/v1/*) + Vanilla JS Enterprise Frontend
          ▲
          │
HAProxy Load Balancer (Lb01) — Active HTTP Health Checks (/api/v1/ready)
```

## 2. Core Design Principles

1. **Passive Reconnaissance Only**: SENTINEL never sends exploit payloads, brute-force requests, or active port scans to target assets.
2. **External Providers as Authoritative Intelligence Sources**: The PostgreSQL database persists scan history, normalized assets, findings, and user sessions across `Web01` and `Web02`, while fresh intelligence always originates from `crt.sh`, Cloudflare DoH, Shodan InternetDB, and NIST NVD.
3. **Stateless Application Tier**: Neither `Web01` nor `Web02` holds critical scan or session state exclusively in process memory. All scan stages, assets, sessions, and audit logs are written directly to shared PostgreSQL tables.
4. **Decoupled Deterministic Risk Engine**: Risk classification (`backend/src/services/risk/`) is completely separated from external HTTP clients (`backend/src/services/providers/`) so rules can be audited and unit-tested deterministically.
