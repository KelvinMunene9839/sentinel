# SENTINEL

**Cloud & Enterprise Attack Surface Intelligence Platform**

SENTINEL discovers and assesses the external attack surface of domains you are authorized to examine. It uses **passive reconnaissance only**: it reads public data sources and never probes, scans ports on, or sends traffic to the targets themselves. Findings are produced by a deterministic, explainable risk engine, and every finding carries its evidence, source, confidence and a recommended remediation.

- **Live Production URL:** [https://kelvinnyagah.tech](https://kelvinnyagah.tech)
- **Demo Video Walkthrough:** [Watch the SENTINEL Feature & Architecture Walkthrough](https://youtu.be/wfiMCEKjTCg)
- **Frontend:** vanilla HTML, CSS and ES6 JavaScript (no build step, no framework)
- **Backend:** Node.js 20+, Express, PostgreSQL (embedded PGlite for local development)
- **Deployment:** two stateless app nodes (`Web01`, `Web02`) behind an HAProxy TLS load balancer (`Lb01`)

[![SENTINEL Demo Video](https://img.youtube.com/vi/wfiMCEKjTCg/maxresdefault.jpg)](https://youtu.be/wfiMCEKjTCg)

---

## Contents

What it does

Quick start

Configuration

Using the application

Roles and permissions

Architecture

Project structure

API overview

Testing

Production deployment

Security notes

Troubleshooting

Credits and licensing

What it does

Capability

Source

Detail

Subdomain discovery

crt.sh Certificate Transparency logs

Finds certificates and the hostnames on them; deduplicates and strips wildcards

DNS intelligence

Cloudflare DNS-over-HTTPS

A, AAAA, CNAME, MX, TXT, NS, CAA, SOA; detects NXDOMAIN and dangling CNAMEs

Public IP exposure

Shodan InternetDB

Open ports, CPEs, hostnames, tags, and CVE associations per public IP

Vulnerability enrichment

NIST NVD API 2.0

CVSS score, severity, description, CWE, and references

Takeover risk analysis

Derived from DNS

Dangling CNAME and known cloud-service patterns, rated on a five-step confidence scale

Risk classification

Internal engine

Critical, High, Medium, Low, and Informational, each with reason, evidence, and remediation

Scan comparison

Stored scans

Shows new and removed assets, new open ports, new CVEs, DNS changes, and risk changes between two scans

Reports

Stored scans

CSV (assets, DNS, vulnerabilities) and consolidated JSON exports

Audit log

Shared PostgreSQL database

Records operator authentication and scan actions across both nodes

Evidence discipline

A CVE reported by InternetDB for an IP is an observed association, not proof that the host runs a vulnerable build. SENTINEL labels every CVE accordingly and advises operators to verify the installed version and any backported patches before treating it as exploitable.

Takeover findings use a confidence scale of Informational, Suspicious, Potentially vulnerable, Verified misconfiguration, Confirmed takeover. SENTINEL never claims or registers external resources to verify a takeover.

Scope enforcement

Scans run only against domains on the authorized domain allowlist, and the operator must attest to authorization on each scan. IP addresses are validated before any lookup, and private, loopback, link-local, CGNAT, multicast, and documentation ranges are rejected to prevent server-side request forgery (SSRF).

Quick start

Prerequisites

Node.js 20 or newer (node --version)

npm

Outbound HTTPS access to crt.sh, cloudflare-dns.com, internetdb.shodan.io, and services.nvd.nist.gov

PostgreSQL is optional locally. By default, local execution uses PGlite, an embedded PostgreSQL engine that stores data in a local directory.

Run it locally

# 1. Create your environment file
cp .env.example backend/.env

# 2. Install backend dependencies
cd backend
npm install

# 3. Create the schema and seed roles, users, and default authorized domains
npm run migrate

# 4. Start the server
npm start


Open http://localhost:3000. The single Node process serves both the REST API (/api/v1/*) and the static frontend, so there is no separate frontend server or build step.

For development with automatic restart on file changes, run npm run dev.

Sign in

Migrations seed three accounts, one per role:

Username

Password

Role

admin

AdminPassword123!

Administrator

analyst

AnalystPassword123!

Security Analyst

auditor

AuditorPassword123!

Read-only Auditor

Security notice: Replace these default credentials and remove any quick-fill helpers before exposing an instance to untrusted networks.

You can browse public dashboards without signing in, while initiating scans and managing authorized scope requires an Administrator or Security Analyst session.

Run your first scan

Sign in at /login.html and navigate to Scans.

Pick an authorized domain such as iana.org (default allowlist: example.com, iana.org, nist.gov, cloudflare.com, shodan.io).

Tick the authorization confirmation checkbox and choose Start scan.

Watch the pipeline stages complete, then explore Overview, Assets, DNS, Findings, Vulnerabilities, and Reports.

Configuration

All settings are environment variables read from backend/.env (locally) or /etc/sentinel/web01.env and /etc/sentinel/web02.env (in production). See .env.example for the full template.

Variable

Default

Purpose

PORT

3000

HTTP port bound by the Node.js application

SERVER_ID

web01

Node identifier returned in X-Sentinel-Server headers and audit logs

DB_MODE

pglite

pglite (embedded local DB) or pg (shared PostgreSQL via DATABASE_URL)

DATABASE_URL

none

PostgreSQL connection string (postgresql://sentinel:***@10.30.10.93:5432/sentinel)

PGLITE_DATA_DIR

../.sentinel_pgdata

Local storage directory when DB_MODE=pglite

SESSION_SECRET

placeholder

Shared cryptographic secret across web01 and web02 for session signing

SESSION_COOKIE_NAME

sentinel_sid

Name of the HttpOnly; SameSite=Strict; Secure session cookie

SESSION_TTL_HOURS

12

Session lifetime in hours

CORS_ALLOWED_ORIGINS

localhost origins

Set to https://kelvinnyagah.tech in production

DEFAULT_AUTHORIZED_DOMAINS

five public domains

Initial domain allowlist seeded on first migration

CRTSH_BASE_URL, CRTSH_TIMEOUT_MS

crt.sh, 15000

Certificate Transparency provider

CLOUDFLARE_DOH_URL, CLOUDFLARE_TIMEOUT_MS

Cloudflare, 8000

DNS-over-HTTPS provider

SHODAN_INTERNETDB_URL, SHODAN_TIMEOUT_MS

InternetDB, 8000

Public IP exposure provider

NVD_API_BASE_URL, NVD_TIMEOUT_MS

NVD 2.0, 12000

Vulnerability enrichment provider

NVD_API_KEY

empty

Optional NVD API key (server-side only; never exposed to the browser)

NVD_RATE_LIMIT_DELAY_MS

2000

Delay between NVD requests to respect rate limits

Using the application

Page

Purpose

Overview

Summary metrics, priority findings with recommended actions, risk distribution, open ports, recent assets and scans, and provider health

Assets

Sortable, filterable asset inventory with column toggles, pagination, and CSV/JSON export; selecting a row opens a detail drawer (overview, DNS, certificates, exposures, vulnerabilities, history)

DNS

All discovered DNS records filterable by record type or search query, with per-host views

Findings

Tabbed views for prioritized security findings, public IP exposures, and subdomain takeover risks

Vulnerabilities

Enriched CVEs with CVSS scores and severity badges, plus a detail drawer with descriptions, affected hosts, and external references

Scans

Launch authorized passive scans, manage the domain allowlist, monitor live pipeline stages, review scan history, and compare two scans

Reports

Per-scan CSV (assets, dns, vulnerabilities) and consolidated JSON downloads

System menu

Live provider status, audit log across both nodes, and system settings

Roles and permissions

Role

View data & reports

Start/cancel scans & edit authorized scope

Administrator

Yes

Yes

Security Analyst

Yes

Yes

Read-only Auditor

Yes

No

Role-based access control is enforced server-side via the requireAuth and requireRole middleware on every protected API endpoint.

Architecture

               Internet Clients (https://kelvinnyagah.tech)
                                     │
                                     ▼
          ┌─────────────────────────────────────────────────────┐
          │   7378-lb-01 (35.176.99.45) — HAProxy 2.0           │
          │   • TLS 1.2/1.3 termination (Let's Encrypt)         │
          │   • HTTP :80 → HTTPS :443 301 redirect              │
          │   • Round-robin balancing + /api/v1/ready healthchk │
          │   • Injects X-Load-Balancer: lb01                   │
          └──────────────────┬──────────────────┬───────────────┘
                             │                  │
              10.30.10.93:3000                  10.30.21.67:3000
                             ▼                  ▼
          ┌──────────────────────────┐  ┌──────────────────────────┐
          │ 7378-web-01              │  │ 7378-web-02              │
          │ (35.177.149.1)           │  │ (3.9.169.82)             │
          │ Node.js 20 + Express     │  │ Node.js 20 + Express     │
          │ X-Sentinel-Server: web01 │  │ X-Sentinel-Server: web02 │
          └─────────────┬────────────┘  └────────────┬─────────────┘
                        │                            │
                        └──────────────┬─────────────┘
                                       ▼
                        ┌──────────────────────────────┐
                        │ PostgreSQL 12 (10.30.10.93)  │
                        │ • Scans, assets, DNS, CVEs   │
                        │ • Shared user_sessions table │
                        │ • Centralized audit_logs     │
                        └──────────────────────────────┘
                                       ▲
                                       │
          crt.sh · Cloudflare DoH · Shodan InternetDB · NIST NVD


Architectural highlights

Stateless horizontal scaling: Both web01 and web02 share the same SESSION_SECRET and PostgreSQL user_sessions store. A user who logs in via web01 remains seamlessly authenticated when subsequent requests are routed to web02.

Active health checks: HAProxy polls GET /api/v1/ready every 5 seconds (fall 3, rise 2), verifying not only that the Node.js process is listening, but also that its PostgreSQL connection is healthy.

Graceful provider degradation: If an upstream intelligence API is slow or unavailable, the scan completes with the remaining sources and records the provider status without fabricating results.

Further documentation is available in docs/ARCHITECTURE.md, docs/LOAD_BALANCING.md, and docs/DATABASE.md.

Project structure

.
├── frontend/                 Static UI served directly by Express
│   ├── *.html                Page templates (index, login, dashboard, assets, dns, findings, vulnerabilities, scans, reports)
│   ├── css/                  Design system (tokens.css, layout.css, components.css, pages.css, styles.css)
│   └── js/                   Client controllers (api.js, auth.js, shell.js, charts.js, and per-page modules)
├── backend/
│   ├── src/
│   │   ├── app.js, server.js Express application and HTTP server entrypoint
│   │   ├── config/           Environment-driven configuration loader
│   │   ├── database/         PostgreSQL/PGlite connection pool, migration runner, and repositories
│   │   ├── middleware/       Session authentication, RBAC, CSRF verification, rate limiting, security headers
│   │   ├── routes/           REST API routers (/auth, /scans, /assets, /dns, /exposures, /vulnerabilities, /findings, /dashboard, /reports)
│   │   ├── services/         Upstream API providers, discovery orchestrator, correlation engine, risk & takeover analyzers
│   │   ├── utils/            Structured logger, audit log recorder, scrypt/session cryptography
│   │   └── validators/       Domain allowlist, SSRF private-IP filtering, CVE format validation
│   ├── migrations/           SQL schema and initial seed data (001_initial_schema.sql)
│   └── tests/                Unit, integration, and end-to-end test suites
├── deployment/
│   ├── haproxy/              HAProxy 2.0 configuration (haproxy.cfg) and setup script (lb01.sh)
│   ├── web01/                Systemd unit (sentinel-web01.service), env template, and setup script
│   ├── web02/                Systemd unit (sentinel-web02.service), env template, and setup script
│   └── scripts/              Rolling deployment and HA verification scripts
└── .env.example              Environment configuration template


API overview

All endpoints are mounted under /api/v1. State-changing requests (POST, PUT, DELETE) require an authenticated session cookie and matching X-CSRF-Token header.

Area

Endpoints

System

GET /health, GET /ready, GET /version, GET /providers/status, POST /system/reset

Auth

POST /auth/login, POST /auth/logout, GET /auth/me

Scans

GET /scans, GET /scans/:id, GET /scans/:id/progress, POST /scans, POST /scans/:id/cancel, GET /scans/:id/compare/:otherId, GET & POST /scans/authorized-domains

Inventory

GET /assets, GET /dns, GET /exposures, GET /vulnerabilities, GET /findings

Dashboard

GET /dashboard/overview, GET /dashboard/risk-distribution, GET /dashboard/activity

Reports

GET /reports, GET & POST /reports/export (assets_csv, dns_csv, vulnerabilities_csv, consolidated_json)

Testing

cd backend
PGLITE_DATA_DIR=memory:// npm test   # Full suite using an isolated in-memory database
npm run test:unit                    # Provider parsers, risk engine, takeover analyzer, discovery validators
npm run test:integration             # REST API contracts, session cookies, CSRF, and RBAC enforcement
npm run test:e2e                     # End-to-end passive scan workflow


See docs/TESTING.md for details on each test suite.

Production deployment

SENTINEL is deployed across three Ubuntu 20.04 (ARM64) nodes serving https://kelvinnyagah.tech:

Node

Hostname

Public IP

Private IP

Role

Load Balancer

7378-lb-01

35.176.99.45

—

HAProxy 2.0 (HTTP :80 redirect + HTTPS :443 TLS termination)

Web Server 1

7378-web-01

35.177.149.1

10.30.10.93

Node.js 20 (sentinel-web01.service on :3000) + PostgreSQL 12 (:5432)

Web Server 2

7378-web-02

3.9.169.82

10.30.21.67

Node.js 20 (sentinel-web02.service on :3000)

1. DNS & network security

DNS A Records: Both @ (kelvinnyagah.tech) and www (www.kelvinnyagah.tech) resolve to 35.176.99.45 (7378-lb-01).

Firewall / Security Groups:

7378-lb-01 accepts inbound TCP 80 and 443 from 0.0.0.0/0.

7378-web-01 and 7378-web-02 accept inbound TCP 3000 only from the internal VPC subnet (10.30.0.0/19).

PostgreSQL (5432) on 7378-web-01 accepts connections only from 127.0.0.1 and 10.30.21.67 (7378-web-02) using md5 authentication.

2. Application nodes (7378-web-01 & 7378-web-02)

Both web servers run /opt/sentinel/backend/src/server.js as a dedicated sentinel system user via systemd (sentinel-web01.service and sentinel-web02.service), configured via /etc/sentinel/web01.env and /etc/sentinel/web02.env with DB_MODE=pg, NODE_ENV=production, CORS_ALLOWED_ORIGINS=https://kelvinnyagah.tech, and an identical 128-character SESSION_SECRET.

# Verify service status and database readiness on each node
sudo systemctl status sentinel-web01 --no-pager
curl -fsS http://127.0.0.1:3000/api/v1/ready


3. HAProxy & TLS termination (7378-lb-01)

7378-lb-01 runs HAProxy 2.0 configured via /opt/sentinel/deployment/haproxy/haproxy.cfg and deployed with /opt/sentinel/deployment/haproxy/lb01.sh:

Terminates TLS 1.2/1.3 on :443 using a Let's Encrypt certificate covering kelvinnyagah.tech and www.kelvinnyagah.tech (/etc/haproxy/certs/kelvinnyagah.tech.pem), with an automatic renewal deploy hook at /etc/letsencrypt/renewal-hooks/deploy/haproxy.sh.

Redirects external HTTP (:80) requests to HTTPS (301 Moved Permanently) while exposing /lb-health for local health verification.

Balances requests across web01 (10.30.10.93:3000) and web02 (10.30.21.67:3000) using roundrobin, active GET /api/v1/ready health checks (inter 5s fall 3 rise 2), and X-Load-Balancer: lb01 response headers.

4. Live verification results

Verified on 2026-11-25 against https://kelvinnyagah.tech:

Load-balancer verification (lb01.sh): 20/20 health requests succeeded with X-Load-Balancer: lb01 and an exact 50/50 split (Web01=10, Web02=10).

HTTPS & HTTP/2 endpoint check: curl -i https://kelvinnyagah.tech/api/v1/health returned HTTP/2 200 with x-load-balancer: lb01 and alternating x-sentinel-server: web01 / web02 headers.

Cross-node authentication: Signing in over HTTPS issues a Secure; HttpOnly; SameSite=Strict session cookie stored in PostgreSQL (user_sessions), keeping sessions active across requests routed to either web01 or web02.

Security notes

Authentication & session security: Passwords are stored as salted scrypt hashes. Session tokens and CSRF tokens are hashed in PostgreSQL (user_sessions). Session cookies use HttpOnly, SameSite=Strict, and Secure flags over HTTPS.

Input validation & SSRF protection: Target domains are validated against strict hostname rules and the authorized_domains allowlist; resolved IP addresses are checked against private, loopback, link-local, CGNAT, and reserved CIDR ranges before querying external APIs.

HTTP security headers & rate limiting: Express sets strict Content-Security-Policy, X-Frame-Options: DENY, X-Content-Type-Options: nosniff, and Permissions-Policy headers, alongside sliding-window rate limiters on authentication and scan endpoints.

Shodan InternetDB terms: Shodan InternetDB is used strictly for non-commercial academic/security assessment purposes in accordance with Shodan's terms of service.

Full details are documented in docs/SECURITY.md.

Troubleshooting

Symptom

Likely cause and fix

Login succeeds on /login.html but session does not persist

Ensure you are accessing https://kelvinnyagah.tech (HTTPS), as production cookies set the Secure flag

EADDRINUSE on start

Port 3000 is already bound; stop the existing process or update PORT

Pages load with empty states

No scans have been executed yet; sign in and run a scan from Scans

Scan reports partial provider failures

An upstream public API timed out or rate-limited; retry the scan or configure NVD_API_KEY

503 Service Unavailable from HAProxy

Verify sentinel-web01 and sentinel-web02 are running and port 3000 is reachable from 7378-lb-01

Credits and licensing

Data providers & external APIs

SENTINEL integrates the following public intelligence services (not affiliated with or endorsed by any provider):

crt.sh — Certificate Transparency log search operated by Sectigo

Cloudflare DNS-over-HTTPS (1.1.1.1) — Authoritative and recursive DNS resolution API

Shodan InternetDB — Passive public IP port, CPE, and CVE lookup API (non-commercial tier)

NIST National Vulnerability Database (NVD API 2.0) — U.S. National Institute of Standards and Technology CVE/CVSS enrichment API

Open-source software & assets

Node.js & Express — Backend runtime and HTTP framework

PostgreSQL, node-postgres (pg), & PGlite — Relational persistence and embedded local SQL engine

HAProxy & Certbot / Let's Encrypt — Layer 7 load balancing and automated TLS certificates

Lucide Icons — Inline SVG iconography (ISC License)

Author & license

Author: Kelvin Munene Nyagah (kelvinnyagah.tech)

License: All rights reserved unless otherwise specified by a repository LICENSE file.
codevibe report is also on the main directory repo
