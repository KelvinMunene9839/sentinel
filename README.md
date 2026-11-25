# SENTINEL

**Cloud & Enterprise Attack Surface Intelligence Platform**

SENTINEL discovers and assesses the external attack surface of domains you are authorized to examine. It uses **passive reconnaissance only**: it reads public data sources and never probes, scans ports on, or sends traffic to the targets themselves. Findings are produced by a deterministic, explainable risk engine, and every finding carries its evidence, source, confidence and a recommended remediation.

- Frontend: vanilla HTML, CSS and ES6 JavaScript (no build step, no framework)
- Backend: Node.js 20+, Express, PostgreSQL (embedded PGlite for local development)
- Deployment target: two stateless app nodes (Web01, Web02) behind an HAProxy load balancer (Lb01)

---

## Contents

1. [What it does](#what-it-does)
2. [Quick start](#quick-start)
3. [Configuration](#configuration)
4. [Using the application](#using-the-application)
5. [Roles and permissions](#roles-and-permissions)
6. [Architecture](#architecture)
7. [Project structure](#project-structure)
8. [API overview](#api-overview)
9. [Testing](#testing)
10. [Deployment](#deployment)
11. [Security notes](#security-notes)
12. [Troubleshooting](#troubleshooting)
13. [Credits and licensing](#credits-and-licensing)

---

## What it does

| Capability | Source | Detail |
|---|---|---|
| Subdomain discovery | [crt.sh](https://crt.sh) Certificate Transparency logs | Finds certificates and the hostnames on them; deduplicates and strips wildcards |
| DNS intelligence | [Cloudflare DNS-over-HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/) | `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `CAA`, `SOA`; detects NXDOMAIN and dangling CNAMEs |
| Public IP exposure | [Shodan InternetDB](https://internetdb.shodan.io) | Open ports, CPEs, hostnames, tags and CVE associations per public IP |
| Vulnerability enrichment | [NIST NVD API 2.0](https://nvd.nist.gov/developers/vulnerabilities) | CVSS score, severity, description, CWE and references |
| Takeover risk analysis | Derived from DNS | Dangling CNAME and known cloud-service patterns, rated on a five-step confidence scale |
| Risk classification | Internal engine | Critical, High, Medium, Low and Informational, each with reason, evidence and remediation |
| Scan comparison | Stored scans | Shows new and removed assets, new open ports, new CVEs, DNS changes and risk changes between two scans |
| Reports | Stored scans | CSV (assets, DNS, vulnerabilities) and consolidated JSON exports |
| Audit log | Database | Records operator actions across both nodes |

### Evidence discipline

A CVE reported by InternetDB for an IP is an **observed association**, not proof the host runs a vulnerable build. SENTINEL labels every CVE this way and tells the operator to confirm the installed version and any backported patches before treating it as exploitable.

Takeover findings use a confidence scale of *Informational, Suspicious, Potentially vulnerable, Verified misconfiguration, Confirmed takeover*. SENTINEL never claims or registers external resources to verify a takeover.

### Scope enforcement

Scans run only against domains on the **authorized domain allowlist**, and the operator must attest to authorization on each scan. IP addresses are validated before any lookup, and private, loopback, link-local, CGNAT, multicast and documentation ranges are rejected to prevent server-side request forgery.

---

## Quick start

### Prerequisites

- **Node.js 20 or newer** (`node --version`)
- **npm**
- Outbound HTTPS access to `crt.sh`, `cloudflare-dns.com`, `internetdb.shodan.io` and `services.nvd.nist.gov`
- PostgreSQL is **optional**. By default the app uses PGlite, an embedded PostgreSQL that stores data in a local folder.

### Run it locally

```bash
# 1. Create your environment file
cp .env.example backend/.env

# 2. Install backend dependencies
cd backend
npm install

# 3. Create the schema and seed roles, users and default authorized domains
npm run migrate

# 4. Start the server
npm start
```

Open **http://localhost:3000**. The one Node process serves both the REST API (`/api/v1/*`) and the frontend, so there is no separate frontend server or build step.

For development with automatic restart on file changes, use `npm run dev` instead of `npm start`.

### Sign in

Migrations seed three accounts, one per role:

| Username | Password | Role |
|---|---|---|
| `admin` | `AdminPassword123!` | Administrator |
| `analyst` | `AnalystPassword123!` | Security Analyst |
| `auditor` | `AuditorPassword123!` | Read-only Auditor |

> **These are development credentials.** Change or remove them before exposing the application to any network you do not control. The sign-in page also offers quick-fill buttons for them, which should be removed for production.

You can browse the dashboard without signing in, but starting scans and changing scope require an Administrator or Security Analyst session.

### Run your first scan

1. Go to **Scans**.
2. Pick an authorized domain such as `iana.org` (default allowlist: `example.com`, `iana.org`, `nist.gov`, `cloudflare.com`, `shodan.io`).
3. Tick the authorization confirmation and choose **Start scan**.
4. Watch the pipeline stages complete, then open **Overview**, **Assets**, **Findings** and **Vulnerabilities**.

The NVD public API is rate limited, so a scan with many CVEs takes noticeably longer without an API key.

---

## Configuration

All settings are environment variables, read from `backend/.env` (or a root `.env`). See [.env.example](.env.example) for the complete list.

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `3000` | HTTP port |
| `SERVER_ID` | `web01` | Node name shown in the UI and audit log |
| `DB_MODE` | `pglite` | `pglite` (embedded) or `pg` (PostgreSQL via `DATABASE_URL`) |
| `DATABASE_URL` | none | PostgreSQL connection string, used when `DB_MODE=pg` |
| `PGLITE_DATA_DIR` | `../.sentinel_pgdata` | Where PGlite stores data |
| `SESSION_SECRET` | placeholder | **Must be replaced** with a long random value in production |
| `SESSION_COOKIE_NAME` | `sentinel_sid` | Session cookie name |
| `SESSION_TTL_HOURS` | `12` | Session lifetime |
| `CORS_ALLOWED_ORIGINS` | localhost origins | Comma-separated allowed origins |
| `DEFAULT_AUTHORIZED_DOMAINS` | five public domains | Allowlist seeded on first run |
| `CRTSH_BASE_URL`, `CRTSH_TIMEOUT_MS` | crt.sh, `15000` | Certificate Transparency provider |
| `CLOUDFLARE_DOH_URL`, `CLOUDFLARE_TIMEOUT_MS` | Cloudflare, `8000` | DNS provider |
| `SHODAN_INTERNETDB_URL`, `SHODAN_TIMEOUT_MS` | InternetDB, `8000` | Exposure provider |
| `NVD_API_BASE_URL`, `NVD_TIMEOUT_MS` | NVD 2.0, `12000` | Vulnerability provider |
| `NVD_API_KEY` | empty | Optional. Raises the NVD rate limit. Used server-side only, never sent to the browser |
| `NVD_RATE_LIMIT_DELAY_MS` | `2000` | Delay between NVD requests |

To use PostgreSQL instead of PGlite, set `DB_MODE=pg` and `DATABASE_URL`, then run `npm run migrate`.

---

## Using the application

| Page | What it is for |
|---|---|
| **Overview** | Summary figures, priority findings with recommended actions, risk distribution, open ports, recent assets and scans, provider health |
| **Assets** | Sortable, filterable inventory with column toggles, pagination and CSV/JSON export. Selecting a row opens a detail drawer (overview, DNS, certificates, exposures, vulnerabilities, history) |
| **DNS** | All stored records, filterable by type or text, with a per-host record view |
| **Findings** | Tabs for security findings, public IP exposure and subdomain takeover risk |
| **Vulnerabilities** | CVEs with CVSS and severity, plus a detail drawer with description, affected hosts and references |
| **Scans** | Start a scan, manage authorized scope, follow live pipeline progress, review history and compare two scans |
| **Reports** | Per-scan CSV and JSON downloads |
| **System menu** | Provider status, audit log, and settings (version, database mode, authorized domains, and a destructive *Clear data* action) |

The top search box accepts an asset name, IP address, or a CVE ID, and routes to the matching page. The sidebar collapses to icons, and the choice is remembered.

---

## Roles and permissions

| Role | View data | Start or cancel scans, edit scope |
|---|---|---|
| Administrator | Yes | Yes |
| Security Analyst | Yes | Yes |
| Read-only Auditor | Yes | No |

Authorization is enforced in the API (`requireRole` middleware), not only in the UI.

---

## Architecture

```text
crt.sh · Cloudflare DoH · Shodan InternetDB · NIST NVD
                         │
                         ▼
   Provider services (timeouts, bounded retries, backoff, caching)
                         │
   Validators (scope allowlist, SSRF and private-IP rejection)
                         │
   Discovery and correlation orchestrator
   subdomains → DNS → public IPs → exposures → CVEs
                         │
   Risk engine and takeover analyzer
                         │
   PostgreSQL (shared by all nodes: data, sessions, audit log)
                         │
   REST API /api/v1/*  +  static frontend
                         ▲
   HAProxy (Lb01) → Web01, Web02 (health check: /api/v1/ready)
```

Design points:

- **Stateless nodes.** Sessions, CSRF tokens and audit events live in the shared database, so either node can serve any request.
- **Graceful degradation.** If one provider fails, the scan continues with the remaining sources and records which provider failed. No data is fabricated.
- **No placeholder data.** The UI shows only stored results; with no scans it shows empty states.

Further detail is in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## Project structure

```text
.
├── frontend/                 Static UI served by the backend
│   ├── *.html                One file per page (dashboard, assets, dns, findings, ...)
│   ├── css/                  tokens.css (design tokens), layout.css, components.css, pages.css
│   └── js/                   shell.js (nav, topbar, system modals), api.js, charts.js, one script per page
├── backend/
│   ├── src/
│   │   ├── app.js, server.js
│   │   ├── config/           Environment-driven configuration
│   │   ├── database/         Connection, migration runner, repositories
│   │   ├── middleware/       Auth, CSRF, rate limiting, security headers
│   │   ├── routes/           One router per API area
│   │   ├── services/         providers, discovery, correlation, risk, reports
│   │   ├── utils/            Logger, audit, crypto
│   │   └── validators/       Domain, IP, CVE and network validation
│   ├── migrations/           SQL schema and seed data
│   └── tests/                unit, integration, e2e
├── deployment/               HAProxy config, systemd units for Web01/Web02, deploy and HA scripts
├── docs/                     Architecture, API integrations, database, security, operations, testing
└── .env.example              Configuration template
```

### Frontend design system

Styling is driven by CSS variables in `frontend/css/tokens.css`: a neutral graphite palette, a single blue accent for primary actions and the active nav item, and colour reserved for severity and error states. Components (panels, summary strips, tables, tags, buttons, drawers, modals) live in `components.css`. See [docs/UI_AUDIT.md](docs/UI_AUDIT.md).

---

## API overview

All routes are under `/api/v1`. State-changing requests require a session cookie and a CSRF token.

| Area | Endpoints |
|---|---|
| System | `GET /health`, `GET /ready`, `GET /version`, `GET /providers/status`, `POST /system/reset` |
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` |
| Scans | `GET /scans`, `GET /scans/:id`, `GET /scans/:id/progress`, `POST /scans`, `POST /scans/:id/cancel`, `GET /scans/:id/compare/:otherId`, `GET` and `POST /scans/authorized-domains` |
| Data | `GET /assets`, `/dns`, `/exposures`, `/vulnerabilities`, `/findings` (each with `/:id` where applicable) |
| Dashboard | `GET /dashboard/overview`, `/dashboard/risk-distribution`, `/dashboard/activity` |
| Reports | `GET /reports`, `GET` or `POST /reports/export` (`reportType`: `assets_csv`, `dns_csv`, `vulnerabilities_csv`, `consolidated_json`) |

Check the route files in `backend/src/routes/` for exact paths and parameters. Provider details are in [docs/API_INTEGRATIONS.md](docs/API_INTEGRATIONS.md).

---

## Testing

```bash
cd backend
npm test                 # everything
npm run test:unit        # provider parsing, risk engine, discovery
npm run test:integration # API behaviour and security controls
npm run test:e2e         # full scan workflow
```

See [docs/TESTING.md](docs/TESTING.md) for what each suite covers.

---

## Deployment

The reference topology is two app nodes behind HAProxy, sharing one PostgreSQL database.

- `deployment/haproxy/haproxy.cfg`: load balancer with active health checks on `/api/v1/ready`
- `deployment/web01/`, `deployment/web02/`: systemd units and environment templates
- `deployment/scripts/rolling-deploy.sh`: updates one node at a time so the service stays up
- `deployment/scripts/verify-ha-and-load.js`: checks failover and load distribution

Use `DB_MODE=pg` for any multi-node deployment (PGlite is single-process and not suitable). Give each node a distinct `SERVER_ID` and the same `SESSION_SECRET` and database. See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/LOAD_BALANCING.md](docs/LOAD_BALANCING.md) and [docs/OPERATIONS.md](docs/OPERATIONS.md).

---

## Security notes

- Passwords are stored as salted `scrypt` hashes. Session and CSRF tokens are stored hashed. Cookies are `HttpOnly` and `SameSite=Strict`.
- Login and API rate limiting are enabled.
- Use of the tool is limited to domains you own or are explicitly authorized to assess. The authorization attestation in the UI is a reminder, not a legal control.
- **Shodan InternetDB is licensed for non-commercial use only.** Commercial use requires a separate license from Shodan. The notice appears in the UI and in exported reports.
- Before production: replace `SESSION_SECRET`, change or remove the seeded accounts and the sign-in quick-fill buttons, terminate TLS at the load balancer, and restrict `CORS_ALLOWED_ORIGINS`.

Full details are in [docs/SECURITY.md](docs/SECURITY.md).

---

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| `EADDRINUSE` on start | Port 3000 is taken. Set `PORT` or stop the other process |
| Pages load but show no data | No scans yet. Run one from the Scans page |
| Scan reports provider failures | A public API was slow or unreachable. The scan still completes with the other sources. Retry later |
| NVD enrichment is slow | Public tier rate limit. Add `NVD_API_KEY` or lower *Max CVEs* |
| "Insufficient permissions" when scanning | Sign in as `admin` or `analyst`. The auditor role is read-only |
| Want a clean slate | System menu, Settings, *Clear data*. This deletes all scans and cached results and cannot be undone |
| Database errors after upgrading | Run `npm run migrate` again |

---

## Credits and licensing

**Data providers.** SENTINEL depends on free public services and is not affiliated with or endorsed by any of them:

- [crt.sh](https://crt.sh), Certificate Transparency search, by Sectigo
- [Cloudflare](https://www.cloudflare.com) DNS-over-HTTPS resolver
- [Shodan InternetDB](https://internetdb.shodan.io), free for non-commercial use
- [NIST National Vulnerability Database](https://nvd.nist.gov), U.S. National Institute of Standards and Technology

**Open-source components.**

- [Express](https://expressjs.com), web framework
- [node-postgres (`pg`)](https://node-postgres.com), PostgreSQL client
- [PGlite](https://github.com/electric-sql/pglite) by ElectricSQL, embedded PostgreSQL
- [dotenv](https://github.com/motdotla/dotenv), environment loading
- Icons are inline SVGs from [Lucide](https://lucide.dev) (ISC license)
- [HAProxy](https://www.haproxy.org) for load balancing in the reference deployment

**Development.** The UI refinement was carried out with assistance from Claude Code (Anthropic).

**License.** No license file is included in this repository, so all rights are reserved by the author until one is added. Add a `LICENSE` file before sharing or accepting contributions.

**Authors and maintainers.** Add project author names and contact details here.
