# SENTINEL — Database Design & Persistence

## 1. Schema Overview (`backend/migrations/001_initial_schema.sql`)

SENTINEL uses PostgreSQL with 14 normalized tables:

1. `roles` — RBAC role definitions (`Administrator`, `Security Analyst`, `Read-only Auditor`).
2. `users` — Operator accounts with `scrypt` salted password hashes and foreign keys to `roles`.
3. `user_sessions` — Shared HTTP-only session tokens (SHA-256 hashed) and CSRF tokens accessible by both `Web01` and `Web02`.
4. `authorized_domains` — Explicit domain allowlist for scope validation.
5. `scans` — Master scan records including current stage, provider status summary, failures, and executive summary JSONB.
6. `scan_stages` — 11-stage progress tracking (`UNIQUE(scan_id, stage_number)`).
7. `assets` — Correlated discovered assets (`UNIQUE(scan_id, subdomain)`).
8. `dns_records` — Normalized Cloudflare DoH records (`A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `CAA`, `SOA`).
9. `ip_exposures` — Shodan InternetDB public IP enrichment records (`UNIQUE(scan_id, ip_address)`).
10. `cve_records` — Authoritative NIST NVD CVE records (`UNIQUE(scan_id, cve_id)`).
11. `findings` — Deterministic risk findings with severity, confidence, reason, supporting evidence, and remediation.
12. `certificates` — Normalized `crt.sh` certificate metadata (`UNIQUE(scan_id, certificate_id)`).
13. `api_provider_logs` — Upstream provider telemetry logs.
14. `audit_logs` — Immutable security audit trail tagged with `server_id` (`web01` or `web02`).

## 2. High-Availability Database Topology & Three-Server Constraint

- **Recommended Production Topology**: Host PostgreSQL on a dedicated managed database service (e.g., AWS RDS Multi-AZ, Cloud SQL, or Supabase PostgreSQL) outside `Web01` and `Web02`, configured via `DB_MODE=pg` and `DATABASE_URL`.
- **Three-Server Assignment Constraint (`Lb01`, `Web01`, `Web02`)**: If an infrastructure environment restricts deployment strictly to three VMs (`Lb01`, `Web01`, `Web02`) without an external managed PostgreSQL instance, hosting PostgreSQL on `Lb01` or `Web01` creates a single point of failure (SPOF) at the database tier even though the application tier (`Web01` + `Web02`) is redundant. For full database high availability, use a managed HA PostgreSQL service or a primary/standby PostgreSQL cluster with automatic failover.
