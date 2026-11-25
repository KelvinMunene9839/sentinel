# SENTINEL — Operations & Maintenance Runbook

## 1. Routine Health & Readiness Monitoring

- **Application Liveness (`Web01` / `Web02`)**: `GET /api/v1/health`
- **Database & Readiness Probe (`Web01` / `Web02`)**: `GET /api/v1/ready`
- **External Intelligence Providers Telemetry**: `GET /api/v1/providers/status`
- **HAProxy Load Balancer Health (`Lb01`)**: `GET /lb-health`

## 2. Zero-Downtime Rolling Upgrades

Execute `deployment/scripts/rolling-deploy.sh` to upgrade `Web01` and `Web02` sequentially without dropping active user traffic:
1. Drains `web01` in HAProxy (`state maint`).
2. Upgrades `web01`, runs idempotent PostgreSQL migrations (`npm run migrate`), restarts `sentinel-web01`, and waits for `/api/v1/ready` to return `200 OK`.
3. Restores `web01` to active rotation (`state ready`).
4. Repeats the drain, upgrade, readiness check, and restore sequence on `web02`.

## 3. Managing Authorized Reconnaissance Scope

- Default authorized domains are configured via `DEFAULT_AUTHORIZED_DOMAINS` in `.env` and persisted in the `authorized_domains` PostgreSQL table.
- Administrators and Security Analysts can add newly authorized domains at runtime via the **Domain Discovery & Scans** UI (`/scans.html`) or `POST /api/v1/scans/authorized-domains`.
- Every scope modification and scan initiation is recorded in the `audit_logs` table with user attribution, timestamp, client IP, and `server_id`.
