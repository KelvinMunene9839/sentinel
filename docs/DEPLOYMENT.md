# SENTINEL — Deployment Guide (`Lb01`, `Web01`, `Web02`)

## 1. Server Topology

| Node | Role | Private IP (Example) | Port | Service |
|------|------|----------------------|------|---------|
| **Lb01** | HAProxy Load Balancer | `10.0.10.10` | `80` / `8404` | HAProxy (`deployment/haproxy/haproxy.cfg`) |
| **Web01** | Application Server 1 | `10.0.10.11` | `3000` | Node.js / Express (`SERVER_ID=web01`) |
| **Web02** | Application Server 2 | `10.0.10.12` | `3000` | Node.js / Express (`SERVER_ID=web02`) |
| **DB01** | Shared PostgreSQL | `10.0.10.20` | `5432` | PostgreSQL 15+ (`sentinel` database) |

## 2. Step-by-Step Deployment on `Web01` and `Web02`

1. Install Node.js 20+ and Git on both `Web01` and `Web02`:
   ```bash
   sudo useradd -r -s /bin/false sentinel
   sudo mkdir -p /opt/sentinel /etc/sentinel
   sudo git clone <repo_url> /opt/sentinel
   cd /opt/sentinel/backend
   sudo npm ci --omit=dev
   ```
2. Configure environment files:
   - On `Web01`: Copy `deployment/web01/web01.env.example` to `/etc/sentinel/web01.env` (`SERVER_ID=web01`, `DB_MODE=pg`, shared `DATABASE_URL`).
   - On `Web02`: Copy `deployment/web02/web02.env.example` to `/etc/sentinel/web02.env` (`SERVER_ID=web02`, `DB_MODE=pg`, shared `DATABASE_URL`).
3. Run PostgreSQL database migrations once from `Web01`:
   ```bash
   cd /opt/sentinel/backend
   sudo -u sentinel env $(cat /etc/sentinel/web01.env | xargs) npm run migrate
   ```
4. Enable and start the `systemd` services:
   ```bash
   # On Web01:
   sudo cp /opt/sentinel/deployment/web01/sentinel-web01.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now sentinel-web01

   # On Web02:
   sudo cp /opt/sentinel/deployment/web02/sentinel-web02.service /etc/systemd/system/
   sudo systemctl daemon-reload && sudo systemctl enable --now sentinel-web02
   ```

## 3. Step-by-Step Deployment on `Lb01` (HAProxy)

1. Install HAProxy:
   ```bash
   sudo apt-get update && sudo apt-get install -y haproxy socat
   ```
2. Copy `deployment/haproxy/haproxy.cfg` to `/etc/haproxy/haproxy.cfg` and validate syntax:
   ```bash
   sudo haproxy -c -f /etc/haproxy/haproxy.cfg
   sudo systemctl restart haproxy
   ```
3. Verify load balancer health and backend rotation:
   ```bash
   curl -i http://10.0.10.10/lb-health
   curl -i http://10.0.10.10/api/v1/health
   ```
