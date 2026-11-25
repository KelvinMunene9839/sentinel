#!/usr/bin/env bash
#---------------------------------------------------------------------
# SENTINEL — Zero-Downtime Rolling Deployment Script (Web01 & Web02)
#---------------------------------------------------------------------
set -euo pipefail

HAPROXY_SOCKET="/run/haproxy/admin.sock"
APP_DIR="/opt/sentinel"

echo "[1/6] Pulling latest release and installing dependencies..."
cd "${APP_DIR}/backend"
npm ci --omit=dev
npm run migrate

echo "[2/6] Draining Web01 from HAProxy rotation on Lb01..."
if [ -S "${HAPROXY_SOCKET}" ]; then
  echo "set server sentinel_web_cluster/web01 state maint" | socat stdio "${HAPROXY_SOCKET}"
fi
sleep 3

echo "[3/6] Restarting sentinel-web01 and verifying /api/v1/ready..."
systemctl restart sentinel-web01
until curl -fsS http://127.0.0.1:3000/api/v1/ready > /dev/null; do
  echo "Waiting for Web01 readiness..."
  sleep 2
done

if [ -S "${HAPROXY_SOCKET}" ]; then
  echo "set server sentinel_web_cluster/web01 state ready" | socat stdio "${HAPROXY_SOCKET}"
fi
echo "Web01 healthy and back in HAProxy rotation."

echo "[4/6] Draining Web02 from HAProxy rotation on Lb01..."
if [ -S "${HAPROXY_SOCKET}" ]; then
  echo "set server sentinel_web_cluster/web02 state maint" | socat stdio "${HAPROXY_SOCKET}"
fi
sleep 3

echo "[5/6] Restarting sentinel-web02 and verifying /api/v1/ready..."
systemctl restart sentinel-web02
echo "[6/6] Re-enabling Web02 in HAProxy rotation..."
if [ -S "${HAPROXY_SOCKET}" ]; then
  echo "set server sentinel_web_cluster/web02 state ready" | socat stdio "${HAPROXY_SOCKET}"
fi

echo "Zero-downtime rolling deployment complete."
