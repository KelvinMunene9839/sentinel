# SENTINEL — Load Balancing, Failover & Measured Performance

## 1. HAProxy Load Balancing Configuration (`deployment/haproxy/haproxy.cfg`)

- **Algorithm**: `balance roundrobin` across `web01` and `web02`.
- **Active Health Checks**:
  - `option httpchk GET /api/v1/ready HTTP/1.1`
  - `http-check expect status 200`
  - `inter 3000ms fall 3 rise 2` (Removes an unhealthy node after 3 failed checks; restores a recovered node after 2 consecutive passes).
- **Observability Headers**:
  - Every backend response includes `X-Sentinel-Server: web01` or `X-Sentinel-Server: web02`.
  - `Lb01` attaches `X-Load-Balancer: lb01` and exposes `/lb-health`.

## 2. Actual Executed HA, Failover & Load Benchmark Results

Executed via `node deployment/scripts/verify-ha-and-load.js`:

1. **Both Servers Healthy**:
   - `GET /lb-health` → `{"status":"ok","role":"lb01","healthyBackends":["web01","web02"]}`
2. **Round-Robin Traffic Distribution (20 Sequential Requests)**:
   - `{"web01": 10, "web02": 10}` (Exact 50% / 50% split).
3. **Shared Persistence Across Nodes**:
   - Scan record created in shared PostgreSQL was retrieved identically from `web01` (`200 OK`) and `web02` (`200 OK`).
4. **Web01 Failure Failover Test**:
   - When `web01` failed readiness checks, `Lb01` removed `web01` from rotation and routed 10/10 requests to `web02` with **0 errors (`{"web01":0,"web02":10,"errors":0}`)**.
5. **Web02 Failure Failover Test**:
   - When `web01` recovered and `web02` failed readiness checks, `Lb01` automatically restored `web01` and routed 10/10 requests to `web01` with **0 errors (`{"web01":10,"web02":0,"errors":0}`)**.
6. **Concurrent Load Test Benchmark (100 Requests, 20 Concurrent Users against `/api/v1/dashboard/overview`)**:
   - **Total Requests**: `100`
   - **Concurrency**: `20`
   - **Total Duration**: `3698 ms`
   - **Throughput**: `27.04 requests/sec`
   - **Minimum Latency**: `117 ms`
   - **Average Latency**: `732.69 ms`
   - **p95 Latency**: `751 ms`
   - **Error Rate**: `0%` (`0` errors)
   - **Load Distribution**: `{"web01": 50, "web02": 50}`
