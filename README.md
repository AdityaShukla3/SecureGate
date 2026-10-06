# SecureGate: Application-Layer API Security Gateway

> Standalone reverse-proxy API security gateway built with **Node.js/Express 5**, **PostgreSQL 16**, and **Redis 7**. Enforces IP filtering, atomic sliding-window rate limiting, JWT authentication with instant revocation, dynamic RBAC access control, secure proxying, and comprehensive audit logging for downstream backend microservices.

---

## 1. Architecture Overview

SecureGate sits in front of backend microservices that contain zero security logic of their own. Every incoming client request must pass through SecureGate's 6-point inspection pipeline before being forwarded to the target service with trusted identity headers and a shared gateway signature.

```
Client Request
      |
      v
+------------------------------- SecureGate (port 8080) -------------------------------+
|  1. IP Blocklist Check     (Redis blip:<ip>)                 -> 403 if blocked       |
|  2. Sliding-Window Limiter (Redis Lua script)                -> 429 if rate exceeded |
|  3. JWT Authentication     (Verification & Redis Blacklist)  -> 401 if invalid/revoked|
|  4. RBAC Permission Check  (Redis Cache + Postgres DB)       -> 403 if unauthorized  |
|  5. Reverse Proxy Forward  (http-proxy-middleware)           -> Injects id headers   |
|  6. Structured Audit Log   (PostgreSQL audit_logs)           -> Records key events   |
+--------------------------------------------------------------------------------------+
                 |                                      |
                 v                                      v
      logs-service (port 4001)               inventory-service (port 4002)
      [No internal auth code]                 [No internal auth code]
```

### The 6 Pipeline Checks
1. **IP Blocklist**: Checks `blip:${req.ip}` in Redis (preloaded from PostgreSQL `blocked_ips` on boot). Fails open on Redis downtime.
2. **Atomic Rate Limiter**: Evaluates request rate using an atomic Redis Lua script (`ZREMRANGEBYSCORE`, `ZCARD`, `ZADD`, `PEXPIRE`). Returns `429 Too Many Requests` with a `Retry-After` header. Fails open on Redis downtime.
3. **JWT Authentication & Revocation**: Validates short-lived access tokens (`15m`). Checks immediate token revocation against Redis blacklist (`bl:${jti}`). **Fails closed (503)** if Redis is unreachable because security takes precedence over availability.
4. **RBAC Authorization**: Compares user role permissions against route requirements. Cached in Redis (`perms:${role}`) for 5 minutes; falls back to relational Postgres joins on cache miss.
5. **Reverse Proxy & Secret Injection**: Strips client `Authorization` headers to ensure backends never see raw tokens; injects verified headers (`x-user-id`, `x-user-role`, `x-gateway-secret`). Handles backend down/timeouts cleanly with HTTP 502/504.
6. **Non-blocking Audit Logging**: Structured logging of sensitive events (logins, failures, lockouts, blocks, denials) into PostgreSQL. Fails quietly without aborting client requests.

---

## 2. API Endpoints

### Gateway-Owned Routes

| Method | Endpoint | Description | Auth / Role |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Gateway health check (checks DB & Redis connections) | Public |
| `POST` | `/auth/register` | Register new user account (defaults to `viewer`) | Public |
| `POST` | `/auth/login` | Login with email/pw; returns access & refresh tokens | Public (Rate limit 10/min) |
| `POST` | `/auth/refresh` | One-time rotating refresh token exchange | Public (Valid refresh token) |
| `POST` | `/auth/logout` | Revokes access token in Redis & deletes refresh token | Authenticated |
| `POST` | `/admin/ips/block` | Add IP to persistent blocklist | `ips:manage` (`admin`) |
| `DELETE` | `/admin/ips/:ip` | Remove IP from blocklist | `ips:manage` (`admin`) |
| `PATCH` | `/admin/users/:id/role` | Update user role (`viewer`, `analyst`, `admin`) | `users:manage` (`admin`) |
| `GET` | `/admin/audit` | Query audit trail by action, status, and limit | `audit:read` (`analyst`, `admin`) |

### Proxied Microservice Routes

| Method | Endpoint | Proxied To | Required Permission | Allowed Roles |
| :--- | :--- | :--- | :--- | :--- |
| `GET` | `/api/logs` | `LOGS_URL` (`:4001`) | `logs:read` | `analyst`, `admin` |
| `GET` | `/api/inventory` | `INVENTORY_URL` (`:4002`) | `inventory:read` | `viewer`, `analyst`, `admin` |
| `POST` | `/api/inventory` | `INVENTORY_URL` (`:4002`) | `inventory:write` | `admin` |
| `DELETE` | `/api/inventory` | `INVENTORY_URL` (`:4002`) | `inventory:write` | `admin` |

---

## 3. Threat Defense Mechanisms

- **5-Strike Account Lockout**:
  Tracks consecutive failed login attempts in Redis (`fail:${email}`). After 5 failed attempts within 15 minutes, the account is temporarily locked (`lock:${email}` with 15m TTL).
- **Credential Stuffing Auto-Block**:
  Monitors each IP's failed attempts across distinct emails using a Redis Set (`stuff:${req.ip}`). If an IP attempts 10+ different email addresses within 10 minutes, the gateway automatically bans the IP (`blip:${req.ip}`) for 1 hour.
- **Refresh Token Rotation**:
  Every refresh token (`rt:${jti}`) stored in Redis is single-use. When used to refresh, the current token is immediately destroyed and a new pair is issued. Replaying an old refresh token returns `401 Refresh token revoked`.
- **Stateless Revocation via Blacklist**:
  When users log out, the token's remaining validity is calculated and stored in Redis (`bl:${jti}` with TTL = remaining seconds). Expired entries are automatically evicted by Redis without manual cleanup.
- **Direct Backend Access Prevention**:
  Dummy backends require `x-gateway-secret` header. Any request made directly to backend ports (bypassing the gateway) returns `403 Direct access not allowed`.

---

## 4. Getting Started

### Prerequisites
- Node.js 20+
- Docker & Docker Compose
- Git

### Local Development Setup

1. **Clone repository**:
   ```bash
   git clone <repo-url>
   cd securegate
   ```

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start local Postgres & Redis with Docker**:
   ```bash
   docker compose -f docker-compose.dev.yml up -d
   ```

4. **Initialize database schema & seed initial admin**:
   ```bash
   npm run init
   ```
   *Creates tables, roles, permissions, and initial admin `admin@securegate.dev` / `Admin@12345`.*

5. **Start dummy backend microservices** (in separate terminals or background):
   ```bash
   npm run svc:logs     # Runs logs-service on port 4001
   npm run svc:inv      # Runs inventory-service on port 4002
   ```

6. **Start the gateway**:
   ```bash
   npm run dev          # Runs SecureGate on port 8080 with nodemon
   ```

### Running the Full System with Docker Compose

To run the complete production topology (Gateway + Postgres + Redis + 2 Backends) with isolated networking where **only port 8080 is published**:

```bash
docker compose up -d --build
docker compose run --rm gateway node src/db/init.js
curl http://localhost:8080/health
```

### Running Tests

```bash
npm test
```
*Executes the complete Jest + Supertest suite verifying authentication, RBAC, lockout, IP blocks, rate limits, token revocation, and proxy routing.*

---

## 5. Architectural & Design Decisions

| Decision | Implementation | Rationale |
| :--- | :--- | :--- |
| **Fail Open vs Fail Closed** | Rate Limit & IP Block: **Fail Open**<br>JWT Revocation: **Fail Closed** | Rate limiting and IP blocking prioritize availability so temporary Redis blips don't take down legitimate traffic. Auth revocation prioritizes security: if we can't confirm whether a token is revoked, we must reject it (503). |
| **Atomic Sliding-Window Limiter** | Redis Lua Script | Check-then-write patterns in Redis are vulnerable to race conditions under concurrent requests. Evaluating timestamps inside an atomic Lua script guarantees correctness without locking. |
| **Redis vs Postgres Roles** | Fast State in Redis, Durability in Postgres | Fast-changing transient state (rate limits, lockout counters, token blacklists) belongs in memory with automatic TTL cleanup. Persistent business data (users, roles, permissions, audit logs) belongs in Postgres. |
| **Identity Header Injection** | Gateway strips `Authorization`, sets `x-user-*` | Downstream services stay simple and don't need JWT parsing or cryptographic dependencies. A shared gateway secret validates the request came from the trusted proxy. |

---

## 6. Performance Benchmarking (autocannon)

To measure gateway latency overhead and throughput:

```bash
# 1. Obtain admin token
TOKEN=$(curl -s -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@securegate.dev","password":"Admin@12345"}' | jq -r .access)

# 2. Benchmark gateway throughput (set RATE_LIMIT=100000 in .env first)
npx autocannon -c 20 -d 10 -H "Authorization: Bearer $TOKEN" http://localhost:8080/api/inventory

# 3. Benchmark direct backend service (baseline)
npx autocannon -c 20 -d 10 -H "x-gateway-secret: replace-with-another-long-random-string" http://localhost:4002/
```

- **Gateway Overhead**: Difference between gateway p50/p99 latency vs direct backend baseline.

### Measured Performance Results

| Test | Requests/sec | Typical (p50) | Slowest 1% (p99) |
| :--- | :--- | :--- | :--- |
| Through the gateway | 1,656 req/s | 64 ms | 163 ms |
| Directly to the backend | 2,948 req/s | 4 ms | 35 ms |

*Machine: 12th Gen Intel Core i5-12500H (12 cores), 16 GB RAM, Windows 11, Node.js 22.*
*Gateway Overhead: ~60 ms median latency added across the full 6-point inspection pipeline (IP check, sliding-window rate limit, JWT verification, Redis revocation blacklist check, RBAC lookup, proxy forwarding).*

---

## 7. 5-Minute Live Demo Script

Follow this script to demonstrate all security capabilities during interview presentations:

1. **Health Check**: Call `GET http://localhost:8080/health` $\rightarrow$ returns `{ db: "up", redis: "up" }`.
2. **Direct Access Rejection**: Call `http://localhost:4002/` directly without gateway secret $\rightarrow$ returns `403 Direct access not allowed`.
3. **Register & Proxy**: Register user (`POST /auth/register`), log in (`POST /auth/login`), call `GET /api/inventory` $\rightarrow$ returns 200 with data showing `x-user-id` and `x-user-role`.
4. **RBAC Enforcement**: Same viewer attempts `GET /api/logs` $\rightarrow$ returns `403 Forbidden` (`viewer lacks logs:read`).
5. **Audit Trail**: Admin logs in and calls `GET /admin/audit` $\rightarrow$ displays log of previous login attempts and 403 access denials.
6. **Account Lockout**: Call `POST /auth/login` 5 times with wrong password $\rightarrow$ 6th attempt with correct password returns `429 Account temporarily locked`.
7. **Rate Limiting**: Burst requests to `/auth/login` $\rightarrow$ returns `429 Too Many Requests` with `Retry-After` header.
8. **Admin IP Blocking**: Admin posts to `POST /admin/ips/block` $\rightarrow$ target IP subsequently receives `403 IP blocked`.
9. **Token Revocation**: Call `POST /auth/logout` with bearer token $\rightarrow$ subsequent calls with same access token return `401 Token revoked`.
10. **Resilience / Fault Tolerance**: Kill the `inventory` service process and call `/api/inventory` $\rightarrow$ gateway returns clean `502 Upstream service unavailable`.

---

## 8. Honest Limitations & Future Work

As an application-layer learning gateway, SecureGate was intentionally designed with the following known trade-offs:

1. **Role Update Latency**: User roles are embedded in access JWTs. A database role change takes effect when the token expires (up to 15 minutes). *Production alternative*: Query Redis role cache per request.
2. **Single Point of Failure**: Gateway currently runs as a single instance. *Production alternative*: Multi-instance deployment behind HAProxy/AWS ALB with Redis Cluster.
3. **Symmetric Secrets (HS256)**: Access tokens use symmetric signing. *Production alternative*: Asymmetric RS256 or EdDSA with public key distribution.
4. **Internal Network Security**: Traffic between gateway and microservices is plain HTTP. *Production alternative*: Mutual TLS (mTLS) in a Service Mesh (Istio / Linkerd).
5. **Audit Table Scaling**: High request volume can cause PostgreSQL `audit_logs` to grow rapidly. *Production alternative*: Stream audit records to Apache Kafka / Cloud PubSub for ingestion into BigQuery or Elasticsearch.
6. **Account lockout can be abused**: Someone who knows your email can fail 5 logins on purpose and lock you out for 15 minutes. *Better version*: Also inspect visitor's IP address, or add a CAPTCHA.
7. **Audit log can flood**: A blocked address still writes a log row on every request, so the table can grow fast. *Better version*: One log row per minute per blocked address.
