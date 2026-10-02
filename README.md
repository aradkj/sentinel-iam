# Secure Identity & Access Management Service (IAM)

![Python 3.12+](https://img.shields.io/badge/Python-3.12%2B-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688?logo=fastapi&logoColor=white)
![JWT RS256](https://img.shields.io/badge/JWT-RS256%20(2048--bit)-6366f1)
![PostgreSQL 17](https://img.shields.io/badge/PostgreSQL-17-4169E1?logo=postgresql&logoColor=white)
![Redis 7](https://img.shields.io/badge/Redis-7-DC382D?logo=redis&logoColor=white)
![Docker Compose](https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white)

---

## 1. Project Overview

The **Secure Identity & Access Management Service (IAM)** is a hardened, enterprise-grade Identity Provider (IdP) and Authentication/Authorization microservice built with **FastAPI**, **SQLAlchemy 2.x (Async)**, **Alembic**, **PostgreSQL 17**, **Redis 7**, **PyJWT (RS256)**, **Passlib/bcrypt**, **Authlib**, and **PyOTP**.

It includes a responsive **Vanilla HTML5/CSS3/JS Dark-Theme Frontend Console** served via **Nginx** and exposes versioned REST endpoints under `/api/v1/*` alongside unversioned health probes (`/health`, `/health/live`, `/health/ready`).

---

## 2. Architecture

### Mermaid Architecture Diagram

```mermaid
flowchart TD
    Browser["Browser / Client App"] --> Nginx["Nginx Frontend (:8080)"]
    Browser --> API["FastAPI IAM Service (:8000 /api/v1)"]
    Nginx --> API
    API --> PG[("PostgreSQL 17 (:5432)")]
    API --> Redis[("Redis 7 (:6379)")]
    API --> MailHog["MailHog SMTP (:1025 / :8025)"]
    API --> OAuth["Google & GitHub OAuth2"]
    PG --> Audit["Immutable Audit Logs"]
```

### ASCII Architecture Overview

```text
                    Browser
                       |
                       v
             Nginx Frontend (:8080)
                       |
                       v
          FastAPI API (:8000 /api/v1)
             /         |         \
            /          |          \
           v           v           v
     PostgreSQL 17   Redis 7   OAuth2 / MailHog
           |
           v
      Audit Logs
```

---

## 3. Technology Stack

- **Backend Framework**: Python 3.12+, FastAPI, Uvicorn
- **ORM & Migrations**: SQLAlchemy 2.x (`AsyncSession`), Alembic, `asyncpg`
- **Data Stores**: PostgreSQL 17 (relational identity/session/audit store), Redis 7 (JWT blacklist, session cache, rate limiter)
- **Cryptography & Auth**: `PyJWT[crypto]` (`RS256` 2048-bit RSA), `passlib[bcrypt]`, `Authlib` (OAuth2), `PyOTP` (RFC 6238 TOTP)
- **Frontend**: HTML5, CSS3, Vanilla ES6 JavaScript, Nginx (`nginx:alpine`)
- **Testing & CI**: Pytest, `pytest-asyncio`, `httpx`, GitHub Actions

---

## 4. Features

- Versioned REST API (`/api/v1/*`) with organized OpenAPI documentation (`/docs`, `/redoc`, `/api/v1/docs`, `/api/v1/redoc`)
- Strict Content-Security-Policy and hardened security headers on both the FastAPI application and the Nginx frontend
- Asymmetric `RS256` JWT signing (`private.pem`) and public key distribution (`/api/v1/auth/public-key`)
- Refresh token rotation with `SHA-256` database hashing and token reuse/theft detection
- Immediate JWT revocation via Redis blacklist (`blacklist:{jti}`)
- Multi-device session tracking (`sessions` table) with single-device (`DELETE /api/v1/sessions/{id}`) and global (`POST /api/v1/sessions/revoke-all`) revocation
- Brute-force account lockout (`HTTP 423 Locked` for 15 minutes after 5 failed login attempts)
- Per-IP Redis rate limiting (`HTTP 429 Too Many Requests` above 5 req/min on login & registration)
- Email verification (`email_verifications` table) & one-time password reset (`password_reset_tokens` table) via MailHog SMTP
- Two-Factor Authentication (TOTP 2FA via `pyotp`)
- Google & GitHub OAuth2 login (`/api/v1/auth/google/login`, `/api/v1/auth/github/login`)
- Granular Role-Based Access Control (RBAC) via `Depends(require_permission(...))`
- Secret-safe structured security logging and PostgreSQL `audit_logs`
- Hardened non-root Docker image (`appuser`) and environment-driven CORS (`ALLOWED_ORIGINS`)

---

## 5. Authentication Flow

1. **Registration (`POST /api/v1/auth/register`)**: Validates input, hashes password with `bcrypt`, assigns default `user` role, creates a one-time `SHA-256` hashed token in `email_verifications`, and dispatches verification email via MailHog.
2. **Email Verification (`GET /api/v1/auth/verify-email/{token}`)**: Marks token `used = true` and `user.is_verified = true`.
3. **Login (`POST /api/v1/auth/login`)**:
   - Checks Redis rate limit (`5 req/min/IP`).
   - Checks `user.locked_until`: returns `423 Locked` if active.
   - Verifies password: increments `failed_login_attempts` on failure (locking for 15m at 5 attempts); resets counter and updates `last_login_at` on success.
   - If `two_factor_enabled` is true, returns a 5-minute single-use `temp_token` (`type="2fa_temp"`) for `POST /api/v1/auth/verify-otp`.
   - Issues `RS256` `access_token` (`15m`) and `refresh_token` (`7d`), records device session in PostgreSQL (`sessions`) and Redis, and logs `LOGIN_SUCCESS`.

---

## 6. JWT RS256 Explanation & Local Key Generation

Tokens are signed with an **RSA 2048-bit private key** (`private.pem`) and verified with the corresponding **RSA public key** (`public.pem`). Private keys are **never** committed to Git (`.gitignore` and `.dockerignore` exclude `*.pem`).

### Generating Local Development Keys

```bash
mkdir -p keys
openssl genrsa -out keys/private.pem 2048
openssl rsa -in keys/private.pem -pubout -out keys/public.pem
chmod 600 keys/private.pem
```

Or using the included helper script:

```bash
python scripts/generate_keys.py
```

The GitHub Actions workflow (`.github/workflows/ci.yml`) generates a throwaway 2048-bit keypair into `security/` immediately before running migrations and `pytest`, so CI exercises real RS256 signing without any private key ever being committed.

*(Note: In automated test suites or ephemeral environments where `./keys/private.pem` has not been created on disk yet, the application generates an in-memory 2048-bit RSA keypair automatically so tests run out-of-the-box without committing private keys to Git.)*

---

## 7. RBAC Explanation

Users are associated with **Roles** (`user_roles`), and Roles are associated with granular **Permissions** (`role_permissions`):

- **`admin`**: `user.create`, `user.read`, `user.update`, `user.delete`, `report.view`, `role.manage`
- **`employee`**: `report.view`
- **`user`**: self-service profile and session endpoints

All `/api/v1/admin/*` routes enforce permissions on the backend via `Depends(require_permission("<perm>"))`. Even if a non-admin manually invokes `DELETE /api/v1/admin/users/1`, the backend returns `403 Forbidden`.

---

## 8. Session Management

Every login records a device session in PostgreSQL (`sessions` table) with `device_name` (parsed from `User-Agent`), `ip_address`, `user_agent`, `last_activity`, `expires_at`, and linked JWT IDs (`jti`, `refresh_jti`):

- `GET /api/v1/sessions` — List active sessions for the current user.
- `DELETE /api/v1/sessions/{id}` — Revoke a specific device session and blacklist its JWT in Redis.
- `POST /api/v1/sessions/revoke-all` — Logout all devices and revoke all active tokens.

---

## 9. Redis Blacklist

When a user logs out (`POST /api/v1/auth/logout`) or revokes a session, the JWT `jti` is stored in Redis under `blacklist:{jti} = "true"` with a TTL equal to the token's remaining lifetime (`exp - now`). Every authenticated request verifies that its `jti` is not blacklisted, returning `401 Unauthorized` immediately if revoked.

---

## 10. Rate Limiting

`RateLimitMiddleware` and `rate_limit_dependency` use Redis per-IP counters (`ratelimit:{scope}:{ip}`) to limit `/api/v1/auth/login` and `/api/v1/auth/register` to **5 requests per IP per minute**, returning `429 Too Many Requests` with `Retry-After`, `X-RateLimit-Limit`, and `X-RateLimit-Remaining` headers.

---

## 11. Account Lockout

The `users` table tracks `failed_login_attempts`, `locked_until`, and `last_login_at`. After **5 consecutive failed password attempts**, `locked_until` is set to `now + 15 minutes`, an `ACCOUNT_LOCKED` audit event is recorded, and subsequent login attempts return `HTTP 423 Locked`.

---

## 12. Email Verification & Password Reset

- **Email Verification (`email_verifications`)**: Tokens are generated with `secrets.token_urlsafe(32)`, hashed with `SHA-256`, and emailed via MailHog SMTP (`mailhog:1025`). Verified via `GET /api/v1/auth/verify-email/{token}` or re-sent via `POST /api/v1/auth/resend-verification`.
- **Password Reset (`password_reset_tokens`)**: Requested via `POST /api/v1/auth/forgot-password` and consumed once via `POST /api/v1/auth/reset-password`, which updates the password, clears any lockout, and revokes all active sessions.

---

## 13. OAuth2 (Google & GitHub)

Implemented with **Authlib** under:
- **Google**: `GET /api/v1/auth/google/login` & `GET /api/v1/auth/google/callback`
- **GitHub**: `GET /api/v1/auth/github/login` & `GET /api/v1/auth/github/callback`

### Manual OAuth2 Provider Setup
To test live OAuth2 redirects against Google or GitHub:
1. Create an OAuth 2.0 Client in Google Cloud Console / GitHub Developer Settings.
2. Set the callback URLs to `http://localhost:8000/api/v1/auth/google/callback` and `http://localhost:8000/api/v1/auth/github/callback`.
3. Populate `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, and `GITHUB_CLIENT_SECRET` in `.env`.
*(Automated tests in `tests/test_hardening.py` verify the redirect and callback flows using mocked Authlib provider responses.)*

---

## 14. Two-Factor Authentication (2FA)

Uses `pyotp` (RFC 6238 TOTP):
- `POST /api/v1/users/enable-2fa`: Generates Base32 secret and `otpauth://` provisioning URI.
- `POST /api/v1/auth/verify-otp`: Verifies the 6-digit TOTP code and exchanges the temporary `2fa_temp` token for full `access_token` and `refresh_token`.
- `POST /api/v1/users/disable-2fa`: Disables TOTP 2FA.

---

## 15. Audit Logging

Security events (`LOGIN_SUCCESS`, `LOGIN_FAILED`, `ACCOUNT_LOCKED`, `LOGOUT`, `TOKEN_REVOKED`, `SESSION_REVOKED`, `PASSWORD_CHANGED`, `ROLE_CREATED`, `ROLE_UPDATED`, `PERMISSION_CHANGED`) are persisted in `audit_logs` (`event_type`, `description`, `ip_address`, `user_agent`, `metadata`) and emitted via `app/core/logging.py` with automatic redaction of sensitive fields (`password`, `token`, `secret`, `otp_code`).

---

## 16. Frontend Console

Located in `frontend/` and built with **pure HTML5, CSS3, and Vanilla JavaScript**:
- `index.html` — Landing page & system status links
- `login.html` — Login, 2FA OTP step, Remember session toggle, Google/GitHub OAuth2 buttons
- `register.html` — Registration form with email verification workflow
- `dashboard.html` — User identity details & metric cards (Active Sessions, Account Status, 2FA Status)
- `profile.html` — Password update & 2FA TOTP provisioning
- `sessions.html` — Active device sessions table & single/global revocation
- `admin.html` — Admin Console for user activation/deactivation/deletion, role & permission creation, and audit log inspection

All frontend requests route through `frontend/js/api.js` using `/api/v1/*` endpoints.

---

## 17. Docker Architecture

- **`api` (`iam-api`)**: Python 3.12-slim running as non-root `appuser` (UID `10001`) on port `8000` with healthcheck `GET /health`.
- **`postgres` (`iam-postgres`)**: PostgreSQL 17 on port `5432` with `pg_isready` healthcheck.
- **`redis` (`iam-redis`)**: Redis 7 on port `6379` with `redis-cli ping` healthcheck.
- **`mailhog` (`iam-mailhog`)**: SMTP server on port `1025` and Web UI on port `8025`.
- **`frontend` (`iam-frontend`)**: Nginx Alpine serving the frontend on port `8080:80` and proxying `/api/v1/*` to `api:8000`.

---

## 18. Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Key variables:
- `ALLOWED_ORIGINS=http://localhost,http://localhost:80,http://localhost:3000,http://localhost:8080`
- `POSTGRES_DB=iam_db`, `POSTGRES_USER=iam_user`, `POSTGRES_PASSWORD=change_me`
- `DATABASE_URL=postgresql+asyncpg://iam_user:change_me@postgres:5432/iam_db`
- `REDIS_URL=redis://redis:6379/0`
- `JWT_ALGORITHM=RS256`, `JWT_PRIVATE_KEY_PATH=/app/keys/private.pem`, `JWT_PUBLIC_KEY_PATH=/app/keys/public.pem`
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`

---

## 19. Database Migrations (Alembic)

Migrations are stored in `migrations/versions/`:
- `20261001_0001_initial_migration.py`: Creates `permissions`, `roles`, `users`, `role_permissions`, `user_roles`, `refresh_tokens`, `audit_logs`.
- `20261001_0002_enterprise_iam_upgrade.py`: Adds lockout columns to `users`, upgrades `audit_logs`, and creates `sessions`, `email_verifications`, and `password_reset_tokens`.

```bash
alembic upgrade head
alembic current
alembic history
```

---

## 20. Testing

Run the full 32-test suite with `pytest`:

```bash
pytest -v
```

---

## 21. API Documentation

Interactive documentation is served at:
- **Swagger UI**: `http://localhost:8000/docs` (alias: `http://localhost:8000/api/v1/docs`)
- **ReDoc**: `http://localhost:8000/redoc` (alias: `http://localhost:8000/api/v1/redoc`)
- **Health Check**: `http://localhost:8000/health` (`{"status": "ok", "database": "ok", "redis": "ok"}`)

### Route Versioning Policy (Final)

Only two route surfaces are exposed:

| Surface | Examples | Notes |
| --- | --- | --- |
| Versioned application API | `POST /api/v1/auth/login`, `GET /api/v1/users/me`, `GET /api/v1/sessions` | The only public application surface; everything here appears in the OpenAPI schema. |
| Unversioned health & docs | `GET /health`, `GET /health/live`, `GET /health/ready`, `GET /docs`, `GET /redoc`, `GET /openapi.json` | Infrastructure probes and documentation only. |

**Unversioned legacy application routes (`/auth/*`, `/users/*`, `/sessions/*`, `/roles/*`, `/permissions/*`, `/admin/*`) have been removed** and now return `HTTP 404 Not Found`. They were never documented in the OpenAPI schema, had no independent consumers, and duplicated the versioned contracts — so the project keeps a single, unambiguous API surface. The frontend (`frontend/js/api.js`) and the entire test suite call `/api/v1/*` exclusively.

---

## 22. Security Considerations

- **CORS**: Wildcard `*` is forbidden; origins are parsed strictly from `ALLOWED_ORIGINS`.
- **Token Storage Tradeoff**: The standalone Vanilla JS frontend stores short-lived (`15m`) access tokens in `sessionStorage` by default (or `localStorage` if "Remember session" is explicitly selected) to support cross-origin API calls, mitigated by strict CSP/XSS hygiene, 15-minute access token expiry, single-use refresh token rotation with reuse detection, and server-side Redis JTI blacklisting.
- **Error Sanitization**: Global exception handlers intercept `SQLAlchemyError` and `RedisError` and return sanitized `503 Service Unavailable` responses without leaking internal stack traces or connection strings.
- **Content Security Policy (CSP)**: A strict CSP is enforced in two places — `frontend/nginx.conf` (production Nginx edge) and the API security-header middleware in `app/main.py`:

  ```text
  default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:;
  connect-src 'self'; font-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
  ```

  `unsafe-inline` and `unsafe-eval` are **not** used: all CSS lives in `frontend/css/style.css`, all JavaScript lives in external files under `frontend/js/`, and dynamic DOM rendering uses `addEventListener` with `data-*` attributes instead of inline `onclick` handlers or `style="..."` attributes.
- **Security Headers**: `X-Content-Type-Options: nosniff`, `Referrer-Policy: strict-origin-when-cross-origin`, and `X-Frame-Options: DENY` (with `frame-ancestors 'none'` in the CSP) are returned by both Nginx and the FastAPI application.

---

## 23. Local Development Setup

```bash
cd iam-service
cp .env.example .env
python scripts/generate_keys.py

# With Docker Compose
docker compose build --no-cache
docker compose up -d
docker compose exec api alembic upgrade head
docker compose exec api pytest
```

- **Frontend UI**: `http://localhost:8080` (also served directly by FastAPI at `http://localhost:8000/index.html`)
- **API & Swagger Docs**: `http://localhost:8000/docs`
- **MailHog Web UI**: `http://localhost:8025`

---

## 24. Production Considerations

- Mount RSA keys from a hardware security module (HSM) or secrets manager (AWS Secrets Manager / HashiCorp Vault / Kubernetes Secrets) to `/app/keys/private.pem` (`0400` permissions).
- Terminate TLS (`HTTPS`) at the ingress / load balancer and restrict `ALLOWED_ORIGINS` to your production domain(s).
- Run PostgreSQL 17 with TLS and regular automated backups, and Redis 7 with ACL authentication enabled.
