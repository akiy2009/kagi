# Configuration reference

All values are read when the process starts. Restart Kagi Identity after changing them. Empty or unset values generally fall back to the defaults in `src/config.rs`.

## Core settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `KAGI_ENV` | `development` (or `production` on Vercel) | `development`, `test`, or `production`; production enforces HTTPS, PostgreSQL, secure cookies/HSTS, PAR, a trusted proxy, rate limiting, disabled demo seeding/auto-migration, and strong administrative/registration secrets |
| `KAGI_ISSUER` | `http://localhost:8080` | Public issuer origin; no path, query, fragment, or trailing slash |
| `KAGI_BIND` | `127.0.0.1:8080` | Address and port to bind |
| `KAGI_RP_ID` | Host derived from issuer | WebAuthn RP ID; bare hostname/domain, no scheme or port |
| `KAGI_RP_NAME` | `Kagi Identity` | Name displayed by passkey UI |
| `KAGI_ORIGIN` | Same as issuer | Expected browser origin for WebAuthn validation |
| `KAGI_DB` | `kagi.db` | SQLite database path |
| `KAGI_DATABASE_URL` | Unset | PostgreSQL/Supabase connection string; takes precedence over `KAGI_DB` |
| `KAGI_AUTO_MIGRATE` | `1` | Apply schema on startup; set `0` in serverless production after running schema migration once |
| `DATABASE_URL` | Unset | Fallback PostgreSQL connection string if `KAGI_DATABASE_URL` is unset |

## Feature and policy settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `KAGI_ALLOW_SIGNUP` | `1` | Allow self-service account registration |
| `KAGI_SEED_DEMO` | `0` | Seed the development `demo-web` client |
| `KAGI_REQUIRE_PAR` | `0` | Require Pushed Authorization Requests |
| `KAGI_REQUIRE_DPOP` | `0` | Require DPoP for applicable flows |
| `KAGI_ADMIN_TOKEN` | Unset | Bearer token protecting the administrative endpoints (`/admin/keys/rotate`, `/admin/stats`); unset disables them |
| `KAGI_REGISTRATION_TOKEN` | Unset | Initial access token required for dynamic client registration |
| `KAGI_CORS_ORIGINS` | Unset | Comma-separated exact HTTPS origins allowed to call API endpoints |
| `KAGI_COOKIE_SECURE` | Derived from HTTPS issuer | Add the Secure attribute to cookies |
| `KAGI_HSTS` | Derived from HTTPS issuer | Emit HSTS; enable only when HTTPS is correctly deployed |
| `KAGI_TRUST_PROXY` | `0` | Trust the first forwarded IP hop; only behind a proxy that overwrites the header |
| `KAGI_RATE_LIMIT` | `1` | Enable atomic PostgreSQL-backed shared rate limiting |
| `KAGI_RECOVERY_ENABLED` | `1` | Enable single-use recovery codes as passkey fallback |
| `KAGI_MAX_PASSKEYS` | `10` | Maximum passkeys per account (clamped to 1–100) |
| `KAGI_AUDIT_RETENTION_DAYS` | `90` | Audit event retention in days; `0` retains indefinitely |

## Lifetimes

All values are seconds and must be positive, except idle TTL may be `0` to disable idle expiry.

| Variable | Default | Meaning |
| --- | ---: | --- |
| `KAGI_SESSION_TTL` | `28800` | Absolute browser-session lifetime (8 hours) |
| `KAGI_SESSION_IDLE_TTL` | `7200` | Idle timeout (2 hours); `0` disables idle expiry |
| `KAGI_CODE_TTL` | `60` | Authorization-code lifetime |
| `KAGI_ACCESS_TTL` | `300` | Access-token lifetime (5 minutes) |
| `KAGI_REFRESH_TTL` | `2592000` | Refresh-token lifetime (30 days) |
| `KAGI_ID_TTL` | `300` | ID-token lifetime (5 minutes) |
| `KAGI_PAR_TTL` | `90` | PAR request URI lifetime |
| `KAGI_DEVICE_TTL` | `600` | RFC 8628 device-code lifetime |
| `KAGI_DEVICE_INTERVAL` | `5` | Minimum device polling interval in seconds; a too-fast poll returns `slow_down` and raises the interval by 5 |

## Example production baseline

These are starting values, not a complete security policy. Replace the domain and store secrets in a secret manager.

```dotenv
KAGI_ISSUER=https://id.example.com
KAGI_ORIGIN=https://id.example.com
KAGI_RP_ID=example.com
KAGI_RP_NAME=Example Identity
KAGI_BIND=127.0.0.1:8080
KAGI_COOKIE_SECURE=1
KAGI_HSTS=1
KAGI_SEED_DEMO=0
KAGI_ALLOW_SIGNUP=0
KAGI_REQUIRE_PAR=1
KAGI_REQUIRE_DPOP=1
KAGI_RATE_LIMIT=1
KAGI_TRUST_PROXY=1
KAGI_AUTO_MIGRATE=0
KAGI_CORS_ORIGINS=https://your-rp.example.com
KAGI_ADMIN_TOKEN=retrieve-from-secret-manager
KAGI_REGISTRATION_TOKEN=retrieve-from-secret-manager
```

For any self-hosted deployment, set `KAGI_ENV=production`; Vercel automatically uses the same production checks. Apply `supabase/schema.sql` once before deployment, then set `KAGI_AUTO_MIGRATE=0` to avoid concurrent schema DDL during starts/cold starts. The `compose.production.yaml` and `.env.production.example` files provide a self-hosted Caddy + Docker baseline. A stricter flag is not a substitute for conformance testing. Production startup intentionally fails closed if required settings are missing.
