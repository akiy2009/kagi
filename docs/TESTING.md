# Testing and validation

Run tests only against an isolated development database and local server. Some end-to-end scripts insert test rows directly into the database; never point them at production data.

## 1. Rust checks

Install the Rust toolchain version supported by `Cargo.toml`, then run:

```bash
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets
cargo build --release
```

Also run the Vercel deployment guardrail checks:

```bash
python3 scripts/check_vercel_security.py
```

## 2. Install Python test dependencies

```bash
python -m venv .venv
# Linux/macOS
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements-test.txt
```

## 3. Run the local server

Use a dedicated test database and enable the demo client. Keep this process running in one terminal:

```bash
KAGI_SEED_DEMO=1 KAGI_ADMIN_TOKEN=test-admin KAGI_REGISTRATION_TOKEN=reg-secret \
KAGI_DEVICE_INTERVAL=1 KAGI_DB=kagi-e2e.db cargo run
```

In another terminal, use the same `KAGI_DB` value for tests that seed database records:

```bash
KAGI_DB=kagi-e2e.db python scripts/e2e_oidc.py
KAGI_DB=kagi-e2e.db python scripts/e2e_advanced.py
KAGI_DB=kagi-e2e.db python scripts/e2e_security_races.py
KAGI_DB=kagi-e2e.db KAGI_REGISTRATION_TOKEN=reg-secret python scripts/e2e_complete_oidc.py
python scripts/e2e_rate_limit.py
python scripts/e2e_webauthn.py
python scripts/e2e_admin.py
```

Run suites one at a time against a fresh database and a freshly started server. Rate limits are per process, and the back-channel logout test registers a loopback receiver, so a shared server can make later runs flaky. The new-feature suite expects `KAGI_REGISTRATION_TOKEN` to match the server and sets `KAGI_DEVICE_INTERVAL=1` to keep polling tests quick.

The admin test expects the development-only values shown above. Never reuse them outside an isolated local test instance. The WebAuthn software-authenticator test has its own in-memory/test credential flow and expects the default local origin and RP ID.

On Windows, use PowerShell to set environment variables before invoking each command, or run the tests in WSL or a Linux container. Do not copy POSIX shell syntax verbatim into PowerShell.

## 4. What the end-to-end scripts cover

| Script | Main coverage |
| --- | --- |
| `e2e_oidc.py` | PAR, consent, PKCE, tokens, UserInfo, introspection, refresh rotation/reuse detection, revocation, prompt behavior, DPoP binding |
| `e2e_advanced.py` | JARM, DPoP key binding across flow, CORS preflight, max_age |
| `e2e_webauthn.py` | Passkey signup/sign-in using a software authenticator, challenge/origin/type validation, signature/counter checks |
| `e2e_admin.py` | Dynamic registration gate, private_key_jwt, JAR, key rotation, logout redirect validation |
| `e2e_complete_oidc.py` | RFC 8628 device authorization/approval/denial/polling, `claims` validation and token filtering, RFC 7592 client management and secret rotation, signed back-channel logout delivery |
| `e2e_security_races.py` | Concurrent authorization-code exchange, concurrent DPoP proof replay, key rotation/JWKS overlap, OIDC discovery sanity checks |
| `e2e_rate_limit.py` | Shared fixed-window rate-limit enforcement and HTTP 429 behavior |

The security-race script checks that exactly one concurrent authorization-code exchange succeeds and that a shared DPoP proof is accepted only once. It also checks a focused set of discovery metadata invariants. These are regression tests, not a complete normative test suite.

## 5. OAuth/OIDC conformance is a separate step

Unit and integration tests only validate the scenarios implemented by this repository. They do not prove full compliance with OAuth 2.1, OpenID Connect Core, FAPI 2.0, WebAuthn, or any certification profile. Before production use:

1. Select the exact profile and version.
2. Run the applicable official/community conformance suite against the deployed configuration.
3. Review all failed and skipped tests; do not suppress failures to get a green badge.
4. Arrange independent security review, including concurrency and deployment boundaries.
5. Record the tested commit, configuration, and test-suite version in the release evidence.
