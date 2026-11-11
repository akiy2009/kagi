-- kagi schema for PostgreSQL / Supabase.
--
-- Apply this either automatically at start-up (KAGI_DATABASE_URL is set) or
-- manually in the Supabase SQL editor. Booleans are stored as BIGINT (0/1) so
-- the same 64-bit integer bindings work against both SQLite and PostgreSQL.

CREATE TABLE IF NOT EXISTS users (
    id              TEXT PRIMARY KEY,
    username        TEXT NOT NULL UNIQUE,
    display_name    TEXT NOT NULL,
    email           TEXT,
    email_verified  BIGINT NOT NULL DEFAULT 0,
    created_at      BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    id              TEXT PRIMARY KEY,          -- credential id (base64url)
    user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    public_key      BYTEA NOT NULL,            -- COSE_Key
    key_type        TEXT NOT NULL,             -- ES256 | EdDSA | RS256
    sign_count      BIGINT NOT NULL,
    transports      TEXT NOT NULL DEFAULT '[]',
    aaguid          TEXT,
    backup_eligible BIGINT NOT NULL DEFAULT 0,
    backup_state    BIGINT NOT NULL DEFAULT 0,
    nickname        TEXT,
    created_at      BIGINT NOT NULL,
    last_used_at    BIGINT
);
CREATE INDEX IF NOT EXISTS idx_credentials_user ON credentials(user_id);

CREATE TABLE IF NOT EXISTS clients (
    id                        TEXT PRIMARY KEY,
    name                      TEXT NOT NULL,
    secret_hash               TEXT,
    redirect_uris             TEXT NOT NULL,
    post_logout_redirect_uris TEXT NOT NULL DEFAULT '[]',
    grant_types               TEXT NOT NULL,
    scopes                    TEXT NOT NULL,
    auth_method               TEXT NOT NULL,
    jwks                      TEXT,
    require_dpop              BIGINT NOT NULL DEFAULT 0,
    require_par               BIGINT NOT NULL DEFAULT 0,
    id_token_alg              TEXT NOT NULL DEFAULT 'ES256',
    registration_token_hash   TEXT,
    backchannel_logout_uri    TEXT,
    backchannel_logout_session_required BIGINT NOT NULL DEFAULT 0,
    created_at                BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,              -- sha256(sid)
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_time   BIGINT NOT NULL,
    amr         TEXT NOT NULL,
    acr         TEXT NOT NULL,
    expires_at  BIGINT NOT NULL,
    created_at  BIGINT NOT NULL,
    last_seen_at BIGINT NOT NULL DEFAULT 0,
    user_agent  TEXT,
    ip          TEXT
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

-- Remembered user consent so that prompt=none can complete silently.
CREATE TABLE IF NOT EXISTS consents (
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    client_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    PRIMARY KEY (user_id, client_id)
);

-- Short-lived interaction state: PAR requests, authorize flows,
-- WebAuthn ceremonies, sign-up flows.
CREATE TABLE IF NOT EXISTS flows (
    id          TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,
    user_id     TEXT,
    client_id   TEXT,
    payload     TEXT NOT NULL,
    challenge   TEXT,
    csrf        TEXT,
    expires_at  BIGINT NOT NULL,
    created_at  BIGINT NOT NULL,
    consumed    BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_kind ON flows(kind, expires_at);

CREATE TABLE IF NOT EXISTS auth_codes (
    code_hash       TEXT PRIMARY KEY,
    client_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    redirect_uri    TEXT NOT NULL,
    scope           TEXT NOT NULL,
    nonce           TEXT,
    code_challenge  TEXT NOT NULL,
    auth_time       BIGINT NOT NULL,
    amr             TEXT NOT NULL,
    acr             TEXT NOT NULL,
    dpop_jkt        TEXT,
    session_id      TEXT,
    claims          TEXT,
    expires_at      BIGINT NOT NULL,
    created_at      BIGINT NOT NULL,
    consumed        BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash      TEXT PRIMARY KEY,
    family_id       TEXT NOT NULL,
    user_id         TEXT NOT NULL,
    client_id       TEXT NOT NULL,
    scope           TEXT NOT NULL,
    auth_time       BIGINT NOT NULL,
    amr             TEXT NOT NULL,
    acr             TEXT NOT NULL,
    dpop_jkt        TEXT,
    session_id      TEXT,
    claims          TEXT,
    issued_at       BIGINT NOT NULL,
    expires_at      BIGINT NOT NULL,
    rotated_to      TEXT,
    revoked         BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rt_family ON refresh_tokens(family_id);
CREATE INDEX IF NOT EXISTS idx_rt_user ON refresh_tokens(user_id);

-- RFC 8628 device authorization grants. Only code hashes are stored.
CREATE TABLE IF NOT EXISTS device_codes (
    device_hash     TEXT PRIMARY KEY,
    user_code_hash  TEXT NOT NULL UNIQUE,
    client_id       TEXT NOT NULL,
    scope           TEXT NOT NULL,
    user_id         TEXT,
    auth_time       BIGINT,
    amr             TEXT NOT NULL DEFAULT '[]',
    acr             TEXT,
    status          TEXT NOT NULL DEFAULT 'pending',
    interval_secs   BIGINT NOT NULL,
    last_polled_at  BIGINT NOT NULL DEFAULT 0,
    expires_at      BIGINT NOT NULL,
    created_at      BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_device_expires ON device_codes(expires_at);

CREATE TABLE IF NOT EXISTS access_tokens (
    jti         TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL,
    client_id   TEXT NOT NULL,
    scope       TEXT NOT NULL,
    audience    TEXT NOT NULL,
    dpop_jkt    TEXT,
    session_id  TEXT,                          -- browser session that authorised it
    subject     TEXT NOT NULL,                 -- sub claim (user id or client id)
    issued_at   BIGINT NOT NULL,
    expires_at  BIGINT NOT NULL,
    revoked     BIGINT NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_at_user ON access_tokens(user_id);

-- Security events shown in the account console.
CREATE TABLE IF NOT EXISTS audit_events (
    id          TEXT PRIMARY KEY,
    user_id     TEXT,
    client_id   TEXT,
    kind        TEXT NOT NULL,
    detail      TEXT NOT NULL,
    ip          TEXT,
    user_agent  TEXT,
    created_at  BIGINT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_events(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_events(created_at);

-- Single-use recovery codes. Only the SHA-256 of the normalised code is stored.
CREATE TABLE IF NOT EXISTS recovery_codes (
    code_hash   TEXT PRIMARY KEY,
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  BIGINT NOT NULL,
    used_at     BIGINT
);
CREATE INDEX IF NOT EXISTS idx_recovery_user ON recovery_codes(user_id);

CREATE TABLE IF NOT EXISTS signing_keys (
    kid         TEXT PRIMARY KEY,
    private_jwk TEXT NOT NULL,
    public_jwk  TEXT NOT NULL,
    created_at  BIGINT NOT NULL,
    active      BIGINT NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS dpop_replay (
    jti         TEXT PRIMARY KEY,
    expires_at  BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS assertion_replay (
    jti         TEXT PRIMARY KEY,
    expires_at  BIGINT NOT NULL
);

-- Forward-compatible upgrades for databases created by earlier releases.
-- CREATE TABLE IF NOT EXISTS does not add columns to an existing table.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at BIGINT NOT NULL DEFAULT 0;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS user_agent TEXT;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS ip TEXT;
ALTER TABLE access_tokens ADD COLUMN IF NOT EXISTS session_id TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS registration_token_hash TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS backchannel_logout_uri TEXT;
ALTER TABLE clients ADD COLUMN IF NOT EXISTS backchannel_logout_session_required BIGINT NOT NULL DEFAULT 0;
ALTER TABLE auth_codes ADD COLUMN IF NOT EXISTS claims TEXT;
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS claims TEXT;

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_at_session ON access_tokens(session_id);

UPDATE sessions SET last_seen_at = created_at WHERE last_seen_at = 0;

-- Shared, atomic rate-limit counters for serverless/multi-instance deployments.
CREATE TABLE IF NOT EXISTS rate_limits (
    bucket_key TEXT NOT NULL,
    window_start BIGINT NOT NULL,
    hits BIGINT NOT NULL,
    PRIMARY KEY (bucket_key, window_start)
);
