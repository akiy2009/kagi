mod auth;
mod backchannel;
mod config;
mod db;
mod device;
mod dpop;
mod error;
mod jose;
mod keys;
mod oidc;
mod ratelimit;
mod resource;
mod ui;
mod util;
mod webauthn;

use axum::extract::{ConnectInfo, DefaultBodyLimit, Request, State};
use axum::http::{header, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use config::Config;
use db::params;
use db::Db;
use keys::KeyRing;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::net::TcpListener;

#[derive(Clone)]
pub struct AppState {
    pub cfg: Arc<Config>,
    pub db: Arc<Db>,
    pub keys: Arc<RwLock<KeyRing>>,
    pub last_key_refresh: Arc<AtomicI64>,
    /// Cheap per-instance rate limiter. The authoritative shared counters live
    /// in the database; this only sheds obvious floods before a DB round trip.
    pub limiter: Arc<ratelimit::RateLimiter>,
}

fn is_usable_production_secret(secret: Option<&String>) -> bool {
    secret.is_some_and(|value| {
        let upper = value.to_ascii_uppercase();
        value.len() >= 32
            && !upper.contains("REPLACE_WITH")
            && !upper.contains("CHANGE_ME")
            && !upper.contains("PLACEHOLDER")
            && !upper.contains("YOUR_SECRET")
    })
}

/// Enforce the same fail-closed baseline for self-hosted and serverless
/// production deployments. Vercel is always production, even if KAGI_ENV is
/// accidentally set to a weaker value.
fn validate_production_config(cfg: &Config, is_vercel: bool) -> anyhow::Result<()> {
    if !cfg.production && !is_vercel {
        return Ok(());
    }

    anyhow::ensure!(
        cfg.database_url
            .as_deref()
            .is_some_and(|url| url.starts_with("postgres://") || url.starts_with("postgresql://")),
        "production requires KAGI_DATABASE_URL (PostgreSQL); SQLite is not supported"
    );
    anyhow::ensure!(
        cfg.issuer.starts_with("https://"),
        "production requires an HTTPS KAGI_ISSUER"
    );
    anyhow::ensure!(
        !cfg.is_local(),
        "production KAGI_ISSUER must not use localhost or a loopback address"
    );
    anyhow::ensure!(
        cfg.origin == cfg.issuer,
        "KAGI_ORIGIN must exactly match KAGI_ISSUER for this deployment"
    );
    anyhow::ensure!(
        cfg.cookie_secure,
        "KAGI_COOKIE_SECURE=1 is required in production"
    );
    anyhow::ensure!(cfg.hsts, "KAGI_HSTS=1 is required in production");
    anyhow::ensure!(
        !cfg.seed_demo,
        "KAGI_SEED_DEMO must be disabled in production"
    );
    anyhow::ensure!(
        cfg.require_par,
        "KAGI_REQUIRE_PAR=1 is required in production"
    );
    anyhow::ensure!(
        cfg.trust_proxy,
        "KAGI_TRUST_PROXY=1 is required behind the trusted HTTPS proxy"
    );
    anyhow::ensure!(
        !cfg.auto_migrate,
        "KAGI_AUTO_MIGRATE=0 is required; apply the database schema before deployment"
    );
    anyhow::ensure!(
        cfg.rate_limit,
        "KAGI_RATE_LIMIT=1 is required in production"
    );
    anyhow::ensure!(
        is_usable_production_secret(cfg.admin_token.as_ref()),
        "KAGI_ADMIN_TOKEN must be a unique, randomly generated secret of at least 32 characters"
    );
    anyhow::ensure!(
        is_usable_production_secret(cfg.registration_token.as_ref()),
        "KAGI_REGISTRATION_TOKEN must be a unique, randomly generated secret of at least 32 characters"
    );
    anyhow::ensure!(
        cfg.admin_token != cfg.registration_token,
        "KAGI_ADMIN_TOKEN and KAGI_REGISTRATION_TOKEN must be different secrets"
    );

    if is_vercel {
        anyhow::ensure!(
            !cfg.cors_origins.is_empty(),
            "KAGI_CORS_ORIGINS must list exact HTTPS RP origins on Vercel"
        );
    }
    Ok(())
}

/// Initialize state once per process/function instance. All durable state,
/// including signing keys, sessions and OAuth artifacts, lives in PostgreSQL.
pub fn build_state() -> anyhow::Result<AppState> {
    let cfg = Arc::new(Config::from_env()?);
    let is_vercel = std::env::var("VERCEL").as_deref() == Ok("1");
    validate_production_config(&cfg, is_vercel)?;

    let db = Arc::new(Db::open_with_options(
        cfg.database_url.as_deref(),
        &cfg.db_path,
        cfg.auto_migrate,
    )?);
    if cfg.seed_demo {
        anyhow::ensure!(
            cfg.is_local(),
            "demo client seeding is only allowed for localhost"
        );
        db.with(db::seed_demo_client)?;
    }

    db.sweep(cfg.audit_retention_days)?;
    let ring = KeyRing::load(&db)?;
    Ok(AppState {
        cfg,
        db,
        keys: Arc::new(RwLock::new(ring)),
        last_key_refresh: Arc::new(AtomicI64::new(util::now())),
        limiter: Arc::new(ratelimit::RateLimiter::new()),
    })
}

/// Build the complete Axum router around durable application state.
pub fn routes(state: AppState) -> Router {
    routes_and_security(state)
}

fn routes_and_security(state: AppState) -> Router {
    Router::new()
        .route("/", get(auth::account))
        .route("/login", get(auth::login_page))
        .route("/signup", get(auth::signup_page))
        .route("/recover", get(auth::recover_page))
        .route(
            "/consent",
            get(auth::consent_page).post(auth::consent_submit),
        )
        .route("/account/logout", post(auth::account_logout))
        .route("/api/recover", post(auth::recover))
        .route("/api/account/profile", post(auth::update_profile))
        .route("/api/account/passkey/rename", post(auth::rename_passkey))
        .route("/api/account/passkey/delete", post(auth::delete_passkey))
        .route("/api/account/sessions/revoke", post(auth::revoke_session))
        .route(
            "/api/account/sessions/revoke-others",
            post(auth::revoke_other_sessions),
        )
        .route("/api/account/consent/revoke", post(auth::revoke_consent))
        .route(
            "/api/account/recovery/generate",
            post(auth::recovery_generate),
        )
        .route("/api/account/delete", post(auth::delete_account))
        .route("/api/webauthn/login/options", post(auth::login_options))
        .route("/api/webauthn/login/verify", post(auth::login_verify))
        .route("/api/webauthn/signup/options", post(auth::signup_options))
        .route("/api/webauthn/signup/verify", post(auth::signup_verify))
        .route(
            "/api/webauthn/passkey/options",
            post(auth::add_passkey_options),
        )
        .route(
            "/api/webauthn/passkey/verify",
            post(auth::add_passkey_verify),
        )
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route(
            "/.well-known/oauth-authorization-server",
            get(oidc::discovery),
        )
        .route("/jwks.json", get(oidc::jwks))
        .route("/authorize", get(oidc::authorize))
        .route("/par", post(oidc::par))
        .route("/token", post(oidc::token))
        .route("/device_authorization", post(device::authorization))
        .route(
            "/device",
            get(device::verification_page).post(device::verification_submit),
        )
        .route(
            "/userinfo",
            get(resource::userinfo).post(resource::userinfo),
        )
        .route("/introspect", post(resource::introspect))
        .route("/revoke", post(resource::revoke))
        .route(
            "/logout",
            get(resource::end_session_get).post(resource::end_session_post),
        )
        .route("/register", post(resource::register_client))
        .route(
            "/register/{client_id}",
            get(resource::client_info)
                .put(resource::update_client)
                .delete(resource::delete_client),
        )
        .route("/admin/keys/rotate", post(resource::rotate_keys))
        .route("/admin/stats", get(resource::admin_stats))
        .route("/healthz", get(resource::health))
        .route("/readyz", get(resource::health))
        .route("/demo", get(demo_page))
        .route("/demo/callback", get(demo_page))
        .route("/static/app.js", get(app_js))
        .route("/static/kagi.js", get(kagi_js))
        .route("/static/theme.js", get(theme_js))
        .route("/static/style.css", get(style_css))
        .fallback(not_found)
        .with_state(state.clone())
        .layer(DefaultBodyLimit::max(128 * 1024))
        .layer(middleware::from_fn_with_state(state, harden))
}

fn api_path(path: &str) -> bool {
    path.starts_with("/.well-known/")
        || path.starts_with("/api/webauthn/")
        || path.starts_with("/api/account/")
        || matches!(
            path,
            "/jwks.json"
                | "/par"
                | "/token"
                | "/userinfo"
                | "/introspect"
                | "/revoke"
                | "/register"
                | "/device_authorization"
                | "/healthz"
                | "/readyz"
                | "/api/recover"
        )
        || path.starts_with("/register/")
}

fn same_origin(a: &str, b: &str) -> bool {
    a.trim_end_matches('/') == b.trim_end_matches('/')
}

/// Browser endpoints that mutate state and are protected by an Origin check.
/// OAuth protocol endpoints are intentionally excluded: they are used by
/// cross-origin relying parties and are protected by OAuth/DPoP instead.
fn browser_post(path: &str) -> bool {
    path == "/consent"
        || path == "/logout"
        || path == "/device"
        || path.starts_with("/account")
        || path.starts_with("/api/account")
        || path.starts_with("/api/webauthn")
        || path == "/api/recover"
}

async fn harden(State(st): State<AppState>, mut req: Request, next: Next) -> Response {
    // Each warm Vercel instance refreshes the shared signing-key view regularly.
    // This keeps independently scaled instances convergent after key rotation.
    let now = util::now();
    let refreshed = st.last_key_refresh.load(Ordering::Relaxed);
    if now.saturating_sub(refreshed) >= 5
        && st
            .last_key_refresh
            .compare_exchange(refreshed, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    {
        match KeyRing::load(&st.db) {
            Ok(ring) => *st.keys.write().unwrap_or_else(|e| e.into_inner()) = ring,
            Err(error) => eprintln!("[kagi] signing-key refresh failed: {error}"),
        }
    }

    let path = req.uri().path().to_string();

    // Resolve the client IP once and hand it to the handlers via an internal
    // header. An inbound `x-kagi-ip` is never trusted: it is always replaced.
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string());
    let forwarded = req
        .headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.split(',').next())
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .map(str::to_string);
    req.headers_mut().remove("x-kagi-ip");
    let client_ip = if st.cfg.trust_proxy || peer.is_none() {
        // Serverless runtimes (the Vercel layer used by `api/index.rs`) expose
        // no peer address, and the platform overwrites `X-Forwarded-For`. Using
        // it there keeps per-client buckets instead of collapsing every client
        // into a single "unknown" bucket. When a peer address is available,
        // `KAGI_TRUST_PROXY` alone decides whether the header is honoured.
        forwarded.clone().or(peer.clone())
    } else {
        peer.clone()
    };
    if let Some(ip) = client_ip.as_deref() {
        if let Ok(value) = HeaderValue::from_str(ip) {
            req.headers_mut()
                .insert(HeaderName::from_static("x-kagi-ip"), value);
        }
    }

    // CSRF defence-in-depth for state-changing browser requests. Browsers send
    // Origin on cross-site POSTs; requests without an Origin (scripts, CLI) are
    // still protected by the session cookie's SameSite=Lax setting. The consent
    // form additionally carries a per-flow CSRF token, and the JSON account API
    // requires `application/json`, which a cross-origin form cannot send without
    // a successful CORS preflight.
    let mutating = !matches!(
        req.method(),
        &Method::GET | &Method::HEAD | &Method::OPTIONS
    );
    if mutating && browser_post(&path) {
        if let Some(origin) = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
        {
            if !same_origin(origin, &st.cfg.issuer) && !same_origin(origin, &st.cfg.origin) {
                return (StatusCode::FORBIDDEN, "cross-origin request rejected").into_response();
            }
        }
        if let Some(site) = req
            .headers()
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
        {
            if !matches!(site, "same-origin" | "none") {
                return (StatusCode::FORBIDDEN, "cross-site request rejected").into_response();
            }
        }
    }

    // CORS preflights are unauthenticated and cheap; never let them consume a
    // credential endpoint's rate-limit budget.
    if st.cfg.rate_limit && req.method() != Method::OPTIONS {
        let policy: Option<(&str, i64)> = match path.as_str() {
            "/api/webauthn/login/options" | "/api/webauthn/login/verify" => {
                Some(("webauthn-login", 12))
            }
            "/api/webauthn/signup/options" | "/api/webauthn/signup/verify" => {
                Some(("webauthn-signup", 8))
            }
            "/api/webauthn/passkey/options" | "/api/webauthn/passkey/verify" => {
                Some(("webauthn-passkey", 12))
            }
            "/api/recover" => Some(("account-recovery", 10)),
            p if p.starts_with("/api/account/") => Some(("account-api", 60)),
            "/authorize" => Some(("oauth-authorize", 30)),
            "/token" => Some(("oauth-token", 60)),
            "/userinfo" | "/introspect" | "/revoke" => Some(("oauth-resource", 60)),
            "/par" => Some(("oauth-par", 30)),
            "/device_authorization" => Some(("oauth-device", 15)),
            "/device" => Some(("device-verification", 20)),
            "/register" => Some(("client-registration", 5)),
            p if p.starts_with("/register/") => Some(("client-management", 30)),
            "/admin/keys/rotate" => Some(("key-rotation", 3)),
            "/login" | "/signup" | "/recover" => Some(("auth-page", 60)),
            _ => None,
        };
        if let Some((bucket, limit)) = policy {
            let ip = client_ip
                .clone()
                .or_else(|| forwarded.clone())
                .unwrap_or_else(|| "unknown".to_string());
            // Per-instance pre-check: sheds floods without a database write.
            if !st
                .limiter
                .allow(&format!("{}:{}", bucket, ip), limit as u32, 60)
            {
                let retry = 60 - now.rem_euclid(60);
                let mut response =
                    (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
                response.headers_mut().insert(
                    header::RETRY_AFTER,
                    HeaderValue::from_str(&retry.to_string())
                        .unwrap_or_else(|_| HeaderValue::from_static("60")),
                );
                return response;
            }
            let key = format!("{}:{}", bucket, util::sha256_hex(&ip));
            let window_start = now.div_euclid(60) * 60;
            let counter = st.db.with(|conn| {
                conn.execute(
                    "INSERT INTO rate_limits (bucket_key, window_start, hits) VALUES (?1, ?2, 1) ON CONFLICT (bucket_key, window_start) DO UPDATE SET hits = rate_limits.hits + 1",
                    params![key, window_start],
                )?;
                Ok(conn.query_row(
                    "SELECT hits FROM rate_limits WHERE bucket_key = ?1 AND window_start = ?2",
                    params![key, window_start],
                    |row| row.get::<_, i64>(0),
                )?)
            });
            match counter {
                Ok(hits) if hits <= limit => {}
                Ok(_) => {
                    let retry = 60 - now.rem_euclid(60);
                    let mut response =
                        (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded").into_response();
                    response.headers_mut().insert(
                        header::RETRY_AFTER,
                        HeaderValue::from_str(&retry.to_string())
                            .unwrap_or_else(|_| HeaderValue::from_static("60")),
                    );
                    return response;
                }
                Err(error) => {
                    eprintln!("[kagi] shared rate-limit store unavailable: {error}");
                    return (StatusCode::SERVICE_UNAVAILABLE, "temporarily unavailable")
                        .into_response();
                }
            }
        }
    }

    let is_api = api_path(req.uri().path());
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    // Same-origin requests are always allowed: browsers attach `Origin` to
    // same-origin POSTs too, and an operator may configure `KAGI_CORS_ORIGINS`
    // with relying parties only. Wildcards are never accepted.
    let allowed_origin = origin
        .as_deref()
        .filter(|origin| {
            st.cfg.cors_origins.iter().any(|allowed| allowed == *origin)
                || same_origin(origin, &st.cfg.issuer)
                || same_origin(origin, &st.cfg.origin)
                || (st.cfg.is_local() && st.cfg.cors_origins.is_empty())
        })
        .map(str::to_owned);
    if is_api && origin.is_some() && allowed_origin.is_none() {
        return StatusCode::FORBIDDEN.into_response();
    }
    let preflight = req.method() == Method::OPTIONS && is_api;

    if preflight {
        let Some(origin) = allowed_origin else {
            return StatusCode::FORBIDDEN.into_response();
        };
        let mut response = StatusCode::NO_CONTENT.into_response();
        let headers = response.headers_mut();
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(&origin).unwrap_or_else(|_| HeaderValue::from_static("null")),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static("GET, POST, OPTIONS"),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static("authorization, content-type, dpop"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static("600"),
        );
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        return response;
    }

    let mut res = next.run(req).await;
    let headers = res.headers_mut();

    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("x-robots-tag"),
        HeaderValue::from_static("noindex, nofollow"),
    );
    headers.insert(
        HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    // A handler may scope a stricter policy to one response (for example the
    // nonce-based CSP used by `form_post`); do not clobber it here.
    if !headers.contains_key(header::CONTENT_SECURITY_POLICY) {
        headers.insert(
            header::CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(
                "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; \
                 connect-src 'self'; font-src 'self'; base-uri 'none'; form-action 'self'; \
                 frame-ancestors 'none'; object-src 'none'; manifest-src 'self'",
            ),
        );
    }
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "camera=(), microphone=(), geolocation=(), payment=(), usb=(), \
             publickey-credentials-get=(self), publickey-credentials-create=(self)",
        ),
    );
    if st.cfg.hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    }
    if is_api {
        if let Some(origin) = allowed_origin.as_deref() {
            if let Ok(value) = HeaderValue::from_str(origin) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, value);
                headers.insert(
                    header::ACCESS_CONTROL_EXPOSE_HEADERS,
                    HeaderValue::from_static("www-authenticate, dpop-nonce"),
                );
                headers.insert(header::VARY, HeaderValue::from_static("Origin"));
                headers.insert(
                    HeaderName::from_static("cross-origin-resource-policy"),
                    HeaderValue::from_static("cross-origin"),
                );
            }
        }
    }

    // Never let a browser or intermediary cache authenticated responses.
    let cacheable = path.starts_with("/static/")
        || path.starts_with("/.well-known/")
        || matches!(path.as_str(), "/jwks.json" | "/healthz" | "/readyz");
    if !cacheable && !headers.contains_key(header::CACHE_CONTROL) {
        headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

async fn app_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../static/app.js"),
    )
        .into_response()
}

async fn kagi_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../static/kagi.js"),
    )
        .into_response()
}

async fn theme_js() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/javascript; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../static/theme.js"),
    )
        .into_response()
}

async fn demo_page(State(st): State<AppState>) -> Response {
    axum::response::Html(ui::demo_page(&st.cfg.issuer, st.cfg.seed_demo)).into_response()
}

async fn style_css() -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        include_str!("../static/style.css"),
    )
        .into_response()
}

async fn not_found() -> Response {
    (
        StatusCode::NOT_FOUND,
        axum::response::Html(ui::error_page("404", "ページが見つかりません")),
    )
        .into_response()
}

pub async fn run_local() -> anyhow::Result<()> {
    let cfg = Arc::new(Config::from_env()?);
    validate_production_config(&cfg, false)?;
    let db = Arc::new(Db::open_with_options(
        cfg.database_url.as_deref(),
        &cfg.db_path,
        cfg.auto_migrate,
    )?);
    if cfg.seed_demo {
        anyhow::ensure!(
            cfg.is_local(),
            "demo client seeding is only allowed for localhost"
        );
        db.with(db::seed_demo_client)?;
    }
    let ring = KeyRing::load(&db)?;
    let sweep_db = db.clone();
    let audit_retention_days = cfg.audit_retention_days;
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(Duration::from_secs(300));
        loop {
            tick.tick().await;
            if let Err(error) = sweep_db.sweep(audit_retention_days) {
                eprintln!("[kagi] periodic cleanup failed: {error}");
            }
        }
    });
    let state = AppState {
        cfg: cfg.clone(),
        db: db.clone(),
        keys: Arc::new(RwLock::new(ring)),
        last_key_refresh: Arc::new(AtomicI64::new(util::now())),
        limiter: Arc::new(ratelimit::RateLimiter::new()),
    };
    let app = routes(state);
    let listener = TcpListener::bind(&cfg.bind).await?;
    println!("[kagi] issuer   {}", cfg.issuer);
    println!("[kagi] bind     http://{}", cfg.bind);
    println!("[kagi] database {}", db.backend());
    for warning in cfg.warnings() {
        eprintln!("[kagi] SECURITY WARNING: {warning}");
    }
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

#[cfg(test)]
mod production_config_tests {
    use super::{is_usable_production_secret, validate_production_config};
    use crate::config::Config;

    fn valid_production_config() -> Config {
        Config {
            issuer: "https://identity.example.com".to_string(),
            bind: "0.0.0.0:8080".to_string(),
            rp_id: "identity.example.com".to_string(),
            rp_name: "Example Identity".to_string(),
            origin: "https://identity.example.com".to_string(),
            db_path: "/data/kagi.db".to_string(),
            database_url: Some(
                "postgresql://kagi:unused-password@db.example.com:5432/kagi?sslmode=require"
                    .to_string(),
            ),
            auto_migrate: false,
            production: true,
            allow_signup: false,
            seed_demo: false,
            require_par: true,
            require_dpop: true,
            admin_token: Some("A".repeat(48)),
            registration_token: Some("B".repeat(48)),
            cors_origins: vec!["https://app.example.com".to_string()],
            cookie_secure: true,
            hsts: true,
            trust_proxy: true,
            rate_limit: true,
            recovery_enabled: true,
            max_passkeys: 10,
            audit_retention_days: 90,
            session_ttl: 28_800,
            session_idle_ttl: 7_200,
            code_ttl: 60,
            access_ttl: 300,
            refresh_ttl: 2_592_000,
            id_ttl: 300,
            par_ttl: 90,
            device_ttl: 600,
            device_interval: 5,
        }
    }

    #[test]
    fn production_configuration_passes_with_all_required_guardrails() {
        assert!(validate_production_config(&valid_production_config(), false).is_ok());
    }

    #[test]
    fn production_rejects_missing_or_placeholder_secrets() {
        let mut config = valid_production_config();
        config.admin_token =
            Some("REPLACE_WITH_A_RANDOM_SECRET_OF_AT_LEAST_32_CHARACTERS".to_string());
        assert!(validate_production_config(&config, false).is_err());
        assert!(!is_usable_production_secret(config.admin_token.as_ref()));
    }

    #[test]
    fn production_requires_distinct_administration_and_registration_secrets() {
        let mut config = valid_production_config();
        config.registration_token = config.admin_token.clone();
        assert!(validate_production_config(&config, false).is_err());
    }

    #[test]
    fn vercel_requires_a_non_empty_exact_cors_allowlist() {
        let mut config = valid_production_config();
        config.cors_origins.clear();
        assert!(validate_production_config(&config, false).is_ok());
        assert!(validate_production_config(&config, true).is_err());
    }
}
