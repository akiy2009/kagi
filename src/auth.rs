//! Browser-facing authentication: passkey sign-in/up, consent, recovery and
//! the account console. The session is an opaque cookie whose SHA-256 is
//! stored server side.

use crate::db::{self, params, Flow, Session, User};
use crate::error::OauthError;
use crate::oidc;
use crate::ratelimit;
use crate::ui;
use crate::util::*;
use crate::webauthn;
use crate::AppState;
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const COOKIE_NAME: &str = "kagi_sid";
/// `__Host-` prefixed name used when the cookie is marked `Secure`. The prefix
/// makes the browser reject a cookie injected over http or from a sibling
/// subdomain.
pub const HOST_COOKIE_NAME: &str = "__Host-kagi_sid";
pub const ACR_PASSKEY: &str = "urn:kagi:acr:passkey";
pub const ACR_RECOVERY: &str = "urn:kagi:acr:recovery";

fn session_expired(session: &Session, now: i64, idle_ttl: i64) -> bool {
    let last_seen_at = if session.last_seen_at > 0 {
        session.last_seen_at
    } else {
        session.created_at
    };
    session.expires_at <= now || (idle_ttl > 0 && now.saturating_sub(last_seen_at) > idle_ttl)
}

// ---------------------------------------------------------------------------
// Request metadata, auditing and rate limiting
// ---------------------------------------------------------------------------

fn client_meta(headers: &HeaderMap) -> (Option<String>, Option<String>) {
    (
        ratelimit::client_ip(headers),
        ratelimit::client_user_agent(headers),
    )
}

pub(crate) fn audit(st: &AppState, user_id: Option<&str>, kind: &str, detail: &str, headers: &HeaderMap) {
    let (ip, ua) = client_meta(headers);
    let _ = st
        .db
        .with(|c| db::record_audit(c, user_id, None, kind, detail, ip.as_deref(), ua.as_deref()));
}

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

pub fn session_from_headers(st: &AppState, headers: &HeaderMap) -> Option<Session> {
    let cookies = parse_cookies(headers);
    // Prefer the hardened cookie, but keep reading the legacy name so an
    // upgrade does not sign every existing browser out.
    let sid = cookies
        .get(HOST_COOKIE_NAME)
        .or_else(|| cookies.get(COOKIE_NAME))?;
    let hash = sha256_hex(sid);
    let now = now();

    st.db
        .with(|c| {
            let Some(session) = db::load_session(c, &hash)? else {
                return Ok(None);
            };

            // Older databases may contain last_seen_at = 0; the helper falls
            // back to created_at and enforces both absolute and idle expiry.
            if session_expired(&session, now, st.cfg.session_idle_ttl) {
                // An expired session must not leave live refresh/access tokens
                // behind, so revoke them before dropping the row.
                db::revoke_session_tokens(c, &session.id)?;
                db::delete_session(c, &session.id, &session.user_id)?;
                return Ok(None);
            }

            // Write at most once a minute: the account console shows last
            // activity, but every page view should not cost a write on Postgres.
            let last_seen = if session.last_seen_at > 0 {
                session.last_seen_at
            } else {
                session.created_at
            };
            if last_seen + 60 < now {
                db::touch_session(c, &session.id, now)?;
            }
            Ok(Some(session))
        })
        .ok()
        .flatten()
}

fn create_session(
    st: &AppState,
    user_id: &str,
    amr: Vec<String>,
    acr: &str,
    headers: &HeaderMap,
) -> anyhow::Result<(String, Session)> {
    let sid = random_token(32);
    let id = sha256_hex(&sid);
    let auth_time = now();
    let expires_at = auth_time + st.cfg.session_ttl;
    let (ip, user_agent) = client_meta(headers);
    st.db.with(|c| {
        c.execute(
            "INSERT INTO sessions
                (id, user_id, auth_time, amr, acr, expires_at, created_at, last_seen_at, user_agent, ip)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                id,
                user_id,
                auth_time,
                serde_json::to_string(&amr).unwrap_or_else(|_| "[]".into()),
                acr,
                expires_at,
                auth_time,
                auth_time,
                user_agent,
                ip,
            ],
        )?;
        Ok(())
    })?;
    Ok((
        sid,
        Session {
            id,
            user_id: user_id.to_string(),
            auth_time,
            amr,
            acr: acr.into(),
            expires_at,
            created_at: auth_time,
            last_seen_at: auth_time,
            user_agent,
            ip,
        },
    ))
}

fn session_cookie_name(st: &AppState) -> &'static str {
    if st.cfg.cookie_secure {
        HOST_COOKIE_NAME
    } else {
        COOKIE_NAME
    }
}

fn build_cookie(st: &AppState, name: &str, sid: &str, max_age: i64) -> HeaderValue {
    let mut value = format!("{name}={sid}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age}");
    if st.cfg.cookie_secure || name == HOST_COOKIE_NAME {
        value.push_str("; Secure");
    }
    HeaderValue::from_str(&value).expect("cookie value is valid ASCII")
}

fn session_cookie(st: &AppState, sid: &str) -> HeaderValue {
    build_cookie(st, session_cookie_name(st), sid, st.cfg.session_ttl)
}

/// Clear both the hardened and the legacy cookie names so an upgrade or a
/// misconfigured `Secure` flag cannot leave a usable session behind.
fn cleared_cookies(st: &AppState) -> Vec<HeaderValue> {
    [COOKIE_NAME, HOST_COOKIE_NAME]
        .iter()
        .map(|name| build_cookie(st, name, "", 0))
        .collect()
}

/// Delete the server-side session(s), revoke tokens issued from them and
/// return `Set-Cookie` headers that clear the browser cookies.
pub fn end_local_session(st: &AppState, headers: &HeaderMap) -> Vec<HeaderValue> {
    let cookies = parse_cookies(headers);
    let mut hashes: Vec<String> = Vec::new();
    for name in [HOST_COOKIE_NAME, COOKIE_NAME] {
        if let Some(sid) = cookies.get(name) {
            let hash = sha256_hex(sid);
            if !hashes.contains(&hash) {
                hashes.push(hash);
            }
        }
    }
    if !hashes.is_empty() {
        // Resolve the sessions before deleting the rows: back-channel logout
        // needs the user and session identifiers after the tokens are revoked.
        let mut ended: Vec<(String, String)> = Vec::new();
        for hash in &hashes {
            if let Ok(Some(session)) = st.db.with(|c| db::load_session(c, hash)) {
                ended.push((session.user_id, session.id));
            }
        }
        // Logout must revoke server-tracked JWTs as well as deleting the browser
        // session. Otherwise a copied access token could remain active until exp.
        let _ = st.db.tx(|tx| {
            for hash in &hashes {
                db::revoke_session_tokens(tx, hash)?;
                tx.execute("DELETE FROM sessions WHERE id = ?1", params![hash])?;
            }
            Ok(())
        });
        for (user_id, session_id) in ended {
            crate::backchannel::notify(st, &user_id, Some(&session_id));
        }
    }
    cleared_cookies(st)
}

fn attach_cookie(mut res: Response, cookie: HeaderValue) -> Response {
    res.headers_mut().append(header::SET_COOKIE, cookie);
    res
}

/// Turn an internal failure into an opaque client error.
///
/// Database and filesystem errors can contain identifiers or paths, so they are
/// logged server-side only. Browsers get a stable, generic message.
fn internal(context: &'static str) -> impl Fn(anyhow::Error) -> OauthError {
    move |error| {
        eprintln!("[kagi] {context}: {error:#}");
        OauthError::server_error("処理を完了できませんでした。時間をおいて再度お試しください。")
    }
}

fn require_session(st: &AppState, headers: &HeaderMap) -> Result<(Session, User), OauthError> {
    let session = session_from_headers(st, headers)
        .ok_or_else(|| OauthError::unauthorized("サインインが必要です"))?;
    let user = st
        .db
        .with(|c| db::load_user(c, &session.user_id))?
        .ok_or_else(|| OauthError::unauthorized("ユーザーが見つかりません"))?;
    Ok((session, user))
}

// ---------------------------------------------------------------------------
// Flow helpers
// ---------------------------------------------------------------------------

pub(crate) fn insert_flow(
    st: &AppState,
    kind: &str,
    user_id: Option<&str>,
    client_id: Option<&str>,
    payload: &Value,
    csrf: Option<&str>,
    ttl: i64,
) -> anyhow::Result<Flow> {
    let id = new_id();
    let expires_at = now() + ttl;
    st.db.with(|c| {
        c.execute(
            "INSERT INTO flows (id, kind, user_id, client_id, payload, challenge, csrf, expires_at, created_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, NULL, ?6, ?7, ?8, 0)",
            params![
                id,
                kind,
                user_id,
                client_id,
                serde_json::to_string(payload)?,
                csrf,
                expires_at,
                now()
            ],
        )?;
        Ok(())
    })?;
    Ok(Flow {
        id,
        kind: kind.to_string(),
        user_id: user_id.map(String::from),
        client_id: client_id.map(String::from),
        payload: payload.clone(),
        challenge: None,
        csrf: csrf.map(String::from),
        expires_at,
        consumed: false,
    })
}

fn set_challenge(st: &AppState, rid: &str, challenge: &str) -> anyhow::Result<()> {
    st.db.with(|c| {
        let changed = c.execute(
            "UPDATE flows SET challenge = ?1 WHERE id = ?2 AND consumed = 0 AND expires_at > ?3",
            params![challenge, rid, now()],
        )?;
        anyhow::ensure!(changed == 1, "flow is consumed or expired");
        Ok(())
    })?;
    Ok(())
}

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(ui::error_page("400", message)),
    )
        .into_response()
}

/// Only same-origin, absolute paths are accepted as post-login destinations.
/// This blocks `//evil.example`, backslash tricks and header/control injection.
pub fn safe_next(raw: &str) -> String {
    if raw.len() <= 512
        && raw.starts_with('/')
        && !raw.starts_with("//")
        && !raw.contains('\\')
        && !raw.chars().any(char::is_control)
    {
        raw.to_string()
    } else {
        "/".to_string()
    }
}

// ---------------------------------------------------------------------------
// Login
// ---------------------------------------------------------------------------

pub async fn login_page(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let rid = match q.get("rid") {
        Some(rid) => rid.clone(),
        None => {
            let next = safe_next(q.get("next").map(String::as_str).unwrap_or("/"));
            match insert_flow(
                &st,
                "session",
                None,
                None,
                &json!({ "next": next }),
                Some(random_token(18).as_str()),
                600,
            ) {
                Ok(flow) => return oidc::redirect_302(&format!("/login?rid={}", urlenc(&flow.id))),
                Err(_) => return bad_request("ログイン画面を初期化できませんでした"),
            }
        }
    };

    let flow = match st.db.with(|c| db::load_flow(c, &rid)) {
        Ok(Some(f)) => f,
        _ => return bad_request("このログインリンクは期限切れです。もう一度お試しください。"),
    };
    if !matches!(flow.kind.as_str(), "authorize" | "session") {
        return bad_request("不正なログイン要求です");
    }

    Html(ui::login_page(&flow.id, flow.csrf.as_deref().unwrap_or(""))).into_response()
}

#[derive(Deserialize)]
pub struct RidRequest {
    pub rid: String,
}

#[derive(Deserialize)]
pub struct CredentialRequest {
    pub rid: String,
    pub credential: Value,
}

pub async fn login_options(State(st): State<AppState>, Json(req): Json<RidRequest>) -> Response {
    let flow = match st.db.with(|c| db::load_flow(c, &req.rid)) {
        Ok(Some(f)) if matches!(f.kind.as_str(), "authorize" | "session") => f,
        _ => {
            return OauthError::invalid_request("ログイン要求が無効か期限切れです").into_response()
        }
    };

    let (public_key, challenge) = webauthn::authentication_options(&st.cfg, &[]);
    if set_challenge(&st, &flow.id, &challenge).is_err() {
        return OauthError::server_error("チャレンジを保存できませんでした").into_response();
    }
    Json(json!({ "publicKey": public_key })).into_response()
}

pub async fn login_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Response {
    match login_verify_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => {
            audit(&st, None, "auth.login_failed", &e.description, &headers);
            e.into_response()
        }
    }
}

fn login_verify_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: CredentialRequest,
) -> Result<Response, OauthError> {
    let flow = st
        .db
        .with(|c| db::load_flow(c, &req.rid))?
        .ok_or_else(|| OauthError::invalid_request("ログイン要求が無効か期限切れです"))?;
    if !matches!(flow.kind.as_str(), "authorize" | "session") {
        return Err(OauthError::invalid_request("不正なログイン要求です"));
    }
    let challenge = flow
        .challenge
        .clone()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| OauthError::invalid_request("チャレンジがありません"))?;

    let cred_id = req
        .credential
        .get("rawId")
        .or_else(|| req.credential.get("id"))
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::invalid_request("credential id がありません"))?
        .to_string();

    let credential = st
        .db
        .with(|c| db::load_credential(c, &cred_id))?
        .ok_or_else(|| OauthError::invalid_request("このパスキーは登録されていません"))?;

    let outcome =
        webauthn::verify_authentication(&st.cfg, &challenge, &req.credential, &credential)
            .map_err(|error| {
                eprintln!("[kagi] WebAuthn authentication failed: {error:#}");
                OauthError::invalid_request("認証に失敗しました")
            })?;

    // Consume the challenge and update the credential counter in one transaction.
    // The conditional update makes the ceremony single-use even when two valid
    // verification requests arrive concurrently.
    let consumed = st.db.tx(|tx| {
        let changed = tx.execute(
            "UPDATE flows SET challenge = '' WHERE id = ?1 AND kind IN ('authorize', 'session') AND challenge = ?2 AND consumed = 0 AND expires_at > ?3",
            params![flow.id, challenge, now()],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        let credential_updated = tx.execute(
            "UPDATE credentials SET sign_count = ?1, backup_state = ?2, last_used_at = ?3 WHERE id = ?4 AND sign_count = ?5",
            params![
                outcome.sign_count,
                outcome.backup_state as i64,
                now(),
                credential.id,
                credential.sign_count,
            ],
        )?;
        Ok(credential_updated == 1)
    })?;
    if !consumed {
        return Err(OauthError::invalid_request(
            "ログイン要求は既に使用済みか期限切れです",
        ));
    }

    let user = st
        .db
        .with(|c| db::load_user(c, &outcome.user_id))?
        .ok_or_else(|| OauthError::invalid_request("ユーザーが見つかりません"))?;

    let amr = if credential.backup_eligible {
        vec!["pop".to_string(), "swk".to_string()]
    } else {
        vec!["pop".to_string(), "hwk".to_string()]
    };
    let (sid, _session) = create_session(st, &user.id, amr, ACR_PASSKEY, headers)
        .map_err(internal("creating a session"))?;

    audit(
        st,
        Some(&user.id),
        "auth.login",
        "パスキーでサインイン",
        headers,
    );

    let next = if flow.kind == "authorize" {
        format!("/consent?rid={}", urlenc(&flow.id))
    } else {
        flow.payload
            .get("next")
            .and_then(Value::as_str)
            .map(safe_next)
            .unwrap_or_else(|| "/".to_string())
    };

    let res = Json(json!({ "ok": true, "next": next })).into_response();
    Ok(attach_cookie(res, session_cookie(st, &sid)))
}

// ---------------------------------------------------------------------------
// Sign-up
// ---------------------------------------------------------------------------

pub async fn signup_page(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !st.cfg.allow_signup {
        return (
            StatusCode::FORBIDDEN,
            Html(ui::error_page("403", "新規登録は無効になっています")),
        )
            .into_response();
    }
    Html(ui::signup_page(q.get("rid").map(String::as_str))).into_response()
}

#[derive(Deserialize)]
pub struct SignupStart {
    pub username: String,
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub rid: Option<String>,
}

pub async fn signup_options(State(st): State<AppState>, Json(req): Json<SignupStart>) -> Response {
    match signup_options_inner(&st, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn signup_options_inner(st: &AppState, req: SignupStart) -> Result<Response, OauthError> {
    if !st.cfg.allow_signup {
        return Err(OauthError::invalid_request("新規登録は無効になっています"));
    }
    let username = req.username.trim().to_ascii_lowercase();
    if username.len() < 3 || username.len() > 64 {
        return Err(OauthError::invalid_request(
            "ユーザー名は3〜64文字で入力してください",
        ));
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(OauthError::invalid_request(
            "ユーザー名は英数字と . _ - のみ使用できます",
        ));
    }
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() || display_name.chars().count() > 80 {
        return Err(OauthError::invalid_request("表示名を入力してください"));
    }
    let email = req
        .email
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(email) = &email {
        if !email.contains('@') || email.len() > 254 {
            return Err(OauthError::invalid_request(
                "メールアドレスの形式が不正です",
            ));
        }
    }
    if st
        .db
        .with(|c| db::load_user_by_name(c, &username))?
        .is_some()
    {
        return Err(OauthError::invalid_request(
            "このユーザー名は既に使われています",
        ));
    }

    let user_id = new_id();
    let user = User {
        id: user_id.clone(),
        username: username.clone(),
        display_name: display_name.clone(),
        email: email.clone(),
        email_verified: false,
        created_at: now(),
    };
    let (public_key, challenge) = webauthn::registration_options(&st.cfg, &user, &[]);
    let payload = json!({
        "user_id": user_id,
        "username": username,
        "display_name": display_name,
        "email": email,
        "return_rid": req.rid,
    });
    let flow = insert_flow(
        st,
        "signup",
        Some(user_id.as_str()),
        None,
        &payload,
        None,
        600,
    )
    .map_err(internal("storing a sign-up flow"))?;
    set_challenge(st, &flow.id, &challenge).map_err(internal("storing a WebAuthn challenge"))?;

    Ok(Json(json!({
        "rid": flow.id,
        "publicKey": public_key,
    }))
    .into_response())
}

pub async fn signup_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Response {
    match signup_verify_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => {
            audit(&st, None, "auth.signup_failed", &e.description, &headers);
            e.into_response()
        }
    }
}

fn signup_verify_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: CredentialRequest,
) -> Result<Response, OauthError> {
    let flow = st
        .db
        .with(|c| db::load_flow(c, &req.rid))?
        .ok_or_else(|| OauthError::invalid_request("登録セッションが期限切れです"))?;
    if flow.kind != "signup" {
        return Err(OauthError::invalid_request("不正な登録要求です"));
    }
    let challenge = flow
        .challenge
        .clone()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| OauthError::invalid_request("チャレンジがありません"))?;

    let payload = &flow.payload;
    let user = User {
        id: payload["user_id"].as_str().unwrap_or_default().to_string(),
        username: payload["username"].as_str().unwrap_or_default().to_string(),
        display_name: payload["display_name"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        email: payload["email"].as_str().map(String::from),
        email_verified: false,
        created_at: now(),
    };
    if user.id.is_empty() || user.username.is_empty() {
        return Err(OauthError::server_error("登録データが壊れています"));
    }

    let new = webauthn::verify_registration(&st.cfg, &challenge, &user, &req.credential)
        .map_err(|error| {
            eprintln!("[kagi] WebAuthn registration failed: {error:#}");
            OauthError::invalid_request("パスキーの登録に失敗しました")
        })?;

    st.db
        .tx(|tx| {
            // Claim the registration ceremony before creating any account data.
            // The conditional update makes the flow single-use under concurrency.
            let claimed = tx.execute(
                "UPDATE flows SET consumed = 1, challenge = '' \
             WHERE id = ?1 AND kind = 'signup' AND challenge = ?2 \
               AND consumed = 0 AND expires_at > ?3",
                params![flow.id, challenge, now()],
            )?;
            anyhow::ensure!(
                claimed == 1,
                "registration flow already consumed or expired"
            );

            tx.execute(
                "INSERT INTO users (id, username, display_name, email, email_verified, created_at)
             VALUES (?1, ?2, ?3, ?4, 0, ?5)",
                params![user.id, user.username, user.display_name, user.email, now()],
            )?;
            tx.execute(
                "INSERT INTO credentials
                (id, user_id, public_key, key_type, sign_count, transports, aaguid,
                 backup_eligible, backup_state, nickname, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
                params![
                    new.id,
                    user.id,
                    new.cose,
                    new.alg_name,
                    new.sign_count,
                    serde_json::to_string(&new.transports).unwrap_or_else(|_| "[]".into()),
                    new.aaguid,
                    new.backup_eligible as i64,
                    new.backup_state as i64,
                    "最初のパスキー",
                    now(),
                ],
            )?;
            Ok(())
        })
        .map_err(|e| {
            if db::is_unique_violation(&e) {
                OauthError::invalid_request("このユーザー名は既に使われています")
            } else {
                internal("storing a new account")(e)
            }
        })?;

    let amr = if new.backup_eligible {
        vec!["pop".to_string(), "swk".to_string()]
    } else {
        vec!["pop".to_string(), "hwk".to_string()]
    };
    let (sid, _) = create_session(st, &user.id, amr, ACR_PASSKEY, headers)
        .map_err(internal("creating a session"))?;

    audit(
        st,
        Some(&user.id),
        "auth.signup",
        "パスキーでアカウントを作成",
        headers,
    );

    let next = match payload["return_rid"].as_str() {
        Some(rid) if !rid.is_empty() => {
            let still_valid = st
                .db
                .with(|c| db::load_flow(c, rid))
                .ok()
                .flatten()
                .is_some();
            if still_valid {
                format!("/consent?rid={}", urlenc(rid))
            } else {
                "/".to_string()
            }
        }
        _ => "/".to_string(),
    };

    let res = Json(json!({ "ok": true, "next": next })).into_response();
    Ok(attach_cookie(res, session_cookie(st, &sid)))
}

// ---------------------------------------------------------------------------
// Consent
// ---------------------------------------------------------------------------

pub async fn consent_page(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let rid = match q.get("rid") {
        Some(r) => r.clone(),
        None => return bad_request("認可リクエストが指定されていません"),
    };
    let Some(session) = session_from_headers(&st, &headers) else {
        return oidc::redirect_302(&format!("/login?rid={}", urlenc(&rid)));
    };
    let flow = match st.db.with(|c| db::load_flow(c, &rid)) {
        Ok(Some(f)) if f.kind == "authorize" => f,
        _ => return bad_request("この認可リクエストは期限切れです"),
    };
    let params: oidc::AuthzParams = match serde_json::from_value(flow.payload.clone()) {
        Ok(p) => p,
        Err(_) => return bad_request("認可リクエストが壊れています"),
    };
    let client = match st.db.with(|c| db::load_client(c, &params.client_id)) {
        Ok(Some(c)) => c,
        _ => return bad_request("クライアントが見つかりません"),
    };
    let user = match st.db.with(|c| db::load_user(c, &session.user_id)) {
        Ok(Some(u)) => u,
        _ => return bad_request("ユーザーが見つかりません"),
    };

    let redirect_host = params
        .redirect_uri
        .split("://")
        .nth(1)
        .unwrap_or(&params.redirect_uri)
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();

    Html(ui::consent_page(
        &flow.id,
        flow.csrf.as_deref().unwrap_or(""),
        &client.name,
        &user.username,
        &params.scope,
        &redirect_host,
    ))
    .into_response()
}

pub async fn consent_submit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(session) = session_from_headers(&st, &headers) else {
        return oidc::redirect_302("/login");
    };
    let Some(rid) = form.get("rid") else {
        return bad_request("認可リクエストがありません");
    };
    let flow = match st.db.with(|c| db::load_flow(c, rid)) {
        Ok(Some(f)) if f.kind == "authorize" => f,
        _ => return bad_request("この認可リクエストは期限切れです"),
    };
    let csrf_ok = match (&flow.csrf, form.get("csrf")) {
        (Some(expected), Some(provided)) => ct_eq(expected, provided),
        _ => false,
    };
    if !csrf_ok {
        return bad_request("CSRF トークンが一致しません");
    }
    let user = match st.db.with(|c| db::load_user(c, &session.user_id)) {
        Ok(Some(u)) => u,
        _ => return bad_request("ユーザーが見つかりません"),
    };
    let approve = form.get("decision").map(|d| d == "allow").unwrap_or(false);
    if approve {
        if let Ok(params) = serde_json::from_value::<oidc::AuthzParams>(flow.payload.clone()) {
            let _ = st
                .db
                .with(|c| db::record_consent(c, &user.id, &params.client_id, &params.scope));
            audit(
                &st,
                Some(&user.id),
                "consent.grant",
                &format!("クライアント {} へのアクセスを許可", params.client_id),
                &headers,
            );
        }
    } else {
        audit(
            &st,
            Some(&user.id),
            "consent.deny",
            "認可リクエストを拒否",
            &headers,
        );
    }
    oidc::complete_authorization(&st, &flow, &user, &session, approve)
}

// ---------------------------------------------------------------------------
// Account console
// ---------------------------------------------------------------------------

pub async fn account(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(session) = session_from_headers(&st, &headers) else {
        return oidc::redirect_302("/login");
    };
    let user = match st.db.with(|c| db::load_user(c, &session.user_id)) {
        Ok(Some(u)) => u,
        _ => return oidc::redirect_302("/login"),
    };
    let creds = st
        .db
        .with(|c| db::credentials_for_user(c, &user.id))
        .unwrap_or_default();
    let sessions = st
        .db
        .with(|c| db::list_sessions(c, &user.id))
        .unwrap_or_default();
    let consents = st
        .db
        .with(|c| db::list_consents(c, &user.id))
        .unwrap_or_default();
    let events = st
        .db
        .with(|c| db::recent_audit(c, &user.id, 12))
        .unwrap_or_default();
    let recovery_codes = st
        .db
        .with(|c| db::count_recovery_codes(c, &user.id))
        .unwrap_or(0);
    Html(ui::account_page(
        &user,
        &creds,
        &sessions,
        &session.id,
        &consents,
        &events,
        recovery_codes,
        st.cfg.recovery_enabled,
    ))
    .into_response()
}

pub async fn account_logout(State(st): State<AppState>, headers: HeaderMap) -> Response {
    if let Some(session) = session_from_headers(&st, &headers) {
        audit(
            &st,
            Some(&session.user_id),
            "auth.logout",
            "サインアウト",
            &headers,
        );
    }
    let cookies = end_local_session(&st, &headers);
    let mut res = oidc::redirect_302("/login");
    for cookie in cookies {
        res.headers_mut().append(header::SET_COOKIE, cookie);
    }
    res
}

// ---------------------------------------------------------------------------
// Adding another passkey
// ---------------------------------------------------------------------------

pub async fn add_passkey_options(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match add_passkey_options_inner(&st, &headers) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn add_passkey_options_inner(st: &AppState, headers: &HeaderMap) -> Result<Response, OauthError> {
    let (session, user) = require_session(st, headers)?;
    let existing = st.db.with(|c| db::credentials_for_user(c, &user.id))?;
    if existing.len() as i64 >= st.cfg.max_passkeys {
        return Err(OauthError::invalid_request(format!(
            "パスキーは最大 {} 個まで登録できます",
            st.cfg.max_passkeys
        )));
    }

    let (public_key, challenge) = webauthn::registration_options(&st.cfg, &user, &existing);
    let flow = insert_flow(
        st,
        "addpasskey",
        Some(session.user_id.as_str()),
        None,
        &json!({}),
        None,
        600,
    )
    .map_err(internal("storing a sign-up flow"))?;
    set_challenge(st, &flow.id, &challenge).map_err(internal("storing a WebAuthn challenge"))?;

    Ok(Json(json!({ "rid": flow.id, "publicKey": public_key })).into_response())
}

pub async fn add_passkey_verify(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<CredentialRequest>,
) -> Response {
    match add_passkey_verify_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn add_passkey_verify_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: CredentialRequest,
) -> Result<Response, OauthError> {
    let (session, user) = require_session(st, headers)?;
    let flow = st
        .db
        .with(|c| db::load_flow(c, &req.rid))?
        .ok_or_else(|| OauthError::invalid_request("登録セッションが期限切れです"))?;
    if flow.kind != "addpasskey" || flow.user_id.as_deref() != Some(session.user_id.as_str()) {
        return Err(OauthError::invalid_request("不正な登録要求です"));
    }
    let challenge = flow
        .challenge
        .clone()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| OauthError::invalid_request("チャレンジがありません"))?;

    let count = st.db.with(|c| db::count_credentials(c, &user.id))?;
    if count >= st.cfg.max_passkeys {
        return Err(OauthError::invalid_request(format!(
            "パスキーは最大 {} 個まで登録できます",
            st.cfg.max_passkeys
        )));
    }

    let new = webauthn::verify_registration(&st.cfg, &challenge, &user, &req.credential)
        .map_err(|error| {
            eprintln!("[kagi] WebAuthn registration failed: {error:#}");
            OauthError::invalid_request("パスキーの登録に失敗しました")
        })?;

    st.db
        .tx(|tx| {
            // Claim the passkey-registration ceremony before inserting the key.
            let claimed = tx.execute(
                "UPDATE flows SET consumed = 1, challenge = '' \
             WHERE id = ?1 AND kind = 'addpasskey' AND user_id = ?2 \
               AND challenge = ?3 AND consumed = 0 AND expires_at > ?4",
                params![flow.id, user.id, challenge, now()],
            )?;
            anyhow::ensure!(claimed == 1, "passkey flow already consumed or expired");

            tx.execute(
                "INSERT INTO credentials
                (id, user_id, public_key, key_type, sign_count, transports, aaguid,
                 backup_eligible, backup_state, nickname, created_at, last_used_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, NULL)",
                params![
                    new.id,
                    user.id,
                    new.cose,
                    new.alg_name,
                    new.sign_count,
                    serde_json::to_string(&new.transports).unwrap_or_else(|_| "[]".into()),
                    new.aaguid,
                    new.backup_eligible as i64,
                    new.backup_state as i64,
                    "追加したパスキー",
                    now(),
                ],
            )?;
            Ok(())
        })
        .map_err(internal("storing an added passkey"))?;

    audit(st, Some(&user.id), "passkey.add", "パスキーを追加", headers);

    Ok(Json(json!({ "ok": true })).into_response())
}

#[cfg(test)]
mod session_expiry_tests {
    use super::*;

    fn sample_session() -> Session {
        Session {
            id: "session-hash".into(),
            user_id: "user-1".into(),
            auth_time: 100,
            amr: vec!["passkey".into()],
            acr: ACR_PASSKEY.into(),
            expires_at: 200,
            created_at: 100,
            last_seen_at: 190,
            user_agent: None,
            ip: None,
        }
    }

    #[test]
    fn absolute_expiry_is_enforced_even_when_recently_active() {
        let mut session = sample_session();
        session.last_seen_at = 199;
        assert!(session_expired(&session, 200, 180));
    }

    #[test]
    fn idle_expiry_is_enforced_before_absolute_expiry() {
        let session = sample_session();
        assert!(session_expired(&session, 195, 4));
    }

    #[test]
    fn zero_idle_timeout_disables_only_the_idle_check() {
        let mut session = sample_session();
        session.expires_at = 500;
        session.last_seen_at = 100;
        assert!(!session_expired(&session, 200, 0));
    }
}
// ---------------------------------------------------------------------------
// Account APIs
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct ProfileUpdate {
    pub display_name: String,
    #[serde(default)]
    pub email: Option<String>,
}

pub async fn update_profile(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ProfileUpdate>,
) -> Response {
    match update_profile_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn update_profile_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: ProfileUpdate,
) -> Result<Response, OauthError> {
    let (_session, user) = require_session(st, headers)?;
    let display_name = req.display_name.trim().to_string();
    if display_name.is_empty() || display_name.chars().count() > 80 {
        return Err(OauthError::invalid_request(
            "表示名は1〜80文字で入力してください",
        ));
    }
    let email = req
        .email
        .map(|e| e.trim().to_string())
        .filter(|e| !e.is_empty());
    if let Some(email) = &email {
        if !email.contains('@') || email.len() > 254 || !email.is_ascii() {
            return Err(OauthError::invalid_request(
                "メールアドレスの形式が不正です",
            ));
        }
    }
    st.db
        .with(|c| db::update_user_profile(c, &user.id, &display_name, email.as_deref()))?;
    audit(
        st,
        Some(&user.id),
        "profile.update",
        "プロフィールを更新",
        headers,
    );
    Ok(Json(json!({ "ok": true })).into_response())
}

#[derive(Deserialize)]
pub struct PasskeyRename {
    pub id: String,
    pub name: String,
}

pub async fn rename_passkey(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRename>,
) -> Response {
    match rename_passkey_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn rename_passkey_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: PasskeyRename,
) -> Result<Response, OauthError> {
    let (_session, user) = require_session(st, headers)?;
    let name = req.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 60 {
        return Err(OauthError::invalid_request(
            "パスキー名は1〜60文字で入力してください",
        ));
    }
    let changed = st
        .db
        .with(|c| db::rename_credential(c, &req.id, &user.id, &name))?;
    if changed == 0 {
        return Err(OauthError::invalid_request("パスキーが見つかりません"));
    }
    audit(
        st,
        Some(&user.id),
        "passkey.rename",
        &format!("パスキー名を変更: {name}"),
        headers,
    );
    Ok(Json(json!({ "ok": true })).into_response())
}

#[derive(Deserialize)]
pub struct PasskeyRef {
    pub id: String,
}

pub async fn delete_passkey(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<PasskeyRef>,
) -> Response {
    match delete_passkey_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn delete_passkey_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: PasskeyRef,
) -> Result<Response, OauthError> {
    let (_session, user) = require_session(st, headers)?;
    // The count check and the delete must be one transaction: two concurrent
    // deletions of the last two passkeys must not leave the account without a
    // way to sign in.
    let changed = st
        .db
        .tx(|tx| {
            if db::count_credentials(tx, &user.id)? <= 1 {
                anyhow::bail!("last-passkey");
            }
            let changed = db::delete_credential(tx, &req.id, &user.id)?;
            if changed > 0 && db::count_credentials(tx, &user.id)? == 0 {
                anyhow::bail!("last-passkey");
            }
            Ok(changed)
        })
        .map_err(|e| {
            if e.to_string().contains("last-passkey") {
                OauthError::invalid_request(
                    "最後のパスキーは削除できません。先に別のパスキーを追加してください。",
                )
            } else {
                // Do not echo database errors to the browser.
                eprintln!("[kagi] passkey deletion failed: {e:#}");
                OauthError::server_error("パスキーを削除できませんでした")
            }
        })?;
    if changed == 0 {
        return Err(OauthError::invalid_request("パスキーが見つかりません"));
    }
    audit(
        st,
        Some(&user.id),
        "passkey.delete",
        "パスキーを削除",
        headers,
    );
    Ok(Json(json!({ "ok": true })).into_response())
}

#[derive(Deserialize)]
pub struct SessionRef {
    pub id: String,
}

pub async fn revoke_session(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SessionRef>,
) -> Response {
    match revoke_session_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn revoke_session_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: SessionRef,
) -> Result<Response, OauthError> {
    let (current, user) = require_session(st, headers)?;
    let changed = st.db.tx(|tx| {
        let changed = db::delete_session(tx, &req.id, &user.id)?;
        if changed > 0 {
            db::revoke_session_tokens(tx, &req.id)?;
        }
        Ok(changed)
    })?;
    if changed == 0 {
        return Err(OauthError::invalid_request("セッションが見つかりません"));
    }
    crate::backchannel::notify(st, &user.id, Some(&req.id));
    audit(
        st,
        Some(&user.id),
        "session.revoke",
        if req.id == current.id {
            "現在のセッションを終了"
        } else {
            "別のデバイスのセッションを終了"
        },
        headers,
    );
    let mut res = Json(json!({ "ok": true, "current": req.id == current.id })).into_response();
    if req.id == current.id {
        for cookie in cleared_cookies(st) {
            res.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }
    Ok(res)
}

pub async fn revoke_other_sessions(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match revoke_other_sessions_inner(&st, &headers) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn revoke_other_sessions_inner(st: &AppState, headers: &HeaderMap) -> Result<Response, OauthError> {
    let (current, user) = require_session(st, headers)?;
    let others: Vec<String> = st.db.with(|c| {
        let rows = c.query_all(
            "SELECT id FROM sessions WHERE user_id = ?1 AND id <> ?2",
            params![user.id, current.id],
        )?;
        rows.iter()
            .map(|row| row.get::<_, String>(0).map_err(|e| anyhow::anyhow!(e.to_string())))
            .collect()
    })?;
    let revoked = st.db.tx(|tx| {
        tx.execute(
            "UPDATE refresh_tokens SET revoked = 1
             WHERE session_id IN (SELECT id FROM sessions WHERE user_id = ?1 AND id <> ?2)",
            params![user.id, current.id],
        )?;
        tx.execute(
            "UPDATE access_tokens SET revoked = 1
             WHERE session_id IN (SELECT id FROM sessions WHERE user_id = ?1 AND id <> ?2)",
            params![user.id, current.id],
        )?;
        Ok(tx.execute(
            "DELETE FROM sessions WHERE user_id = ?1 AND id <> ?2",
            params![user.id, current.id],
        )?)
    })?;
    audit(
        st,
        Some(&user.id),
        "session.revoke_others",
        &format!("他のデバイス {revoked} 件をサインアウト"),
        headers,
    );
    for session_id in others {
        crate::backchannel::notify(st, &user.id, Some(&session_id));
    }
    Ok(Json(json!({ "ok": true, "revoked": revoked })).into_response())
}

#[derive(Deserialize)]
pub struct ConsentRef {
    pub client_id: String,
}

pub async fn revoke_consent(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<ConsentRef>,
) -> Response {
    match revoke_consent_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn revoke_consent_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: ConsentRef,
) -> Result<Response, OauthError> {
    let (_session, user) = require_session(st, headers)?;
    st.db.tx(|tx| {
        db::delete_consent(tx, &user.id, &req.client_id)?;
        // Withdrawing consent must also invalidate everything already issued
        // to that client. Otherwise a refresh token would keep the grant alive
        // despite the user having revoked it in the console.
        db::revoke_client_tokens(tx, &user.id, &req.client_id)?;
        Ok(())
    })?;
    audit(
        st,
        Some(&user.id),
        "consent.revoke",
        &format!("クライアント {} のアクセスを取り消し", req.client_id),
        headers,
    );
    Ok(Json(json!({ "ok": true })).into_response())
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

pub async fn recovery_generate(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match recovery_generate_inner(&st, &headers) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn recovery_generate_inner(st: &AppState, headers: &HeaderMap) -> Result<Response, OauthError> {
    if !st.cfg.recovery_enabled {
        return Err(OauthError::invalid_request(
            "リカバリーコードは無効になっています",
        ));
    }
    let (_session, user) = require_session(st, headers)?;
    let codes: Vec<String> = (0..10).map(|_| recovery_code()).collect();
    let hashes: Vec<String> = codes
        .iter()
        .map(|code| {
            crate::util::hash_recovery_code(&user.id, &normalize_recovery_code(code))
        })
        .collect();
    st.db
        .tx(|tx| db::replace_recovery_codes(tx, &user.id, &hashes, now()))?;
    audit(
        st,
        Some(&user.id),
        "recovery.generate",
        "リカバリーコードを再生成",
        headers,
    );
    Ok(Json(json!({ "ok": true, "codes": codes, "remaining": 10 })).into_response())
}

pub async fn recover_page(
    State(st): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if !st.cfg.recovery_enabled {
        return (
            StatusCode::NOT_FOUND,
            Html(ui::error_page(
                "404",
                "リカバリーコードは無効になっています",
            )),
        )
            .into_response();
    }
    Html(ui::recover_page(q.get("rid").map(String::as_str))).into_response()
}

#[derive(Deserialize)]
pub struct RecoveryRequest {
    pub username: String,
    pub code: String,
    #[serde(default)]
    pub rid: Option<String>,
}

pub async fn recover(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<RecoveryRequest>,
) -> Response {
    match recover_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => {
            audit(&st, None, "recovery.failed", &e.description, &headers);
            e.into_response()
        }
    }
}

fn recover_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: RecoveryRequest,
) -> Result<Response, OauthError> {
    if !st.cfg.recovery_enabled {
        return Err(OauthError::invalid_request(
            "リカバリーコードは無効になっています",
        ));
    }
    let username = req.username.trim();
    let code = normalize_recovery_code(&req.code);
    if username.is_empty() || code.len() < 8 {
        return Err(OauthError::invalid_request(
            "ユーザー名とリカバリーコードを確認してください",
        ));
    }

    let user = st.db.with(|c| db::load_user_by_name(c, username))?;
    let consumed = match &user {
        Some(user) => {
            let hash = crate::util::hash_recovery_code(&user.id, &code);
            st.db
                .with(|c| db::consume_recovery_code(c, &user.id, &hash))?
        }
        None => false,
    };
    let Some(user) = user.filter(|_| consumed) else {
        return Err(OauthError::invalid_request(
            "ユーザー名またはリカバリーコードが正しくありません",
        ));
    };

    let (sid, _session) = create_session(
        st,
        &user.id,
        vec!["pwd".into(), "otp".into()],
        ACR_RECOVERY,
        headers,
    )
    .map_err(|e| {
        eprintln!("[kagi] recovery sign-in could not create a session: {e:#}");
        OauthError::server_error("サインインできませんでした")
    })?;
    audit(
        st,
        Some(&user.id),
        "recovery.use",
        "リカバリーコードでサインイン",
        headers,
    );

    let next = match req.rid.as_deref() {
        Some(rid) if !rid.is_empty() => {
            let flow = st.db.with(|c| db::load_flow(c, rid))?;
            match flow {
                Some(flow) if flow.kind == "authorize" => {
                    format!("/consent?rid={}", urlenc(rid))
                }
                _ => "/".to_string(),
            }
        }
        _ => "/".to_string(),
    };
    let res = Json(json!({ "ok": true, "next": next })).into_response();
    Ok(attach_cookie(res, session_cookie(st, &sid)))
}

// ---------------------------------------------------------------------------
// Account deletion
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct DeleteAccount {
    pub username: String,
}

pub async fn delete_account(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<DeleteAccount>,
) -> Response {
    match delete_account_inner(&st, &headers, req) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn delete_account_inner(
    st: &AppState,
    headers: &HeaderMap,
    req: DeleteAccount,
) -> Result<Response, OauthError> {
    let (_session, user) = require_session(st, headers)?;
    if !ct_eq(
        &user.username.to_ascii_lowercase(),
        &req.username.trim().to_ascii_lowercase(),
    ) {
        return Err(OauthError::invalid_request(
            "確認のためユーザー名を正確に入力してください",
        ));
    }
    audit(
        st,
        Some(&user.id),
        "account.delete",
        "アカウントを削除",
        headers,
    );
    st.db.with(|c| db::delete_user(c, &user.id))?;
    let mut res = Json(json!({ "ok": true })).into_response();
    for cookie in cleared_cookies(st) {
        res.headers_mut().append(header::SET_COOKIE, cookie);
    }
    Ok(res)
}
