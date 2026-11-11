//! Protected resources and lifecycle endpoints: userinfo, introspection,
//! revocation, RP-initiated logout, dynamic registration and key rotation.

use crate::db::{self, Client};
use crate::db::{params, OptionalExt};
use crate::error::{ApiResult, OauthError};
use crate::jose;
use crate::oidc;
use crate::util::*;
use crate::AppState;
use axum::extract::{Form, Path, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Access token validation
// ---------------------------------------------------------------------------

/// Split an `Authorization` header into a lowercased scheme and the token.
fn bearer_token(headers: &HeaderMap) -> Option<(String, String)> {
    let raw = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let mut parts = raw.splitn(2, ' ');
    let scheme = parts.next()?.to_ascii_lowercase();
    let token = parts.next()?.trim();
    if matches!(scheme.as_str(), "bearer" | "dpop") && !token.is_empty() {
        Some((scheme, token.to_string()))
    } else {
        None
    }
}

pub fn verify_access_token(st: &AppState, token: &str) -> ApiResult<Value> {
    let jwks = st.keys.read().unwrap_or_else(|e| e.into_inner()).jwks();
    let (_header, claims) = jose::verify_with_jwks(&jwks, token, Some("at+jwt"))
        .map_err(|_| OauthError::unauthorized("invalid access token"))?;

    if claims.get("iss").and_then(Value::as_str) != Some(st.cfg.issuer.as_str()) {
        return Err(OauthError::unauthorized("access token issuer mismatch"));
    }
    let exp = claims.get("exp").and_then(Value::as_i64).unwrap_or(0);
    if exp < now() {
        return Err(OauthError::unauthorized("access token expired"));
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::unauthorized("access token has no jti"))?;

    let revoked: Option<i64> = st.db.with(|c| {
        Ok(c.query_row(
            "SELECT revoked FROM access_tokens WHERE jti = ?1 AND expires_at > ?2",
            params![jti, now()],
            |r| r.get(0),
        )
        .optional()?)
    })?;
    match revoked {
        Some(0) => {}
        _ => return Err(OauthError::unauthorized("access token is not active")),
    }
    Ok(claims)
}

// ---------------------------------------------------------------------------
// UserInfo
// ---------------------------------------------------------------------------

pub async fn userinfo(State(st): State<AppState>, method: Method, headers: HeaderMap) -> Response {
    match userinfo_inner(&st, &method, &headers) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn userinfo_inner(st: &AppState, method: &Method, headers: &HeaderMap) -> ApiResult<Response> {
    const BEARER: &str = "Bearer realm=\"kagi\"";
    const DPOP: &str = "DPoP algs=\"ES256\"";

    let (scheme, token) = bearer_token(headers).ok_or_else(|| {
        OauthError::unauthorized("an access token is required").with_challenge(BEARER)
    })?;
    let claims = verify_access_token(st, &token).map_err(|e| e.with_challenge(BEARER))?;

    let bound_jkt = claims
        .get("cnf")
        .and_then(|c| c.get("jkt"))
        .and_then(Value::as_str)
        .map(str::to_string);

    match (scheme.as_str(), bound_jkt) {
        // RFC 9449 §7.1: a DPoP-bound token needs a matching proof.
        ("dpop", Some(jkt)) => {
            let proof = crate::dpop::require(
                st.cfg.as_ref(),
                &st.db,
                headers,
                method.as_str(),
                "/userinfo",
                Some(token.as_str()),
            )
            .map_err(|e| e.with_status(StatusCode::UNAUTHORIZED).with_challenge(DPOP))?;
            if proof.jkt != jkt {
                return Err(
                    OauthError::unauthorized("DPoP key does not match the token")
                        .with_challenge(DPOP),
                );
            }
        }
        ("dpop", None) => {
            return Err(OauthError::unauthorized(
                "DPoP scheme used with a token that is not DPoP-bound",
            )
            .with_challenge(BEARER));
        }
        // RFC 9449 §7.1: a DPoP-bound token must not be accepted as a bearer token.
        ("bearer", Some(_)) => {
            return Err(OauthError::unauthorized(
                "access token is DPoP-bound and must be presented with the DPoP scheme",
            )
            .with_challenge(DPOP));
        }
        _ => {}
    }

    let sub = claims
        .get("sub")
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::unauthorized("access token has no sub"))?;
    let scope = claims.get("scope").and_then(Value::as_str).unwrap_or("");
    let user = st
        .db
        .with(|c| db::load_user(c, sub))?
        .ok_or_else(|| OauthError::unauthorized("unknown subject"))?;

    let mut out = json!({ "sub": user.id });
    let requested = claims
        .get("kagi_claims")
        .and_then(|value| value.get("userinfo"))
        .and_then(Value::as_object);
    let profile_allowed = oidc::scope_contains(scope, "profile");
    let email_allowed = oidc::scope_contains(scope, "email");
    if let Some(requested) = requested {
        // The RP explicitly named the UserInfo claims it wants. Scope is still
        // enforced: a claims request can never widen the original grant.
        for claim in requested.keys() {
            match claim.as_str() {
                "name" if profile_allowed => out["name"] = json!(user.display_name),
                "preferred_username" if profile_allowed => {
                    out["preferred_username"] = json!(user.username)
                }
                "email" if email_allowed => {
                    if let Some(email) = &user.email {
                        out["email"] = json!(email);
                        out["email_verified"] = json!(user.email_verified);
                    }
                }
                "email_verified" if email_allowed && user.email.is_some() => {
                    out["email_verified"] = json!(user.email_verified)
                }
                _ => {}
            }
        }
    } else {
        if profile_allowed {
            out["name"] = json!(user.display_name);
            out["preferred_username"] = json!(user.username);
        }
        if email_allowed {
            out["email"] = json!(user.email);
            out["email_verified"] = json!(user.email_verified);
        }
    }
    if let Some(sid) = claims.get("sid").and_then(Value::as_str) {
        out["sid"] = json!(sid);
    }

    let mut res = Json(out).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

// ---------------------------------------------------------------------------
// Introspection (RFC 7662)
// ---------------------------------------------------------------------------

pub async fn introspect(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match introspect_inner(&st, &headers, &form) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn introspect_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = oidc::authenticate_client(st, headers, form)?;
    let token = form
        .get("token")
        .ok_or_else(|| OauthError::invalid_request("token is required"))?;

    // Try an access token first (a JWT), then an opaque refresh token.
    if let Ok(claims) = verify_access_token(st, token) {
        let token_client = claims
            .get("client_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if token_client != client.id {
            return Ok(Json(json!({ "active": false })).into_response());
        }
        let mut body = json!({
            "active": true,
            "token_type": if claims.get("cnf").is_some() { "DPoP" } else { "Bearer" },
            "scope": claims.get("scope"),
            "sub": claims.get("sub"),
            "iss": st.cfg.issuer,
            "aud": claims.get("aud"),
            "client_id": claims.get("client_id"),
            "iat": claims.get("iat"),
            "exp": claims.get("exp"),
            "jti": claims.get("jti"),
        });
        if let Some(sid) = claims.get("sid") {
            body["sid"] = sid.clone();
        }
        if let Some(cnf) = claims.get("cnf") {
            body["cnf"] = cnf.clone();
        }
        let mut res = Json(body).into_response();
        res.headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        return Ok(res);
    }

    let hash = sha256_hex(token);
    if let Some(row) = st.db.with(|c| db::load_refresh(c, &hash))? {
        if row.client_id != client.id || row.revoked || row.expires_at < now() {
            return Ok(Json(json!({ "active": false })).into_response());
        }
        let body = json!({
            "active": true,
            "token_type": "refresh_token",
            "scope": row.scope,
            "sub": row.user_id,
            "iss": st.cfg.issuer,
            "aud": client.id,
            "client_id": row.client_id,
            "iat": row.issued_at,
            "exp": row.expires_at,
        });
        return Ok(Json(body).into_response());
    }

    Ok(Json(json!({ "active": false })).into_response())
}

// ---------------------------------------------------------------------------
// Revocation (RFC 7009)
// ---------------------------------------------------------------------------

pub async fn revoke(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match revoke_inner(&st, &headers, &form) {
        Ok(()) => StatusCode::OK.into_response(),
        Err(e) => e.into_response(),
    }
}

fn revoke_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<()> {
    let client = oidc::authenticate_client(st, headers, form)?;
    let token = form
        .get("token")
        .ok_or_else(|| OauthError::invalid_request("token is required"))?;

    // Only revoke a JWT after its signature, issuer, expiry and server-side
    // state have been verified. Parsing without verification would let any
    // authenticated client revoke an arbitrary `jti` it can guess or observe.
    if let Ok(claims) = verify_access_token(st, token) {
        let belongs_to_client = claims.get("client_id").and_then(Value::as_str)
            == Some(client.id.as_str());
        if belongs_to_client {
            if let Some(jti) = claims.get("jti").and_then(Value::as_str) {
                st.db.with(|c| {
                    c.execute(
                        "UPDATE access_tokens SET revoked = 1 WHERE jti = ?1 AND client_id = ?2",
                        params![jti, client.id],
                    )?;
                    Ok(())
                })?;
            }
        }
        // RFC 7009: revoking an unknown or foreign token is not an error.
        return Ok(());
    }

    let hash = sha256_hex(token);
    if let Some(row) = st.db.with(|c| db::load_refresh(c, &hash))? {
        if row.client_id == client.id {
            oidc::revoke_family(st, &row.family_id)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RP-initiated logout
// ---------------------------------------------------------------------------

pub async fn end_session_get(
    State(st): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(q): axum::extract::Query<HashMap<String, String>>,
) -> Response {
    end_session(&st, &headers, &q)
}

pub async fn end_session_post(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    end_session(&st, &headers, &form)
}

fn end_session(st: &AppState, headers: &HeaderMap, params: &HashMap<String, String>) -> Response {
    let mut client: Option<Client> = None;

    if let Some(hint) = params.get("id_token_hint") {
        let jwks = st.keys.read().unwrap_or_else(|e| e.into_inner()).jwks();
        if let Ok((_h, claims)) = jose::verify_with_jwks(&jwks, hint, Some("JWT")) {
            if let Some(aud) = claims.get("aud").and_then(Value::as_str) {
                if let Ok(Some(c)) = st.db.with(|c| db::load_client(c, aud)) {
                    client = Some(c);
                }
            }
        }
    }
    if client.is_none() {
        if let Some(cid) = params.get("client_id") {
            if let Ok(Some(c)) = st.db.with(|c| db::load_client(c, cid)) {
                client = Some(c);
            }
        }
    }

    let mut redirect_to: Option<String> = None;
    if let (Some(target), Some(client)) = (params.get("post_logout_redirect_uri"), client.as_ref())
    {
        if client.post_logout_redirect_uris.iter().any(|u| u == target)
            && validate_redirect_uri(target).is_ok()
        {
            let mut url = target.clone();
            if let Some(state) = params.get("state") {
                url = build_url(&url, &[("state", state.clone())]);
            }
            redirect_to = Some(url);
        } else {
            return (
                StatusCode::BAD_REQUEST,
                "post_logout_redirect_uri is not registered",
            )
                .into_response();
        }
    }

    let cookies = crate::auth::end_local_session(st, headers);

    let mut res = match redirect_to {
        Some(url) => oidc::redirect_302(&url),
        None => {
            let body = r#"<!doctype html><meta charset="utf-8"><title>Signed out</title>
<link rel="stylesheet" href="/static/style.css">
<body class="signed-out"><section class="card narrow">
<div class="brand"><span class="mark"><span></span></span><span>kagi</span></div>
<h1>サインアウトしました</h1>
<p class="muted">このタブは閉じてかまいません。</p>
<p class="foot"><a href="/login">もう一度サインイン</a></p>
</section></body>"#
                .to_string();
            ([(header::CACHE_CONTROL, "no-store")], Html(body)).into_response()
        }
    };
    for cookie in cookies {
        res.headers_mut().append(header::SET_COOKIE, cookie);
    }
    res
}

// ---------------------------------------------------------------------------
// Dynamic client registration (RFC 7591)
// ---------------------------------------------------------------------------

/// Scopes kagi can actually issue. Dynamic registration must not be able to
/// create a client with a scope that no endpoint understands: that would make
/// consent screens and authorization decisions misleading.
const REGISTERABLE_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

fn validate_registerable_scopes(scopes: &[String]) -> ApiResult<()> {
    for scope in scopes {
        if !REGISTERABLE_SCOPES.iter().any(|allowed| allowed == scope) {
            return Err(OauthError::invalid_scope(format!(
                "scope {scope} is not supported"
            )));
        }
    }
    if !scopes.iter().any(|scope| scope == "openid") {
        return Err(OauthError::invalid_scope("openid is required"));
    }
    Ok(())
}

fn parse_optional_uri(value: Option<&Value>, field: &str) -> ApiResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let Some(raw) = value.as_str() else {
        return Err(OauthError::invalid_request(format!(
            "{field} must be a string"
        )));
    };
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    validate_redirect_uri(raw).map_err(|reason| {
        OauthError::invalid_request(format!("{field} is invalid: {reason}"))
    })?;
    Ok(Some(raw.to_string()))
}

fn string_array(body: &Value, field: &str) -> Vec<String> {
    body.get(field)
        .and_then(Value::as_array)
        .map(|array| {
            array
                .iter()
                .filter_map(|value| value.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

fn validate_redirect_list(uris: &[String], field: &str) -> ApiResult<()> {
    if uris.is_empty() {
        return Err(OauthError::invalid_request(format!("{field} is required")));
    }
    if uris.len() > 16 {
        return Err(OauthError::invalid_request(format!(
            "{field} must contain at most 16 entries"
        )));
    }
    for uri in uris {
        validate_redirect_uri(uri).map_err(|reason| {
            OauthError::invalid_request(format!("{field} entry {uri} is invalid: {reason}"))
        })?;
    }
    Ok(())
}

fn validate_client_name(body: &Value) -> ApiResult<String> {
    let name = body
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("dynamic client")
        .trim()
        .to_string();
    if name.is_empty() || name.chars().count() > 120 || name.chars().any(char::is_control) {
        return Err(OauthError::invalid_request(
            "client_name must be 1–120 printable characters",
        ));
    }
    Ok(name)
}

fn client_metadata_json(client: &Client, secret: Option<&str>) -> Value {
    let mut response = json!({
        "client_id": client.id,
        "client_name": client.name,
        "redirect_uris": client.redirect_uris,
        "post_logout_redirect_uris": client.post_logout_redirect_uris,
        "grant_types": client.grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": client.auth_method,
        "scope": client.scopes.join(" "),
        "require_dpop": client.require_dpop,
        "require_pushed_authorization_requests": client.require_par,
        "id_token_signed_response_alg": client.id_token_alg,
        "backchannel_logout_session_required": client.backchannel_logout_session_required,
    });
    if let Some(jwks) = &client.jwks {
        response["jwks"] = jwks.clone();
    }
    if let Some(uri) = &client.backchannel_logout_uri {
        response["backchannel_logout_uri"] = json!(uri);
    }
    if let Some(secret) = secret {
        response["client_secret"] = json!(secret);
        response["client_secret_expires_at"] = json!(0);
    }
    response
}

/// Authenticate an RFC 7592 management request with the registration access
/// token issued at registration time.
fn authenticate_registration_client(
    st: &AppState,
    headers: &HeaderMap,
    client_id: &str,
) -> ApiResult<Client> {
    let token = headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            OauthError::unauthorized("a registration access token is required")
                .with_challenge("Bearer")
        })?;

    let client = st
        .db
        .with(|c| db::load_client(c, client_id))?
        .ok_or_else(|| OauthError::unauthorized("invalid registration access token"))?;

    let Some(expected) = client.registration_token_hash.as_deref() else {
        return Err(OauthError::unauthorized(
            "this client has no registration access token",
        ));
    };
    if !ct_eq(&sha256_hex(token), expected) {
        return Err(OauthError::unauthorized(
            "invalid registration access token",
        ));
    }
    Ok(client)
}

pub async fn client_info(
    State(st): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result: ApiResult<Response> = (|| {
        let client = authenticate_registration_client(&st, &headers, &client_id)?;
        Ok(Json(client_metadata_json(&client, None)).into_response())
    })();
    match result {
        Ok(mut res) => {
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(error) => error.into_response(),
    }
}

pub async fn update_client(
    State(st): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    match update_client_inner(&st, &client_id, &headers, &body) {
        Ok(res) => res,
        Err(error) => error.into_response(),
    }
}

fn update_client_inner(
    st: &AppState,
    client_id: &str,
    headers: &HeaderMap,
    body: &Value,
) -> ApiResult<Response> {
    let existing = authenticate_registration_client(st, headers, client_id)?;

    let redirect_uris = string_array(body, "redirect_uris");
    validate_redirect_list(&redirect_uris, "redirect_uris")?;

    let post_logout = string_array(body, "post_logout_redirect_uris");
    for uri in &post_logout {
        validate_redirect_uri(uri).map_err(|reason| {
            OauthError::invalid_request(format!(
                "post_logout_redirect_uri {uri} is invalid: {reason}"
            ))
        })?;
    }

    let auth_method = body
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or(&existing.auth_method)
        .to_string();
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt"
    ) {
        return Err(OauthError::invalid_request(
            "unsupported token_endpoint_auth_method",
        ));
    }

    let jwks = match body.get("jwks") {
        Some(value) if !value.is_null() => {
            validate_jwks(value)
                .map_err(|reason| OauthError::invalid_request(format!("invalid jwks: {reason}")))?;
            Some(value.to_string())
        }
        _ => None,
    };
    if auth_method == "private_key_jwt" && jwks.is_none() {
        return Err(OauthError::invalid_request(
            "private_key_jwt requires an inline jwks",
        ));
    }

    let grant_types = match body.get("grant_types") {
        Some(_) => string_array(body, "grant_types"),
        None => existing.grant_types.clone(),
    };
    if grant_types.is_empty()
        || grant_types.iter().any(|grant| {
            !matches!(
                grant.as_str(),
                "authorization_code"
                    | "refresh_token"
                    | "client_credentials"
                    | "urn:ietf:params:oauth:grant-type:device_code"
            )
        })
    {
        return Err(OauthError::invalid_request("unsupported grant type"));
    }
    if body.get("response_types").is_some() {
        let response_types = string_array(body, "response_types");
        if response_types.is_empty() || response_types.iter().any(|value| value != "code") {
            return Err(OauthError::invalid_request(
                "only response_type=code is supported",
            ));
        }
    }

    let scopes = match body.get("scope") {
        Some(value) => {
            let raw = value
                .as_str()
                .ok_or_else(|| OauthError::invalid_request("scope must be a string"))?;
            oidc::split_scope(raw)
        }
        None => existing.scopes.clone(),
    };
    validate_registerable_scopes(&scopes)?;

    let name = validate_client_name(body)?;
    let backchannel_logout_uri =
        parse_optional_uri(body.get("backchannel_logout_uri"), "backchannel_logout_uri")?;
    let backchannel_required = body
        .get("backchannel_logout_session_required")
        .and_then(Value::as_bool)
        .unwrap_or(existing.backchannel_logout_session_required);

    // RFC 7592 §2.2: the server may rotate the secret. Rotate when explicitly
    // requested, or when the client moves to a secret-based method for the
    // first time. Never silently keep returning a secret the client cannot see.
    let rotate = body
        .get("rotate_client_secret")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let secret_needed = auth_method.starts_with("client_secret");
    let new_secret = if secret_needed
        && (rotate || existing.secret_hash.is_none() || !existing.auth_method.starts_with("client_secret"))
    {
        Some(random_token(32))
    } else {
        None
    };
    let secret_hash = if let Some(secret) = &new_secret {
        Some(sha256_hex(secret))
    } else if secret_needed {
        existing.secret_hash.clone()
    } else {
        None
    };

    st.db.with(|c| {
        c.execute(
            "UPDATE clients SET name = ?1, secret_hash = ?2, redirect_uris = ?3,
                 post_logout_redirect_uris = ?4, grant_types = ?5, scopes = ?6,
                 auth_method = ?7, jwks = ?8, require_dpop = ?9, require_par = ?10,
                 backchannel_logout_uri = ?11, backchannel_logout_session_required = ?12
             WHERE id = ?13",
            params![
                name,
                secret_hash,
                serde_json::to_string(&redirect_uris).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&post_logout).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&grant_types).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&scopes).unwrap_or_else(|_| "[]".into()),
                auth_method,
                jwks,
                body.get("require_dpop")
                    .and_then(Value::as_bool)
                    .unwrap_or(existing.require_dpop) as i64,
                body.get("require_pushed_authorization_requests")
                    .and_then(Value::as_bool)
                    .unwrap_or(existing.require_par) as i64,
                backchannel_logout_uri,
                backchannel_required as i64,
                client_id,
            ],
        )?;
        Ok(())
    })?;

    let updated = st
        .db
        .with(|c| db::load_client(c, client_id))?
        .ok_or_else(|| OauthError::server_error("client disappeared during update"))?;
    let mut response = client_metadata_json(&updated, new_secret.as_deref());
    response["client_id_issued_at"] = json!(0);
    response["client_secret_expires_at"] = json!(0);

    let mut res = Json(response).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

pub async fn delete_client(
    State(st): State<AppState>,
    Path(client_id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let result: ApiResult<Response> = (|| {
        authenticate_registration_client(&st, &headers, &client_id)?;
        st.db.tx(|tx| {
            for statement in [
                "DELETE FROM access_tokens WHERE client_id = ?1",
                "DELETE FROM refresh_tokens WHERE client_id = ?1",
                "DELETE FROM consents WHERE client_id = ?1",
                "DELETE FROM device_codes WHERE client_id = ?1",
                "DELETE FROM flows WHERE client_id = ?1",
            ] {
                tx.execute(statement, params![client_id])?;
            }
            tx.execute("DELETE FROM clients WHERE id = ?1", params![client_id])?;
            Ok(())
        })?;
        Ok(StatusCode::NO_CONTENT.into_response())
    })();
    match result {
        Ok(res) => res,
        Err(error) => error.into_response(),
    }
}

pub async fn register_client(
    State(st): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> Response {
    match register_client_inner(&st, &headers, &body) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

/// A registered JWK Set must contain public signing keys only. Accepting a
/// private or symmetric key would turn the client's key material into an OP
/// secret and could allow key confusion.
fn validate_jwks(value: &Value) -> Result<(), &'static str> {
    let keys = value
        .get("keys")
        .and_then(Value::as_array)
        .ok_or("jwks must be a JWK Set with a keys array")?;
    if keys.is_empty() || keys.len() > 8 {
        return Err("jwks must contain between 1 and 8 keys");
    }
    for key in keys {
        if ["d", "p", "q", "dp", "dq", "qi", "k"]
            .iter()
            .any(|field| key.get(field).is_some())
        {
            return Err("jwks must contain public keys only");
        }
        if !matches!(
            key.get("kty").and_then(Value::as_str),
            Some("EC" | "RSA" | "OKP")
        ) {
            return Err("jwks contains an unsupported key type");
        }
    }
    Ok(())
}

fn register_client_inner(st: &AppState, headers: &HeaderMap, body: &Value) -> ApiResult<Response> {
    if let Some(expected) = &st.cfg.registration_token {
        let provided = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default();
        if !ct_eq(provided.trim(), expected) {
            return Err(OauthError::unauthorized(
                "an initial access token is required to register a client",
            ));
        }
    }

    let redirect_uris: Vec<String> = body
        .get("redirect_uris")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if redirect_uris.is_empty() {
        return Err(OauthError::invalid_request("redirect_uris is required"));
    }
    for uri in &redirect_uris {
        if let Err(reason) = validate_redirect_uri(uri) {
            return Err(OauthError::invalid_request(format!(
                "redirect_uri {uri} is invalid: {reason}"
            )));
        }
    }

    if body.get("jwks_uri").is_some() {
        return Err(OauthError::invalid_request(
            "jwks_uri is not supported; supply jwks inline",
        ));
    }
    if let Some(jwks) = body.get("jwks") {
        validate_jwks(jwks)
            .map_err(|reason| OauthError::invalid_request(format!("invalid jwks: {reason}")))?;
    }

    let auth_method = body
        .get("token_endpoint_auth_method")
        .and_then(Value::as_str)
        .unwrap_or("client_secret_basic")
        .to_string();
    if !matches!(
        auth_method.as_str(),
        "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt"
    ) {
        return Err(OauthError::invalid_request(
            "unsupported token_endpoint_auth_method",
        ));
    }
    if auth_method == "private_key_jwt" && body.get("jwks").is_none() {
        return Err(OauthError::invalid_request(
            "private_key_jwt requires an inline jwks",
        ));
    }

    let grant_types: Vec<String> = body
        .get("grant_types")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["authorization_code".into(), "refresh_token".into()]);
    let response_types: Vec<String> = body
        .get("response_types")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_else(|| vec!["code".into()]);
    if response_types.iter().any(|r| r != "code") {
        return Err(OauthError::invalid_request(
            "only response_type=code is supported",
        ));
    }
    if grant_types.iter().any(|g| {
        !matches!(
            g.as_str(),
            "authorization_code"
                | "refresh_token"
                | "client_credentials"
                | "urn:ietf:params:oauth:grant-type:device_code"
        )
    }) {
        return Err(OauthError::invalid_request("unsupported grant type"));
    }

    let scopes: Vec<String> = body
        .get("scope")
        .and_then(Value::as_str)
        .map(oidc::split_scope)
        .unwrap_or_else(|| vec!["openid".into(), "profile".into(), "email".into()]);
    validate_registerable_scopes(&scopes)?;

    let client_id = format!("kagi_{}", random_token(12));
    let secret = if auth_method.starts_with("client_secret") {
        Some(random_token(32))
    } else {
        None
    };
    let secret_hash = secret.as_deref().map(sha256_hex);
    // RFC 7592 registration access token. Only its hash is persisted; the
    // plaintext is shown exactly once in the creation response.
    let registration_token = random_token(32);
    let registration_token_hash = sha256_hex(&registration_token);
    let name = body
        .get("client_name")
        .and_then(Value::as_str)
        .unwrap_or("dynamic client")
        .trim()
        .to_string();
    if name.is_empty() || name.chars().count() > 120 || name.chars().any(char::is_control) {
        return Err(OauthError::invalid_request(
            "client_name must be 1–120 printable characters",
        ));
    }

    let post_logout: Vec<String> = body
        .get("post_logout_redirect_uris")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    for uri in &post_logout {
        if let Err(reason) = validate_redirect_uri(uri) {
            return Err(OauthError::invalid_request(format!(
                "post_logout_redirect_uri {uri} is invalid: {reason}"
            )));
        }
    }
    let backchannel_logout_uri = parse_optional_uri(
        body.get("backchannel_logout_uri"),
        "backchannel_logout_uri",
    )?;

    st.db.with(|c| {
        c.execute(
            "INSERT INTO clients
                (id, name, secret_hash, redirect_uris, post_logout_redirect_uris, grant_types,
                 scopes, auth_method, jwks, require_dpop, require_par, id_token_alg,
                 registration_token_hash, backchannel_logout_uri,
                 backchannel_logout_session_required, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'ES256', ?12, ?13, ?14, ?15)",
            params![
                client_id,
                name,
                secret_hash,
                serde_json::to_string(&redirect_uris).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&post_logout).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&grant_types).unwrap_or_else(|_| "[]".into()),
                serde_json::to_string(&scopes).unwrap_or_else(|_| "[]".into()),
                auth_method,
                body.get("jwks").map(|j| j.to_string()),
                body.get("require_dpop")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) as i64,
                body.get("require_pushed_authorization_requests")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) as i64,
                registration_token_hash,
                backchannel_logout_uri.clone(),
                body.get("backchannel_logout_session_required")
                    .and_then(Value::as_bool)
                    .unwrap_or(false) as i64,
                now(),
            ],
        )?;
        Ok(())
    })?;

    let mut response = json!({
        "client_id": client_id,
        "client_id_issued_at": now(),
        "client_name": name,
        "redirect_uris": redirect_uris,
        "post_logout_redirect_uris": post_logout,
        "grant_types": grant_types,
        "response_types": ["code"],
        "token_endpoint_auth_method": auth_method,
        "scope": scopes.join(" "),
        "require_pushed_authorization_requests": body
            .get("require_pushed_authorization_requests")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        "registration_access_token": registration_token,
        "registration_client_uri": st
            .cfg
            .endpoint(&format!("/register/{client_id}")),
    });
    if let Some(uri) = &backchannel_logout_uri {
        response["backchannel_logout_uri"] = json!(uri);
    }
    if body
        .get("backchannel_logout_session_required")
        .and_then(Value::as_bool)
        .unwrap_or(false)
    {
        response["backchannel_logout_session_required"] = json!(true);
    }
    if let Some(secret) = secret {
        response["client_secret"] = json!(secret);
        response["client_secret_expires_at"] = json!(0);
    }

    let mut res = (StatusCode::CREATED, Json(response)).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

// ---------------------------------------------------------------------------
// Key rotation
// ---------------------------------------------------------------------------

pub async fn rotate_keys(State(st): State<AppState>, headers: HeaderMap) -> Response {
    let Some(expected) = &st.cfg.admin_token else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    if !ct_eq(provided.trim(), expected) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let mut ring = st.keys.write().unwrap_or_else(|e| e.into_inner());
    match ring.rotate(&st.db) {
        Ok(kid) => Json(json!({ "kid": kid, "keys": ring.key_ids() })).into_response(),
        Err(error) => {
            // Key-store errors can contain SQL or connection details.
            eprintln!("[kagi] key rotation failed: {error:#}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "key_rotation_failed" })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Admin statistics
// ---------------------------------------------------------------------------

fn admin_authorised(st: &AppState, headers: &HeaderMap) -> Option<bool> {
    let Some(expected) = &st.cfg.admin_token else {
        return None;
    };
    let provided = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .unwrap_or_default();
    Some(ct_eq(provided.trim(), expected))
}

pub async fn admin_stats(State(st): State<AppState>, headers: HeaderMap) -> Response {
    match admin_authorised(&st, &headers) {
        // Hide the endpoint entirely when no admin token is configured.
        None => return StatusCode::NOT_FOUND.into_response(),
        Some(false) => return StatusCode::UNAUTHORIZED.into_response(),
        Some(true) => {}
    }

    match st.db.with(db::stats) {
        Ok(stats) => {
            let mut res = Json(json!({
                "issuer": st.cfg.issuer,
                "database": st.db.backend(),
                "generated_at": now(),
                "stats": stats,
            }))
            .into_response();
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
            res
        }
        Err(error) => {
            // Keep database details out of the response body; operators get
            // them from the server log.
            eprintln!("[kagi] admin stats query failed: {error}");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "stats_unavailable" })),
            )
                .into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// Health
// ---------------------------------------------------------------------------

/// Liveness + database readiness probe. Returns `503` when the database cannot
/// answer a trivial query, which makes it safe to use as a Kubernetes /
/// load-balancer ready check.
pub async fn health(State(st): State<AppState>) -> Response {
    let db_ok = st
        .db
        .with(|c| {
            let value: i64 = c.query_row("SELECT 1", params![], |r| r.get(0))?;
            // Touch the tables created by the runtime migrations so that a
            // half-applied schema is reported as unavailable, not "ok".
            let _: i64 =
                c.query_row("SELECT COUNT(*) FROM rate_limits", params![], |r| r.get(0))?;
            let _: i64 =
                c.query_row("SELECT COUNT(*) FROM signing_keys", params![], |r| r.get(0))?;
            Ok(value == 1)
        })
        .unwrap_or(false);

    let status = if db_ok {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    let mut res = (
        status,
        Json(json!({
            "status": if db_ok { "ok" } else { "unavailable" },
            "database": st.db.backend(),
            "database_ready": db_ok,
            "issuer": st.cfg.issuer,
        })),
    )
        .into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}
