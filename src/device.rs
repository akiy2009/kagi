//! RFC 8628 OAuth 2.0 Device Authorization Grant.
//!
//! The device receives an opaque `device_code` and a short, human-enterable
//! `user_code`. Only SHA-256 hashes of both are stored. A browser session
//! approves the grant out of band, and the device polls the token endpoint.

use crate::db::{self, params, Client};
use crate::error::{ApiResult, OauthError};
use crate::util::*;
use crate::AppState;
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use serde_json::{json, Value};
use std::collections::HashMap;

pub const DEVICE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

const USER_CODE_ALPHABET: &[u8; 32] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

/// A user code is 8 characters from a 32-symbol alphabet (40 bits), displayed
/// as `ABCD-EFGH`. It is only useful together with aggressive rate limiting.
fn generate_user_code() -> String {
    let bytes = random_bytes(8);
    let mut out = String::with_capacity(9);
    for (index, byte) in bytes.iter().enumerate() {
        if index == 4 {
            out.push('-');
        }
        out.push(USER_CODE_ALPHABET[(*byte as usize) & 31] as char);
    }
    out
}

pub fn normalize_user_code(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

fn user_code_hash(raw: &str) -> String {
    sha256_hex(&normalize_user_code(raw))
}

fn device_error(code: &'static str, description: impl Into<String>) -> OauthError {
    OauthError::new(StatusCode::BAD_REQUEST, code, description)
}

fn json_no_store(body: Value, status: StatusCode) -> Response {
    let mut res = (status, Json(body)).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

// ---------------------------------------------------------------------------
// Device authorization endpoint
// ---------------------------------------------------------------------------

pub async fn authorization(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match authorization_inner(&st, &headers, &form) {
        Ok(res) => res,
        Err(error) => error.into_response(),
    }
}

fn authorization_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = crate::oidc::authenticate_client(st, headers, form)?;
    if !client.grant_types.iter().any(|grant| grant == DEVICE_GRANT) {
        return Err(OauthError::unauthorized(
            "this client is not registered for the device authorization grant",
        ));
    }

    let scope = match form.get("scope").map(|value| value.trim()) {
        Some(value) if !value.is_empty() => value.to_string(),
        _ => "openid".to_string(),
    };
    if !crate::oidc::scope_contains(&scope, "openid") {
        return Err(OauthError::invalid_scope("openid scope is required"));
    }
    if !crate::oidc::scope_subset(&scope, &client.scopes.join(" ")) {
        return Err(OauthError::invalid_scope(
            "scope exceeds the client registration",
        ));
    }

    let device_code = random_token(32);
    let device_hash = sha256_hex(&device_code);
    let user_code = generate_user_code();
    let code_hash = user_code_hash(&user_code);
    let expires_at = now() + st.cfg.device_ttl;

    st.db.with(|c| {
        c.execute(
            "INSERT INTO device_codes
                (device_hash, user_code_hash, client_id, scope, user_id, auth_time, amr, acr,
                 status, interval_secs, last_polled_at, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, NULL, NULL, '[]', NULL, 'pending', ?5, 0, ?6, ?7)",
            params![
                device_hash,
                code_hash,
                client.id,
                scope,
                st.cfg.device_interval,
                expires_at,
                now(),
            ],
        )?;
        Ok(())
    })?;

    let verification_uri = st.cfg.endpoint("/device");
    let complete = build_url(&verification_uri, &[("user_code", user_code.clone())]);
    Ok(json_no_store(
        json!({
            "device_code": device_code,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "verification_uri_complete": complete,
            "expires_in": st.cfg.device_ttl,
            "interval": st.cfg.device_interval,
        }),
        StatusCode::OK,
    ))
}

// ---------------------------------------------------------------------------
// Browser verification
// ---------------------------------------------------------------------------

pub async fn verification_page(
    State(st): State<AppState>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    let prefill = query.get("user_code").cloned().unwrap_or_default();
    let Some(session) = crate::auth::session_from_headers(&st, &headers) else {
        let next = format!("/device?user_code={}", urlenc(&prefill));
        return crate::oidc::redirect_302(&format!("/login?next={}", urlenc(&next)));
    };
    let user = match st.db.with(|c| db::load_user(c, &session.user_id)) {
        Ok(Some(user)) => user,
        _ => return crate::oidc::redirect_302("/login"),
    };
    let csrf = random_token(18);
    let flow = match crate::auth::insert_flow(
        &st,
        "device",
        Some(&session.user_id),
        None,
        &json!({}),
        Some(&csrf),
        600,
    ) {
        Ok(flow) => flow,
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Html(crate::ui::error_page(
                    "500",
                    "承認画面を初期化できませんでした",
                )),
            )
                .into_response()
        }
    };
    Html(crate::ui::device_page(
        &flow.id,
        &csrf,
        &prefill,
        &user.username,
    ))
    .into_response()
}

pub async fn verification_submit(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let Some(session) = crate::auth::session_from_headers(&st, &headers) else {
        return crate::oidc::redirect_302("/login?next=%2Fdevice");
    };
    let Some(rid) = form.get("rid") else {
        return bad_request("承認リクエストがありません");
    };
    let flow = match st.db.with(|c| db::load_flow(c, rid)) {
        Ok(Some(flow)) if flow.kind == "device" => flow,
        _ => return bad_request("この承認リクエストは期限切れです"),
    };
    let csrf_ok = match (&flow.csrf, form.get("csrf")) {
        (Some(expected), Some(provided)) => ct_eq(expected, provided),
        _ => false,
    };
    if !csrf_ok {
        return bad_request("CSRF トークンが一致しません");
    }
    let decision = form.get("decision").map(String::as_str).unwrap_or("deny");
    if !matches!(decision, "allow" | "deny") {
        return bad_request("不正な操作です");
    }

    let raw_code = form.get("user_code").map(String::as_str).unwrap_or("");
    if normalize_user_code(raw_code).len() != 8 {
        return bad_request(
            "デバイスコードは 8 文字です。画面に表示されたコードを入力してください。",
        );
    }
    let hash = user_code_hash(raw_code);
    let grant = match st.db.with(|c| db::load_device_by_user_code(c, &hash)) {
        Ok(Some(grant)) if grant.status == "pending" => grant,
        _ => {
            return bad_request("コードが正しくないか、有効期限が切れています。");
        }
    };
    let client = match st.db.with(|c| db::load_client(c, &grant.client_id)) {
        Ok(Some(client)) => client,
        _ => return bad_request("クライアントが見つかりません"),
    };

    let consumed = st.db.with(|c| {
        Ok(c.execute(
            "UPDATE flows SET consumed = 1 WHERE id = ?1 AND kind = 'device' AND consumed = 0",
            params![rid],
        )?)
    });
    if !matches!(consumed, Ok(1)) {
        return bad_request("この承認リクエストは既に使用済みです");
    }

    if decision == "deny" {
        let _ = st.db.with(|c| {
            Ok(c.execute(
                "UPDATE device_codes SET status = 'denied'
                 WHERE device_hash = ?1 AND status = 'pending' AND expires_at > ?2",
                params![grant.device_hash, now()],
            )?)
        });
        crate::auth::audit(
            &st,
            Some(&session.user_id),
            "device.deny",
            &format!("デバイス {} の接続を拒否", client.id),
            &headers,
        );
        return Html(crate::ui::device_result_page(
            "接続を拒否しました",
            "デバイスはアクセスできません。心当たりがある場合は、もう一度コードを発行してください。",
        ))
        .into_response();
    }

    let amr = serde_json::to_string(&session.amr).unwrap_or_else(|_| "[]".to_string());
    let approved = st.db.with(|c| {
        Ok(c.execute(
            "UPDATE device_codes SET status = 'approved', user_id = ?1, auth_time = ?2,
                 amr = ?3, acr = ?4
             WHERE device_hash = ?5 AND status = 'pending' AND expires_at > ?6",
            params![
                session.user_id,
                session.auth_time,
                amr,
                session.acr,
                grant.device_hash,
                now(),
            ],
        )?)
    });
    if !matches!(approved, Ok(1)) {
        return bad_request("このコードは既に使用されたか、有効期限が切れています。");
    }
    crate::auth::audit(
        &st,
        Some(&session.user_id),
        "device.approve",
        &format!("デバイス {} の接続を許可", client.id),
        &headers,
    );
    Html(crate::ui::device_result_page(
        "接続を許可しました",
        "デバイスへのサインインが完了します。この画面を閉じて構いません。",
    ))
    .into_response()
}

fn bad_request(message: &str) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Html(crate::ui::error_page("400", message)),
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// Token exchange
// ---------------------------------------------------------------------------

pub fn exchange(
    st: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> ApiResult<Response> {
    let device_code = form
        .get("device_code")
        .ok_or_else(|| OauthError::invalid_request("device_code is required"))?;
    if device_code.len() > 512 {
        return Err(device_error("invalid_grant", "invalid device_code"));
    }
    let hash = sha256_hex(device_code);
    let grant = st
        .db
        .with(|c| db::load_device(c, &hash))?
        .ok_or_else(|| device_error("invalid_grant", "unknown device_code"))?;

    if grant.client_id != client.id {
        return Err(device_error(
            "invalid_grant",
            "device_code was issued to another client",
        ));
    }
    if grant.expires_at < now() {
        return Err(device_error("expired_token", "the device_code has expired"));
    }

    match grant.status.as_str() {
        "pending" => {
            let interval = grant.interval_secs.max(1);
            if grant.last_polled_at > 0 && now().saturating_sub(grant.last_polled_at) < interval {
                // RFC 8628 §3.5: back off and increase the interval by 5 s.
                st.db.with(|c| {
                    Ok(c.execute(
                        "UPDATE device_codes SET interval_secs = interval_secs + 5, last_polled_at = ?1
                         WHERE device_hash = ?2",
                        params![now(), grant.device_hash],
                    )?)
                })?;
                return Err(device_error(
                    "slow_down",
                    "polling too quickly; increase the interval by 5 seconds",
                ));
            }
            st.db.with(|c| {
                Ok(c.execute(
                    "UPDATE device_codes SET last_polled_at = ?1 WHERE device_hash = ?2",
                    params![now(), grant.device_hash],
                )?)
            })?;
            Err(device_error(
                "authorization_pending",
                "the user has not approved the request yet",
            ))
        }
        "denied" => Err(device_error(
            "access_denied",
            "the user denied the device authorization request",
        )),
        "approved" => {
            let changed = st.db.with(|c| {
                Ok(c.execute(
                    "UPDATE device_codes SET status = 'consumed'
                     WHERE device_hash = ?1 AND status = 'approved' AND expires_at > ?2",
                    params![grant.device_hash, now()],
                )?)
            })?;
            if changed != 1 {
                return Err(device_error(
                    "expired_token",
                    "the device_code was already used or has expired",
                ));
            }
            let user_id = grant
                .user_id
                .as_deref()
                .ok_or_else(|| device_error("expired_token", "the grant has no user"))?;
            let user = st
                .db
                .with(|c| db::load_user(c, user_id))?
                .ok_or_else(|| device_error("expired_token", "the user no longer exists"))?;
            let auth_time = grant.auth_time.unwrap_or_else(now);
            let acr = grant.acr.as_deref().unwrap_or(crate::auth::ACR_PASSKEY);

            let (access_token, expires_in) = crate::oidc::mint_access_token(
                st,
                &user.id,
                &client.id,
                &grant.scope,
                jkt,
                None,
                None,
            )?;
            let id_token = if crate::oidc::scope_contains(&grant.scope, "openid") {
                Some(crate::oidc::mint_id_token(
                    st,
                    &user,
                    &client.id,
                    &grant.scope,
                    None,
                    auth_time,
                    &grant.amr,
                    acr,
                    &access_token,
                    None,
                    jkt,
                    None,
                )?)
            } else {
                None
            };
            let refresh_token = if crate::oidc::scope_contains(&grant.scope, "offline_access") {
                Some(crate::oidc::mint_refresh_token(
                    st,
                    &user.id,
                    &client.id,
                    &grant.scope,
                    auth_time,
                    &grant.amr,
                    acr,
                    jkt,
                    None,
                    None,
                    None,
                )?)
            } else {
                None
            };
            Ok(crate::oidc::token_response(
                access_token,
                expires_in,
                &grant.scope,
                refresh_token,
                id_token,
                jkt.is_some(),
            ))
        }
        _ => Err(device_error(
            "expired_token",
            "the device_code is no longer usable",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{generate_user_code, normalize_user_code, user_code_hash};

    #[test]
    fn user_codes_normalize_to_eight_alphanumerics() {
        assert_eq!(normalize_user_code("abcd-efgh"), "ABCDEFGH");
        assert_eq!(normalize_user_code(" ABCD EFGH "), "ABCDEFGH");
        assert_eq!(normalize_user_code("a1b2-c3d4"), "A1B2C3D4");
    }

    #[test]
    fn equivalent_user_codes_hash_the_same() {
        assert_eq!(user_code_hash("abcd-efgh"), user_code_hash("ABCD EFGH"));
        assert_ne!(user_code_hash("abcd-efgh"), user_code_hash("abcd-efgi"));
    }

    #[test]
    fn generated_codes_are_displayable_and_unambiguous() {
        for _ in 0..64 {
            let code = generate_user_code();
            assert_eq!(code.len(), 9, "{code}");
            assert_eq!(code.as_bytes()[4], b'-');
            assert!(normalize_user_code(&code).len() == 8);
            assert!(!code.contains('0') && !code.contains('O') && !code.contains('I'));
        }
    }
}
