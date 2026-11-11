//! OIDC / OAuth 2.1 core: discovery, PAR, authorize, token issuance.

use crate::db::params;
use crate::db::{self, Client, Flow, Session, User};
use crate::dpop;
use crate::error::{ApiResult, OauthError};
use crate::jose;
use crate::util::*;
use crate::AppState;
use axum::extract::{Form, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Authorization request parameters
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AuthzParams {
    #[serde(default)]
    pub client_id: String,
    #[serde(default)]
    pub redirect_uri: String,
    #[serde(default)]
    pub response_type: String,
    #[serde(default)]
    pub response_mode: Option<String>,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub state: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
    #[serde(default)]
    pub code_challenge: String,
    #[serde(default)]
    pub code_challenge_method: Option<String>,
    #[serde(default)]
    pub prompt: Option<String>,
    #[serde(default)]
    pub max_age: Option<i64>,
    #[serde(default)]
    pub login_hint: Option<String>,
    #[serde(default)]
    pub acr_values: Option<String>,
    #[serde(default)]
    pub claims: Option<String>,
    #[serde(default)]
    pub dpop_jkt: Option<String>,
    #[serde(default)]
    pub resource: Option<String>,
}

impl AuthzParams {
    pub fn from_map(m: &HashMap<String, String>) -> Self {
        let get = |k: &str| m.get(k).cloned().filter(|v| !v.is_empty());
        Self {
            client_id: get("client_id").unwrap_or_default(),
            redirect_uri: get("redirect_uri").unwrap_or_default(),
            response_type: get("response_type").unwrap_or_default(),
            response_mode: get("response_mode"),
            scope: get("scope").unwrap_or_default(),
            state: get("state"),
            nonce: get("nonce"),
            code_challenge: get("code_challenge").unwrap_or_default(),
            code_challenge_method: get("code_challenge_method"),
            prompt: get("prompt"),
            max_age: get("max_age").and_then(|v| v.parse().ok()),
            login_hint: get("login_hint"),
            acr_values: get("acr_values"),
            claims: get("claims"),
            dpop_jkt: get("dpop_jkt"),
            resource: get("resource"),
        }
    }

    pub fn prompt_set(&self) -> Vec<&str> {
        self.prompt
            .as_deref()
            .map(|p| p.split(' ').filter(|s| !s.is_empty()).collect())
            .unwrap_or_default()
    }

    pub fn wants(&self, value: &str) -> bool {
        self.prompt_set().contains(&value)
    }

    pub fn response_mode(&self) -> &str {
        self.response_mode.as_deref().unwrap_or("query")
    }
}

pub fn split_scope(scope: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for s in scope.split_whitespace() {
        if !out.iter().any(|x| x == s) {
            out.push(s.to_string());
        }
    }
    out
}

pub fn scope_contains(scope: &str, name: &str) -> bool {
    split_scope(scope).iter().any(|s| s == name)
}

// ---------------------------------------------------------------------------
// OIDC `claims` request parameter
// ---------------------------------------------------------------------------

/// Claims kagi can release in an ID Token or at UserInfo. Keeping this list
/// closed prevents a client from probing for internal attributes by name.
const SUPPORTED_CLAIMS: [&str; 10] = [
    "sub",
    "auth_time",
    "acr",
    "amr",
    "sid",
    "name",
    "preferred_username",
    "email",
    "email_verified",
    "iss",
];

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimsRequest {
    #[serde(default)]
    pub id_token: std::collections::BTreeMap<String, Option<ClaimSpec>>,
    #[serde(default)]
    pub userinfo: std::collections::BTreeMap<String, Option<ClaimSpec>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimSpec {
    #[serde(default)]
    pub essential: bool,
    #[serde(default)]
    pub value: Option<Value>,
    #[serde(default)]
    pub values: Option<Vec<Value>>,
}

impl ClaimsRequest {
    fn targets(&self) -> impl Iterator<Item = &std::collections::BTreeMap<String, Option<ClaimSpec>>> {
        [&self.id_token, &self.userinfo].into_iter()
    }
}

fn parse_claims_request(raw: &str) -> ApiResult<ClaimsRequest> {
    if raw.len() > 4096 {
        return Err(OauthError::invalid_request(
            "claims parameter is too large (maximum 4096 bytes)",
        ));
    }
    let request: ClaimsRequest = serde_json::from_str(raw)
        .map_err(|_| OauthError::invalid_request("claims must be a valid JSON object"))?;
    for target in request.targets() {
        for (claim, spec) in target {
            if !SUPPORTED_CLAIMS.iter().any(|supported| supported == claim) {
                return Err(OauthError::invalid_request(format!(
                    "claim {claim} is not supported"
                )));
            }
            if let Some(spec) = spec {
                if (spec.value.is_some() || spec.values.is_some()) && claim != "acr" {
                    return Err(OauthError::invalid_request(
                        "value/values are only supported for the acr claim",
                    ));
                }
                if let Some(values) = &spec.values {
                    if values.is_empty() || values.len() > 8 {
                        return Err(OauthError::invalid_request(
                            "acr values must contain between 1 and 8 entries",
                        ));
                    }
                }
            }
        }
    }
    Ok(request)
}

/// Parse and validate the request parameter once, returning the canonical JSON
/// that is persisted with the authorization grant.
pub fn normalized_claims(p: &AuthzParams) -> ApiResult<Option<String>> {
    let Some(raw) = p.claims.as_deref() else {
        return Ok(None);
    };
    let request = parse_claims_request(raw)?;
    serde_json::to_string(&request)
        .map(Some)
        .map_err(|_| OauthError::server_error("could not serialise claims request"))
}

/// ACR values required by `claims.id_token.acr`, if the client constrained it.
fn claims_acr_values_from_spec(spec: &ClaimSpec) -> Vec<String> {
    let mut values = Vec::new();
    if let Some(value) = &spec.value {
        if let Some(value) = value.as_str() {
            values.push(value.to_string());
        }
    }
    if let Some(list) = &spec.values {
        for value in list {
            if let Some(value) = value.as_str() {
                values.push(value.to_string());
            }
        }
    }
    values
}

/// Check that every claim the client marked `essential` can actually be
/// released. Shown as an authorization error rather than silently omitting a
/// claim the RP said it cannot work without.
fn essential_claims_satisfied(
    p: &AuthzParams,
    client: &Client,
    user: &User,
    session: &Session,
) -> Result<(), String> {
    let Some(raw) = normalized_claims(p).map_err(|e| e.description)? else {
        return Ok(());
    };
    let request: ClaimsRequest = serde_json::from_str(&raw).map_err(|_| "invalid claims".to_string())?;
    let has_profile = client.scopes.iter().any(|s| s == "profile")
        && p.scope.split_whitespace().any(|s| s == "profile");
    let has_email = client.scopes.iter().any(|s| s == "email")
        && p.scope.split_whitespace().any(|s| s == "email");
    for target in request.targets() {
        for (claim, spec) in target {
            let essential = spec.as_ref().is_some_and(|s| s.essential);
            if !essential {
                continue;
            }
            let available = match claim.as_str() {
                "sub" | "auth_time" | "amr" | "sid" | "iss" => true,
                "acr" => {
                    let required = spec
                        .as_ref()
                        .map(claims_acr_values_from_spec)
                        .unwrap_or_default();
                    required.is_empty() || required.iter().any(|value| value == &session.acr)
                }
                "name" | "preferred_username" => has_profile,
                "email" | "email_verified" => has_email && user.email.is_some(),
                _ => false,
            };
            if !available {
                return Err(format!("essential claim {claim} cannot be provided"));
            }
        }
    }
    Ok(())
}

pub(crate) fn scope_subset(requested: &str, allowed: &str) -> bool {
    let allowed = split_scope(allowed);
    split_scope(requested)
        .iter()
        .all(|s| allowed.iter().any(|a| a == s))
}

const SUPPORTED_ACRS: [&str; 2] = [crate::auth::ACR_PASSKEY, crate::auth::ACR_RECOVERY];

fn requested_acrs(p: &AuthzParams) -> Vec<&str> {
    p.acr_values
        .as_deref()
        .map(|value| {
            value
                .split_whitespace()
                .filter(|v| !v.is_empty())
                .collect()
        })
        .unwrap_or_default()
}

/// Requested ACR values that kagi can satisfy. Unknown values are ignored: RPs
/// commonly send a preference list, but a supported value becomes a hard
/// requirement so we never claim an authentication level we did not perform.
fn required_acrs(p: &AuthzParams) -> Vec<&'static str> {
    let requested = requested_acrs(p);
    SUPPORTED_ACRS
        .iter()
        .copied()
        .filter(|supported| requested.iter().any(|value| value == supported))
        .collect()
}

fn acr_satisfied(p: &AuthzParams, session: &Session) -> bool {
    let required = required_acrs(p);
    let list_ok = required.is_empty() || required.iter().any(|acr| *acr == session.acr);
    if !list_ok {
        return false;
    }
    // A `claims.id_token.acr` constraint is just as binding as acr_values.
    let Ok(raw) = normalized_claims(p) else {
        return false;
    };
    let Some(raw) = raw else {
        return true;
    };
    let Ok(request) = serde_json::from_str::<ClaimsRequest>(&raw) else {
        return false;
    };
    let claims_required = request
        .id_token
        .get("acr")
        .and_then(Option::as_ref)
        .map(claims_acr_values_from_spec)
        .unwrap_or_default();
    claims_required.is_empty() || claims_required.iter().any(|acr| acr == &session.acr)
}

// ---------------------------------------------------------------------------
// Static endpoints
// ---------------------------------------------------------------------------

pub async fn discovery(State(st): State<AppState>) -> Response {
    let cfg = &st.cfg;
    let doc = json!({
        "issuer": cfg.issuer,
        "authorization_endpoint": cfg.endpoint("/authorize"),
        "token_endpoint": cfg.endpoint("/token"),
        "userinfo_endpoint": cfg.endpoint("/userinfo"),
        "jwks_uri": cfg.endpoint("/jwks.json"),
        "registration_endpoint": cfg.endpoint("/register"),
        "pushed_authorization_request_endpoint": cfg.endpoint("/par"),
        "device_authorization_endpoint": cfg.endpoint("/device_authorization"),
        "introspection_endpoint": cfg.endpoint("/introspect"),
        "revocation_endpoint": cfg.endpoint("/revoke"),
        "end_session_endpoint": cfg.endpoint("/logout"),
        "scopes_supported": ["openid", "profile", "email", "offline_access"],
        "response_types_supported": ["code"],
        "response_modes_supported": ["query", "fragment", "jwt", "query.jwt", "fragment.jwt", "form_post"],
        "grant_types_supported": [
            "authorization_code", "refresh_token", "client_credentials",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "userinfo_signing_alg_values_supported": ["none"],
        "token_endpoint_auth_methods_supported": [
            "none", "client_secret_basic", "client_secret_post", "private_key_jwt"
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "EdDSA", "RS256", "PS256"],
        "revocation_endpoint_auth_methods_supported": [
            "none", "client_secret_basic", "client_secret_post", "private_key_jwt"
        ],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "private_key_jwt"
        ],
        "claims_supported": [
            "sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "azp", "sid",
            "name", "preferred_username", "email", "email_verified"
        ],
        "claims_parameter_supported": true,
        "acr_values_supported": [crate::auth::ACR_PASSKEY, crate::auth::ACR_RECOVERY],
        "code_challenge_methods_supported": ["S256"],
        "request_parameter_supported": true,
        "request_uri_parameter_supported": true,
        "require_request_uri_registration": false,
        "authorization_response_iss_parameter_supported": true,
        "request_object_signing_alg_values_supported": ["ES256", "EdDSA", "RS256", "PS256"],
        "authorization_signing_alg_values_supported": ["ES256"],
        "authorization_encryption_alg_values_supported": [],
        "dpop_signing_alg_values_supported": ["ES256", "EdDSA", "RS256", "PS256"],
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "require_pushed_authorization_requests": cfg.require_par,
        "tls_client_certificate_bound_access_tokens": false,
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
        "frontchannel_logout_supported": false,
    });
    ([(header::CACHE_CONTROL, "public, max-age=300")], Json(doc)).into_response()
}

pub async fn jwks(State(st): State<AppState>) -> Response {
    let jwks = st.keys.read().unwrap_or_else(|e| e.into_inner()).jwks();
    ([(header::CACHE_CONTROL, "public, max-age=300")], Json(jwks)).into_response()
}

// ---------------------------------------------------------------------------
// PAR (RFC 9126)
// ---------------------------------------------------------------------------

pub async fn par(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match par_inner(&st, &headers, &form) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn par_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = authenticate_client(st, headers, form)?;
    let mut params = AuthzParams::from_map(form);
    params.client_id = client.id.clone();

    validate_authorization_params(st, &params)?;

    if params.code_challenge.is_empty() {
        return Err(OauthError::invalid_request("PKCE is required"));
    }

    // DPoP at the PAR endpoint binds the whole authorization request to a key.
    if let Some(proof) = dpop::inspect(st.cfg.as_ref(), &st.db, headers, "POST", "/par", None)? {
        params.dpop_jkt = Some(proof.jkt);
    }
    if (st.cfg.require_dpop || client.require_dpop) && params.dpop_jkt.is_none() {
        return Err(OauthError::invalid_dpop_proof("DPoP proof required"));
    }

    let id = random_token(24);
    let payload = serde_json::to_string(&params)
        .map_err(|_| OauthError::server_error("could not serialise request"))?;
    let expires_at = now() + st.cfg.par_ttl;
    st.db.with(|c| {
        c.execute(
            "INSERT INTO flows (id, kind, user_id, client_id, payload, challenge, csrf, expires_at, created_at, consumed)
             VALUES (?1, 'par', NULL, ?2, ?3, NULL, NULL, ?4, ?5, 0)",
            params![id, client.id, payload, expires_at, now()],
        )?;
        Ok(())
    })?;

    let body = json!({
        "request_uri": format!("urn:ietf:params:oauth:request_uri:{id}"),
        "expires_in": st.cfg.par_ttl,
    });
    let mut res = (StatusCode::CREATED, Json(body)).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(res)
}

// ---------------------------------------------------------------------------
// Authorization endpoint
// ---------------------------------------------------------------------------

pub async fn authorize(
    State(st): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    authorize_inner(&st, &headers, query)
}

fn authorize_inner(st: &AppState, headers: &HeaderMap, query: HashMap<String, String>) -> Response {
    let (params, via_par) = match resolve_authorization_request(st, &query) {
        Ok(v) => v,
        Err(e) => return authz_fail(st, None, e.code, &e.description),
    };

    let client = match validate_authorization_params(st, &params) {
        Ok(c) => c,
        Err(e) => return authz_fail(st, Some(&params), e.code, &e.description),
    };

    if !via_par && (st.cfg.require_par || client.require_par) {
        return authz_fail(
            st,
            Some(&params),
            "invalid_request",
            "pushed authorization requests are required for this client",
        );
    }

    let session = crate::auth::session_from_headers(st, headers);
    let prompt = params.prompt_set();

    let max_age_exceeded = match (&session, params.max_age) {
        (Some(s), Some(max)) => s.auth_time + max < now(),
        _ => false,
    };
    let acr_missing = match &session {
        Some(s) => !acr_satisfied(&params, s),
        None => false,
    };
    let needs_login = session.is_none()
        || prompt.contains(&"login")
        || prompt.contains(&"select_account")
        || max_age_exceeded
        || acr_missing;

    if prompt.contains(&"none") {
        if needs_login {
            let (code, description) = if acr_missing {
                (
                    "unmet_authentication_requirements",
                    "no active session satisfies the requested acr",
                )
            } else {
                ("login_required", "no active session")
            };
            return authz_fail(st, Some(&params), code, description);
        }
        let s = session.unwrap();
        let user = match st.db.with(|c| db::load_user(c, &s.user_id)) {
            Ok(Some(u)) => u,
            _ => return authz_fail(st, Some(&params), "login_required", "unknown session user"),
        };
        let consented = st
            .db
            .with(|c| db::consent_covers(c, &user.id, &client.id, &params.scope))
            .unwrap_or(false);
        if !consented {
            return authz_fail(
                st,
                Some(&params),
                "consent_required",
                "the user has not consented to this client yet",
            );
        }
        let flow = match create_authorize_flow(st, &params) {
            Ok(f) => f,
            Err(e) => return authz_fail(st, Some(&params), "server_error", &e.description),
        };
        return complete_authorization(st, &flow, &user, &s, true);
    }

    let flow = match create_authorize_flow(st, &params) {
        Ok(f) => f,
        Err(e) => return authz_fail(st, Some(&params), "server_error", &e.description),
    };

    if needs_login {
        return redirect_303(&format!("/login?rid={}", urlenc(&flow.id)));
    }
    // A previously remembered consent makes the round trip unnecessary unless
    // the RP explicitly asks to re-prompt. This keeps authorization code flow
    // silent without weakening prompt=consent.
    if !prompt.contains(&"consent") {
        if let Some(s) = &session {
            if let Ok(Some(user)) = st.db.with(|c| db::load_user(c, &s.user_id)) {
                let consented = st
                    .db
                    .with(|c| db::consent_covers(c, &user.id, &client.id, &params.scope))
                    .unwrap_or(false);
                if consented {
                    return complete_authorization(st, &flow, &user, s, true);
                }
            }
        }
    }
    redirect_303(&format!("/consent?rid={}", urlenc(&flow.id)))
}

fn resolve_authorization_request(
    st: &AppState,
    query: &HashMap<String, String>,
) -> ApiResult<(AuthzParams, bool)> {
    let has_request = query.get("request").is_some();
    let has_request_uri = query.get("request_uri").is_some();
    if has_request && has_request_uri {
        return Err(OauthError::invalid_request(
            "request and request_uri are mutually exclusive",
        ));
    }

    if let Some(uri) = query.get("request_uri") {
        let Some(id) = uri.strip_prefix("urn:ietf:params:oauth:request_uri:") else {
            return Err(OauthError::invalid_request(
                "only urn:ietf:params:oauth:request_uri values are supported",
            ));
        };
        let flow = st
            .db
            .with(|c| db::load_flow(c, id))?
            .ok_or_else(|| OauthError::invalid_request("unknown or expired request_uri"))?;
        if flow.kind != "par" {
            return Err(OauthError::invalid_request(
                "request_uri is not a PAR handle",
            ));
        }
        // Single use.
        let used = st.db.with(|c| {
            Ok(c.execute(
                "UPDATE flows SET consumed = 1 WHERE id = ?1 AND consumed = 0",
                params![id],
            )?)
        })?;
        if used != 1 {
            return Err(OauthError::invalid_request("request_uri already used"));
        }
        let params: AuthzParams = serde_json::from_value(flow.payload)
            .map_err(|_| OauthError::invalid_request("stored request is corrupt"))?;
        return Ok((params, true));
    }

    if let Some(request) = query.get("request") {
        let params = resolve_request_object(st, query, request)?;
        return Ok((params, false));
    }

    Ok((AuthzParams::from_map(query), false))
}

fn resolve_request_object(
    st: &AppState,
    query: &HashMap<String, String>,
    request: &str,
) -> ApiResult<AuthzParams> {
    let client_id = query
        .get("client_id")
        .cloned()
        .ok_or_else(|| OauthError::invalid_request("client_id is required with request"))?;
    let client = st
        .db
        .with(|c| db::load_client(c, &client_id))?
        .ok_or_else(|| OauthError::invalid_request("unknown client"))?;
    let jwks = client
        .jwks
        .as_ref()
        .ok_or_else(|| OauthError::invalid_request("client has no registered jwks"))?;

    let (_header, claims) = jose::verify_with_jwks(jwks, request, Some("oauth-authz-req+jwt"))
        .map_err(|error| {
            eprintln!("[kagi] request object signature validation failed: {error:#}");
            OauthError::invalid_request("invalid request object")
        })?;

    if claims.get("iss").and_then(Value::as_str) != Some(client.id.as_str()) {
        return Err(OauthError::invalid_request(
            "request object iss must equal client_id",
        ));
    }
    // If client_id is repeated inside the signed request object, it must not
    // override the client whose key was used to verify the signature.
    if let Some(request_client_id) = claims.get("client_id").and_then(Value::as_str) {
        if request_client_id != client.id {
            return Err(OauthError::invalid_request(
                "request object client_id does not match the outer client_id",
            ));
        }
    }
    let aud_ok = match claims.get("aud") {
        Some(Value::String(s)) => s == &st.cfg.issuer,
        Some(Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(st.cfg.issuer.as_str())),
        _ => false,
    };
    if !aud_ok {
        return Err(OauthError::invalid_request(
            "request object aud must contain the issuer",
        ));
    }
    if let Some(exp) = claims.get("exp").and_then(Value::as_i64) {
        if exp < now() {
            return Err(OauthError::invalid_request("request object has expired"));
        }
    } else {
        return Err(OauthError::invalid_request("request object has no exp"));
    }
    if claims.get("request").is_some() || claims.get("request_uri").is_some() {
        return Err(OauthError::invalid_request(
            "request objects must not nest request or request_uri",
        ));
    }

    let mut map = HashMap::new();
    if let Some(obj) = claims.as_object() {
        for (k, v) in obj {
            match v {
                Value::String(s) => {
                    map.insert(k.clone(), s.clone());
                }
                Value::Number(n) => {
                    map.insert(k.clone(), n.to_string());
                }
                Value::Bool(b) => {
                    map.insert(k.clone(), b.to_string());
                }
                _ => {}
            }
        }
    }
    // Parameters outside the request object must not override it.
    map.entry("client_id".to_string())
        .or_insert(client.id.clone());
    Ok(AuthzParams::from_map(&map))
}

fn validate_authorization_params(st: &AppState, p: &AuthzParams) -> ApiResult<Client> {
    if p.client_id.is_empty() {
        return Err(OauthError::invalid_request("client_id is required"));
    }
    let client = st
        .db
        .with(|c| db::load_client(c, &p.client_id))?
        .ok_or_else(|| OauthError::invalid_request("unknown client_id"))?;

    if p.redirect_uri.is_empty() || !client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
        return Err(OauthError::invalid_request(
            "redirect_uri is not registered for this client",
        ));
    }
    if let Err(reason) = validate_redirect_uri(&p.redirect_uri) {
        return Err(OauthError::invalid_request(format!(
            "redirect_uri is not acceptable: {reason}"
        )));
    }
    if p.response_type != "code" {
        return Err(OauthError::invalid_request(
            "only response_type=code is supported",
        ));
    }
    let scopes = split_scope(&p.scope);
    if !scopes.iter().any(|s| s == "openid") {
        return Err(OauthError::invalid_scope("openid scope is required"));
    }
    if let Some(bad) = scopes
        .iter()
        .find(|s| !client.scopes.iter().any(|a| a == *s))
    {
        return Err(OauthError::invalid_scope(format!(
            "scope {bad} is not registered for this client"
        )));
    }
    if p.code_challenge.is_empty() {
        return Err(OauthError::invalid_request(
            "PKCE (code_challenge) is required",
        ));
    }
    if p.code_challenge.len() < 43 || p.code_challenge.len() > 128 {
        return Err(OauthError::invalid_request(
            "code_challenge has an invalid length",
        ));
    }
    if p.code_challenge_method.as_deref() != Some("S256") {
        return Err(OauthError::invalid_request(
            "code_challenge_method must be S256",
        ));
    }
    if !matches!(
        p.response_mode(),
        "query" | "fragment" | "form_post" | "jwt" | "query.jwt" | "fragment.jwt"
    ) {
        return Err(OauthError::invalid_request("unsupported response_mode"));
    }
    for value in p.prompt_set() {
        if !matches!(value, "none" | "login" | "consent" | "select_account") {
            return Err(OauthError::invalid_request(format!(
                "unsupported prompt value {value}"
            )));
        }
    }
    if p.wants("none") && p.prompt_set().len() > 1 {
        return Err(OauthError::invalid_request(
            "prompt=none cannot be combined with other values",
        ));
    }
    // The `claims` member is attacker-controlled JSON; validate it once here so
    // token issuance never has to handle a malformed request.
    normalized_claims(p)?;
    if p.acr_values.is_some() {
        let requested = requested_acrs(p);
        if requested.is_empty()
            || requested
                .iter()
                .all(|value| !SUPPORTED_ACRS.contains(value))
        {
            return Err(OauthError::invalid_request(
                "none of the requested acr_values are supported",
            ));
        }
    }
    if let Some(raw) = normalized_claims(p)? {
        if let Ok(request) = serde_json::from_str::<ClaimsRequest>(&raw) {
            let requested = request
                .id_token
                .get("acr")
                .and_then(Option::as_ref)
                .map(claims_acr_values_from_spec)
                .unwrap_or_default();
            if !requested.is_empty()
                && requested
                    .iter()
                    .all(|value| !SUPPORTED_ACRS.contains(&value.as_str()))
            {
                return Err(OauthError::invalid_request(
                    "the requested acr claim value is not supported",
                ));
            }
        }
    }
    if let Some(max_age) = p.max_age {
        if max_age < 0 {
            return Err(OauthError::invalid_request("max_age must be non-negative"));
        }
    }
    Ok(client)
}

fn create_authorize_flow(st: &AppState, params: &AuthzParams) -> ApiResult<Flow> {
    let id = new_id();
    let csrf = random_token(18);
    let payload = serde_json::to_string(params)
        .map_err(|_| OauthError::server_error("could not serialise request"))?;
    let expires_at = now() + 600;
    st.db.with(|c| {
        c.execute(
            "INSERT INTO flows (id, kind, user_id, client_id, payload, challenge, csrf, expires_at, created_at, consumed)
             VALUES (?1, 'authorize', NULL, ?2, ?3, NULL, ?4, ?5, ?6, 0)",
            params![id, params.client_id, payload, csrf, expires_at, now()],
        )?;
        Ok(())
    })?;
    Ok(Flow {
        id,
        kind: "authorize".to_string(),
        user_id: None,
        client_id: Some(params.client_id.clone()),
        payload: serde_json::to_value(params).unwrap_or(Value::Null),
        challenge: None,
        csrf: Some(csrf),
        expires_at,
        consumed: false,
    })
}

fn authz_fail(
    st: &AppState,
    params: Option<&AuthzParams>,
    code: &str,
    description: &str,
) -> Response {
    if let Some(p) = params {
        if let Ok(Some(client)) = st.db.with(|c| db::load_client(c, &p.client_id)) {
            if client.redirect_uris.iter().any(|u| u == &p.redirect_uri) {
                return authorization_error_redirect(st, &client, p, code, description);
            }
        }
    }
    let body = format!(
        "<!doctype html><meta charset=\"utf-8\"><title>Authorization error</title>\
         <h1>認可リクエストを処理できません</h1><p><code>{}</code>: {}</p>",
        esc(code),
        esc(description)
    );
    (StatusCode::BAD_REQUEST, Html(body)).into_response()
}

fn authorization_error_redirect(
    st: &AppState,
    client: &Client,
    p: &AuthzParams,
    code: &str,
    description: &str,
) -> Response {
    let mode = p.response_mode();
    let mut params: Vec<(&str, String)> = vec![("error", code.to_string())];
    if !description.is_empty() {
        params.push(("error_description", description.to_string()));
    }
    if let Some(state) = &p.state {
        params.push(("state", state.clone()));
    }
    params.push(("iss", st.cfg.issuer.clone()));

    if mode.ends_with("jwt") {
        let claims = json!({
            "iss": st.cfg.issuer,
            "aud": client.id,
            "iat": now(),
            "exp": now() + 120,
            "error": code,
            "error_description": description,
            "state": p.state,
        });
        let signed = match st
            .keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .current()
            .sign(Some("JWT"), &claims)
        {
            Ok(token) => token,
            Err(error) => {
                eprintln!("[kagi] JARM error response signing failed: {error:#}");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Html("<!doctype html><meta charset=\"utf-8\"><title>Server error</title><h1>Internal server error</h1>"),
                )
                    .into_response();
            }
        };
        let target = if mode.starts_with("fragment") {
            build_fragment(&p.redirect_uri, &[("response", signed)])
        } else {
            build_url(&p.redirect_uri, &[("response", signed)])
        };
        return redirect_303(&target);
    }

    let target = build_url(&p.redirect_uri, &params);
    redirect_303(&target)
}

/// Issue the authorization code and send the user back to the RP.
pub fn complete_authorization(
    st: &AppState,
    flow: &Flow,
    user: &User,
    session: &Session,
    approve: bool,
) -> Response {
    let params: AuthzParams = match serde_json::from_value(flow.payload.clone()) {
        Ok(p) => p,
        Err(_) => return authz_fail(st, None, "server_error", "stored request is corrupt"),
    };
    let client = match st.db.with(|c| db::load_client(c, &params.client_id)) {
        Ok(Some(c)) => c,
        _ => return authz_fail(st, Some(&params), "invalid_request", "unknown client"),
    };

    if !acr_satisfied(&params, session) {
        return authz_fail(
            st,
            Some(&params),
            "unmet_authentication_requirements",
            "the authenticated session does not satisfy the requested acr",
        );
    }
    if let Err(reason) = essential_claims_satisfied(&params, &client, user, session) {
        return authz_fail(st, Some(&params), "access_denied", &reason);
    }

    // Claim the flow before issuing anything. Two concurrent consent posts can
    // both pass the CSRF check and load the same flow; only the winner of this
    // compare-and-swap is allowed to mint an authorization code.
    let claimed = match st.db.with(|c| {
        Ok(c.execute(
            "UPDATE flows SET consumed = 1
             WHERE id = ?1 AND kind = 'authorize' AND consumed = 0 AND expires_at > ?2",
            params![flow.id, now()],
        )?)
    }) {
        Ok(changed) => changed,
        Err(error) => {
            eprintln!("[kagi] could not claim authorization flow: {error:#}");
            return authz_fail(
                st,
                Some(&params),
                "server_error",
                "could not complete the authorization request",
            );
        }
    };
    if claimed != 1 {
        return authz_fail(
            st,
            Some(&params),
            "invalid_request",
            "this authorization request was already completed or has expired",
        );
    }

    if !approve {
        return authorization_error_redirect(
            st,
            &client,
            &params,
            "access_denied",
            "the user denied the request",
        );
    }

    let code = random_token(32);
    let code_hash = sha256_hex(&code);
    let amr = serde_json::to_string(&session.amr).unwrap_or_else(|_| "[]".to_string());
    let grant_claims = normalized_claims(&params).unwrap_or(None);
    let inserted = st.db.with(|c| {
        c.execute(
            "INSERT INTO auth_codes
                (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge,
                 auth_time, amr, acr, dpop_jkt, session_id, claims, expires_at, created_at, consumed)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, 0)",
            params![
                code_hash,
                client.id,
                user.id,
                params.redirect_uri,
                params.scope,
                params.nonce,
                params.code_challenge,
                session.auth_time,
                amr,
                session.acr,
                params.dpop_jkt,
                session.id,
                grant_claims,
                now() + st.cfg.code_ttl,
                now(),
            ],
        )?;
        Ok(())
    });
    if inserted.is_err() {
        return authz_fail(
            st,
            Some(&params),
            "server_error",
            "could not store the code",
        );
    }

    authorization_success(st, &client, &params, &code, session)
}

fn authorization_success(
    st: &AppState,
    client: &Client,
    p: &AuthzParams,
    code: &str,
    session: &Session,
) -> Response {
    let mode = p.response_mode().to_string();

    if mode.ends_with("jwt") {
        let claims = json!({
            "iss": st.cfg.issuer,
            "aud": client.id,
            "iat": now(),
            "exp": now() + 120,
            "code": code,
            "state": p.state,
            "auth_time": session.auth_time,
            "amr": session.amr,
            "acr": session.acr,
            "sub": session.user_id,
        });
        let signed = match st
            .keys
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .current()
            .sign(Some("JWT"), &claims)
        {
            Ok(t) => t,
            Err(_) => return authz_fail(st, Some(p), "server_error", "signing failed"),
        };
        let target = if mode.starts_with("fragment") {
            build_fragment(&p.redirect_uri, &[("response", signed)])
        } else {
            build_url(&p.redirect_uri, &[("response", signed)])
        };
        return redirect_303(&target);
    }

    let mut params: Vec<(&str, String)> = vec![("code", code.to_string())];
    if let Some(state) = &p.state {
        params.push(("state", state.clone()));
    }
    params.push(("iss", st.cfg.issuer.clone()));

    if mode == "form_post" {
        let Some(action) = uri_origin(&p.redirect_uri) else {
            return authz_fail(
                st,
                Some(p),
                "invalid_request",
                "redirect_uri is not a valid absolute URI",
            );
        };
        let nonce = random_token(18);
        let inputs: String = params
            .iter()
            .map(|(k, v)| {
                format!(
                    "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
                    esc(k),
                    esc(v)
                )
            })
            .collect();
        let body = format!(
            "<!doctype html><meta charset=\"utf-8\"><title>Redirecting…</title>\
             <form id=\"f\" method=\"post\" action=\"{}\">{inputs}\
             <noscript><button type=\"submit\">Continue</button></noscript></form>\
             <script nonce=\"{}\">document.getElementById('f').submit()</script>",
            esc(&p.redirect_uri),
            esc(&nonce)
        );
        // The default document CSP allows scripts only from 'self' and forms
        // only to 'self'. A form_post response needs exactly one inline script
        // and a cross-origin form target, so scope a dedicated policy to this
        // response instead of weakening the global one.
        let csp = format!(
            "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'none'; img-src 'none'; \
             connect-src 'none'; font-src 'none'; base-uri 'none'; form-action {action}; \
             frame-ancestors 'none'; object-src 'none'"
        );
        let header_value = match HeaderValue::from_str(&csp) {
            Ok(value) => value,
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "invalid response policy")
                    .into_response()
            }
        };
        let mut res = ([(header::CACHE_CONTROL, "no-store")], Html(body)).into_response();
        res.headers_mut()
            .insert(header::CONTENT_SECURITY_POLICY, header_value);
        return res;
    }

    let target = if mode == "fragment" {
        build_fragment(&p.redirect_uri, &params)
    } else {
        build_url(&p.redirect_uri, &params)
    };
    redirect_303(&target)
}

// ---------------------------------------------------------------------------
// Token endpoint
// ---------------------------------------------------------------------------

pub async fn token(
    State(st): State<AppState>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    match token_inner(&st, &headers, &form) {
        Ok(res) => res,
        Err(e) => e.into_response(),
    }
}

fn token_inner(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Response> {
    let client = authenticate_client(st, headers, form)?;
    let grant_type = form
        .get("grant_type")
        .ok_or_else(|| OauthError::invalid_request("grant_type is required"))?
        .clone();

    let proof = dpop::inspect(st.cfg.as_ref(), &st.db, headers, "POST", "/token", None)?;
    let jkt = proof.map(|p| p.jkt);
    if (st.cfg.require_dpop || client.require_dpop) && jkt.is_none() {
        return Err(OauthError::invalid_dpop_proof("DPoP proof required"));
    }

    match grant_type.as_str() {
        "authorization_code" => exchange_code(st, &client, form, jkt.as_deref()),
        "refresh_token" => refresh(st, &client, form, jkt.as_deref()),
        "client_credentials" => client_credentials(st, &client, form, jkt.as_deref()),
        grant if grant == crate::device::DEVICE_GRANT => {
            crate::device::exchange(st, &client, form, jkt.as_deref())
        }
        other => Err(OauthError::unsupported(format!(
            "unsupported grant_type {other}"
        ))),
    }
}

fn exchange_code(
    st: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> ApiResult<Response> {
    let code = form
        .get("code")
        .ok_or_else(|| OauthError::invalid_request("code is required"))?;
    let verifier = form
        .get("code_verifier")
        .ok_or_else(|| OauthError::invalid_request("code_verifier is required"))?;
    if verifier.len() < 43 || verifier.len() > 128 {
        return Err(OauthError::invalid_grant(
            "code_verifier has an invalid length",
        ));
    }

    let code_hash = sha256_hex(code);
    let row = st
        .db
        .with(|c| db::load_code(c, &code_hash))?
        .ok_or_else(|| OauthError::invalid_grant("unknown authorization code"))?;

    if row.consumed {
        return Err(OauthError::invalid_grant("authorization code already used"));
    }
    if row.expires_at < now() {
        return Err(OauthError::invalid_grant("authorization code expired"));
    }
    if row.client_id != client.id {
        return Err(OauthError::invalid_grant(
            "authorization code was issued to another client",
        ));
    }
    let redirect_uri = form
        .get("redirect_uri")
        .ok_or_else(|| OauthError::invalid_request("redirect_uri is required"))?;
    if &row.redirect_uri != redirect_uri {
        return Err(OauthError::invalid_grant("redirect_uri mismatch"));
    }

    let computed = b64(&sha256(verifier.as_bytes()));
    if !ct_eq(&computed, &row.code_challenge) {
        return Err(OauthError::invalid_grant("PKCE verification failed"));
    }

    match (&row.dpop_jkt, jkt) {
        (Some(bound), Some(present)) if bound.as_str() == present => {}
        (Some(_), _) => {
            return Err(OauthError::invalid_grant(
                "authorization code is bound to a different DPoP key",
            ))
        }
        (None, _) => {}
    }

    let changed = st.db.with(|c| {
        Ok(c.execute(
            "UPDATE auth_codes SET consumed = 1 WHERE code_hash = ?1 AND consumed = 0",
            params![code_hash],
        )?)
    })?;
    if changed != 1 {
        return Err(OauthError::invalid_grant("authorization code already used"));
    }

    let user = st
        .db
        .with(|c| db::load_user(c, &row.user_id))?
        .ok_or_else(|| OauthError::invalid_grant("user no longer exists"))?;

    let (access_token, expires_in) = mint_access_token(
        st,
        &user.id,
        &client.id,
        &row.scope,
        jkt,
        row.session_id.as_deref(),
        row.claims.as_deref(),
    )?;

    let id_token = mint_id_token(
        st,
        &user,
        &client.id,
        &row.scope,
        row.nonce.as_deref(),
        row.auth_time,
        &row.amr,
        &row.acr,
        &access_token,
        row.session_id.as_deref(),
        jkt,
        row.claims.as_deref(),
    )?;

    let refresh_token = if scope_contains(&row.scope, "offline_access") {
        Some(mint_refresh_token(
            st,
            &user.id,
            &client.id,
            &row.scope,
            row.auth_time,
            &row.amr,
            &row.acr,
            jkt,
            row.session_id.as_deref(),
            None,
            row.claims.as_deref(),
        )?)
    } else {
        None
    };

    Ok(token_response(
        access_token,
        expires_in,
        &row.scope,
        refresh_token,
        Some(id_token),
        jkt.is_some(),
    ))
}

fn refresh(
    st: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> ApiResult<Response> {
    let token = form
        .get("refresh_token")
        .ok_or_else(|| OauthError::invalid_request("refresh_token is required"))?;
    let hash = sha256_hex(token);
    let row = st
        .db
        .with(|c| db::load_refresh(c, &hash))?
        .ok_or_else(|| OauthError::invalid_grant("unknown refresh token"))?;

    if row.client_id != client.id {
        return Err(OauthError::invalid_grant(
            "refresh token was issued to another client",
        ));
    }
    if row.revoked || row.rotated_to.is_some() {
        // Reuse detection: kill the whole token family.
        revoke_family(st, &row.family_id)?;
        return Err(OauthError::invalid_grant(
            "refresh token reuse detected; the token family has been revoked",
        ));
    }
    if row.expires_at < now() {
        return Err(OauthError::invalid_grant("refresh token expired"));
    }

    // A refresh token issued from a browser session must not outlive that
    // session's absolute or idle lifetime. This check is server-side; it does
    // not depend on the browser still sending its session cookie.
    if let Some(session_id) = row.session_id.as_deref() {
        let session = st.db.with(|c| db::load_session(c, session_id))?;
        let session_active = session.as_ref().is_some_and(|session| {
            let last_seen = if session.last_seen_at > 0 {
                session.last_seen_at
            } else {
                session.created_at
            };
            st.cfg.session_idle_ttl == 0
                || now().saturating_sub(last_seen) <= st.cfg.session_idle_ttl
        });
        if !session_active {
            st.db.tx(|tx| {
                db::revoke_session_tokens(tx, session_id)?;
                tx.execute(
                    "UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?1",
                    params![row.family_id],
                )?;
                tx.execute("DELETE FROM sessions WHERE id = ?1", params![session_id])?;
                Ok(())
            })?;
            return Err(OauthError::invalid_grant(
                "the browser session has expired; sign in again",
            ));
        }
    }

    match (&row.dpop_jkt, jkt) {
        (Some(bound), Some(present)) if bound.as_str() == present => {}
        (Some(_), _) => {
            return Err(OauthError::invalid_grant(
                "refresh token is bound to a different DPoP key",
            ))
        }
        (None, _) => {}
    }

    let scope = match form.get("scope") {
        Some(requested) if !requested.trim().is_empty() => {
            if !scope_subset(requested, &row.scope) {
                return Err(OauthError::invalid_scope(
                    "requested scope exceeds the original grant",
                ));
            }
            requested.clone()
        }
        _ => row.scope.clone(),
    };

    let new_token = random_token(32);
    let new_hash = sha256_hex(&new_token);
    let rotated = st.db.tx(|tx| {
        // A compare-and-swap is required: two concurrent requests may both
        // have loaded the same active token before either transaction starts.
        let changed = tx.execute(
            "UPDATE refresh_tokens SET revoked = 1, rotated_to = ?1 \
             WHERE token_hash = ?2 AND client_id = ?3 AND revoked = 0 \
               AND rotated_to IS NULL AND expires_at > ?4",
            params![new_hash, hash, client.id, now()],
        )?;
        if changed != 1 {
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO refresh_tokens
                (token_hash, family_id, user_id, client_id, scope, auth_time, amr, acr,
                 dpop_jkt, session_id, claims, issued_at, expires_at, rotated_to, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, 0)",
            params![
                new_hash,
                row.family_id,
                row.user_id,
                row.client_id,
                scope,
                row.auth_time,
                serde_json::to_string(&row.amr).unwrap_or_else(|_| "[]".into()),
                row.acr,
                row.dpop_jkt,
                row.session_id,
                row.claims,
                now(),
                now() + st.cfg.refresh_ttl,
            ],
        )?;
        Ok(true)
    })?;
    if !rotated {
        // Treat a lost compare-and-swap as concurrent reuse and revoke every
        // token in the family, rather than issuing a second descendant token.
        revoke_family(st, &row.family_id)?;
        return Err(OauthError::invalid_grant(
            "refresh token reuse detected; the token family has been revoked",
        ));
    }

    let (access_token, expires_in) = mint_access_token(
        st,
        &row.user_id,
        &client.id,
        &scope,
        jkt,
        row.session_id.as_deref(),
        row.claims.as_deref(),
    )?;

    let id_token = if scope_contains(&scope, "openid") {
        let user = st
            .db
            .with(|c| db::load_user(c, &row.user_id))?
            .ok_or_else(|| OauthError::invalid_grant("user no longer exists"))?;
        Some(mint_id_token(
            st,
            &user,
            &client.id,
            &scope,
            None,
            row.auth_time,
            &row.amr,
            &row.acr,
            &access_token,
            row.session_id.as_deref(),
            jkt,
            row.claims.as_deref(),
        )?)
    } else {
        None
    };

    Ok(token_response(
        access_token,
        expires_in,
        &scope,
        Some(new_token),
        id_token,
        jkt.is_some(),
    ))
}

fn client_credentials(
    st: &AppState,
    client: &Client,
    form: &HashMap<String, String>,
    jkt: Option<&str>,
) -> ApiResult<Response> {
    if client.auth_method == "none" {
        return Err(OauthError::invalid_client(
            "client_credentials requires a confidential client",
        ));
    }
    if !client.grant_types.iter().any(|g| g == "client_credentials") {
        return Err(OauthError::invalid_request(
            "client is not allowed to use client_credentials",
        ));
    }

    let scope = match form.get("scope") {
        Some(s) if !s.trim().is_empty() => {
            if !scope_subset(s, &client.scopes.join(" ")) {
                return Err(OauthError::invalid_scope(
                    "scope exceeds client registration",
                ));
            }
            s.clone()
        }
        _ => client.scopes.join(" "),
    };

    let (access_token, expires_in) =
        mint_access_token(st, &client.id, &client.id, &scope, jkt, None, None)?;

    Ok(token_response(
        access_token,
        expires_in,
        &scope,
        None,
        None,
        jkt.is_some(),
    ))
}

pub(crate) fn token_response(
    access_token: String,
    expires_in: i64,
    scope: &str,
    refresh_token: Option<String>,
    id_token: Option<String>,
    dpop: bool,
) -> Response {
    let mut body = json!({
        "access_token": access_token,
        "token_type": if dpop { "DPoP" } else { "Bearer" },
        "expires_in": expires_in,
        "scope": scope,
    });
    if let Some(rt) = refresh_token {
        body["refresh_token"] = json!(rt);
    }
    if let Some(idt) = id_token {
        body["id_token"] = json!(idt);
    }
    let mut res = Json(body).into_response();
    res.headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res.headers_mut()
        .insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    res
}

// ---------------------------------------------------------------------------
// Token minting
// ---------------------------------------------------------------------------

pub(crate) fn mint_access_token(
    st: &AppState,
    subject: &str,
    client_id: &str,
    scope: &str,
    jkt: Option<&str>,
    session_id: Option<&str>,
    grant_claims: Option<&str>,
) -> ApiResult<(String, i64)> {
    let issued_at = now();
    let expires_at = issued_at + st.cfg.access_ttl;
    let jti = random_token(16);

    let mut claims = json!({
        "iss": st.cfg.issuer,
        "sub": subject,
        "aud": st.cfg.issuer,
        "client_id": client_id,
        "scope": scope,
        "iat": issued_at,
        "exp": expires_at,
        "jti": jti,
    });
    if let Some(jkt) = jkt {
        claims["cnf"] = json!({ "jkt": jkt });
    }
    if let Some(sid) = session_id {
        claims["sid"] = json!(sid);
    }
    // UserInfo needs the same claim filter that was consented to at the
    // authorization endpoint. The request is not secret; only claim names and
    // essential flags are carried.
    if let Some(raw) = grant_claims {
        if let Ok(value) = serde_json::from_str::<Value>(raw) {
            claims["kagi_claims"] = value;
        }
    }

    let token = st
        .keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .current()
        .sign(Some("at+jwt"), &claims)
        .map_err(|error| {
            eprintln!("[kagi] access-token signing failed: {error:#}");
            OauthError::server_error("internal server error")
        })?;

    st.db.with(|c| {
        c.execute(
            "INSERT INTO access_tokens
                (jti, user_id, client_id, scope, audience, dpop_jkt, subject, session_id, issued_at, expires_at, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, 0)",
            params![
                jti,
                subject,
                client_id,
                scope,
                st.cfg.issuer,
                jkt,
                subject,
                session_id,
                issued_at,
                expires_at,
            ],
        )?;
        Ok(())
    })?;

    Ok((token, st.cfg.access_ttl))
}

// Token minting signatures mirror the OAuth/OpenID claims they emit; grouping
// them into a struct would obscure that mapping without removing any argument.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_refresh_token(
    st: &AppState,
    user_id: &str,
    client_id: &str,
    scope: &str,
    auth_time: i64,
    amr: &[String],
    acr: &str,
    jkt: Option<&str>,
    session_id: Option<&str>,
    family_id: Option<&str>,
    grant_claims: Option<&str>,
) -> ApiResult<String> {
    let token = random_token(32);
    let hash = sha256_hex(&token);
    let family = family_id.map(|s| s.to_string()).unwrap_or_else(new_id);
    st.db.with(|c| {
        c.execute(
            "INSERT INTO refresh_tokens
                (token_hash, family_id, user_id, client_id, scope, auth_time, amr, acr,
                 dpop_jkt, session_id, claims, issued_at, expires_at, rotated_to, revoked)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, NULL, 0)",
            params![
                hash,
                family,
                user_id,
                client_id,
                scope,
                auth_time,
                serde_json::to_string(amr).unwrap_or_else(|_| "[]".into()),
                acr,
                jkt,
                session_id,
                grant_claims,
                now(),
                now() + st.cfg.refresh_ttl,
            ],
        )?;
        Ok(())
    })?;
    Ok(token)
}

// See `mint_refresh_token` for why the claim arguments stay explicit.
#[allow(clippy::too_many_arguments)]
pub(crate) fn mint_id_token(
    st: &AppState,
    user: &User,
    client_id: &str,
    scope: &str,
    nonce: Option<&str>,
    auth_time: i64,
    amr: &[String],
    acr: &str,
    access_token: &str,
    session_id: Option<&str>,
    dpop_jkt: Option<&str>,
    grant_claims: Option<&str>,
) -> ApiResult<String> {
    let hash = sha256(access_token.as_bytes());
    let at_hash = b64(&hash[..16]);
    let mut claims = json!({
        "iss": st.cfg.issuer,
        "sub": user.id,
        "aud": client_id,
        "azp": client_id,
        "iat": now(),
        "exp": now() + st.cfg.id_ttl,
        "auth_time": auth_time,
        "amr": amr,
        "acr": acr,
        "at_hash": at_hash,
    });
    if let Some(nonce) = nonce {
        claims["nonce"] = json!(nonce);
    }
    if let Some(sid) = session_id {
        claims["sid"] = json!(sid);
    }
    // RFC 9449 §10: bind the ID token to the DPoP key as well.
    if let Some(jkt) = dpop_jkt {
        claims["cnf"] = json!({ "jkt": jkt });
    }
    // Only release profile/email claims that the granted scope and an explicit
    // `claims` request both allow. Scope remains the outer boundary.
    if let Some(raw) = grant_claims {
        if let Ok(request) = serde_json::from_str::<ClaimsRequest>(raw) {
            for claim in request.id_token.keys() {
                match claim.as_str() {
                    "name" if scope_contains(scope, "profile") => {
                        claims["name"] = json!(user.display_name);
                    }
                    "preferred_username" if scope_contains(scope, "profile") => {
                        claims["preferred_username"] = json!(user.username);
                    }
                    "email" if scope_contains(scope, "email") => {
                        if let Some(email) = &user.email {
                            claims["email"] = json!(email);
                        }
                    }
                    "email_verified"
                        if scope_contains(scope, "email") && user.email.is_some() =>
                    {
                        claims["email_verified"] = json!(user.email_verified);
                    }
                    _ => {}
                }
            }
        }
    }
    st.keys
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .current()
        .sign(Some("JWT"), &claims)
        .map_err(|error| {
            eprintln!("[kagi] ID-token signing failed: {error:#}");
            OauthError::server_error("internal server error")
        })
}

pub fn revoke_family(st: &AppState, family_id: &str) -> ApiResult<()> {
    st.db.with(|c| {
        c.execute(
            "UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?1",
            params![family_id],
        )?;
        Ok(())
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Client authentication
// ---------------------------------------------------------------------------

pub fn authenticate_client(
    st: &AppState,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> ApiResult<Client> {
    let basic = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Basic "))
        .and_then(|b| STANDARD.decode(b.trim()).ok());
    if let Some(raw) = basic {
        let raw = String::from_utf8(raw)
            .map_err(|_| OauthError::invalid_client("basic credentials are not UTF-8"))?;
        let (id, secret) = raw
            .split_once(':')
            .ok_or_else(|| OauthError::invalid_client("malformed basic credentials"))?;
        let client = load_client_required(st, id)?;
        if client.auth_method != "client_secret_basic" {
            return Err(OauthError::invalid_client(
                "client is not registered for client_secret_basic",
            ));
        }
        verify_secret(&client, secret)?;
        return Ok(client);
    }

    if let Some(assertion) = form.get("client_assertion") {
        let assertion_type = form
            .get("client_assertion_type")
            .map(String::as_str)
            .unwrap_or_default();
        if assertion_type != "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" {
            return Err(OauthError::invalid_client(
                "unsupported client_assertion_type",
            ));
        }
        let client_id = form
            .get("client_id")
            .ok_or_else(|| OauthError::invalid_client("client_id is required"))?
            .clone();
        let client = load_client_required(st, &client_id)?;
        if client.auth_method != "private_key_jwt" {
            return Err(OauthError::invalid_client(
                "client is not registered for private_key_jwt",
            ));
        }
        verify_client_assertion(st, &client, assertion)?;
        return Ok(client);
    }

    let client_id = form
        .get("client_id")
        .ok_or_else(|| OauthError::invalid_client("client_id is required"))?;
    let client = load_client_required(st, client_id)?;

    if let Some(secret) = form.get("client_secret") {
        if client.auth_method != "client_secret_post" {
            return Err(OauthError::invalid_client(
                "client is not registered for client_secret_post",
            ));
        }
        verify_secret(&client, secret)?;
        return Ok(client);
    }

    if client.auth_method != "none" {
        return Err(OauthError::invalid_client(
            "client authentication is required",
        ));
    }
    Ok(client)
}

fn load_client_required(st: &AppState, id: &str) -> ApiResult<Client> {
    st.db
        .with(|c| db::load_client(c, id))?
        .ok_or_else(|| OauthError::invalid_client("unknown client"))
}

fn verify_secret(client: &Client, secret: &str) -> ApiResult<()> {
    let Some(expected) = client.secret_hash.as_deref() else {
        return Err(OauthError::invalid_client("client has no secret"));
    };
    if !ct_eq(&sha256_hex(secret), expected) {
        return Err(OauthError::invalid_client("invalid client secret"));
    }
    Ok(())
}

fn verify_client_assertion(st: &AppState, client: &Client, assertion: &str) -> ApiResult<()> {
    let jwks = client
        .jwks
        .as_ref()
        .ok_or_else(|| OauthError::invalid_client("client has no registered jwks"))?;
    let (header, claims) = jose::verify_with_jwks(jwks, assertion, Some("JWT")).map_err(|error| {
        eprintln!("[kagi] client assertion validation failed: {error:#}");
        OauthError::invalid_client("invalid client assertion")
    })?;
    if header.get("alg").and_then(Value::as_str) == Some("none") {
        return Err(OauthError::invalid_client("alg=none is not allowed"));
    }
    if claims.get("iss").and_then(Value::as_str) != Some(client.id.as_str())
        || claims.get("sub").and_then(Value::as_str) != Some(client.id.as_str())
    {
        return Err(OauthError::invalid_client(
            "assertion iss/sub must equal client_id",
        ));
    }
    let token_endpoint = st.cfg.endpoint("/token");
    let aud_ok = match claims.get("aud") {
        Some(Value::String(s)) => s == &token_endpoint || s == &st.cfg.issuer,
        Some(Value::Array(a)) => a.iter().any(|v| {
            v.as_str() == Some(token_endpoint.as_str())
                || v.as_str() == Some(st.cfg.issuer.as_str())
        }),
        _ => false,
    };
    if !aud_ok {
        return Err(OauthError::invalid_client("assertion aud is not this OP"));
    }
    let exp = claims
        .get("exp")
        .and_then(Value::as_i64)
        .ok_or_else(|| OauthError::invalid_client("assertion has no exp"))?;
    if exp < now() {
        return Err(OauthError::invalid_client("assertion expired"));
    }
    if let Some(iat) = claims.get("iat").and_then(Value::as_i64) {
        if (now() - iat).abs() > 300 {
            return Err(OauthError::invalid_client("assertion iat is out of range"));
        }
    }
    let jti = claims
        .get("jti")
        .and_then(Value::as_str)
        .ok_or_else(|| OauthError::invalid_client("assertion has no jti"))?;
    let inserted = st.db.with(|c| {
        Ok(c.execute(
            "INSERT OR IGNORE INTO assertion_replay (jti, expires_at) VALUES (?1, ?2)",
            params![jti, exp.max(now()) + 60],
        )?)
    })?;
    if inserted == 0 {
        return Err(OauthError::invalid_client("assertion replayed"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Redirect helpers
// ---------------------------------------------------------------------------

pub fn redirect_303(url: &str) -> Response {
    redirect_with(StatusCode::SEE_OTHER, url)
}

pub fn redirect_302(url: &str) -> Response {
    redirect_with(StatusCode::FOUND, url)
}

fn redirect_with(status: StatusCode, url: &str) -> Response {
    let mut res = status.into_response();
    match HeaderValue::from_str(url) {
        Ok(value) => {
            res.headers_mut().insert(header::LOCATION, value);
            res.headers_mut()
                .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
        }
        Err(_) => {
            return (StatusCode::BAD_REQUEST, "invalid redirect target").into_response();
        }
    }
    res
}

fn build_fragment(base: &str, params: &[(&str, String)]) -> String {
    let mut out = String::from(base);
    out.push('#');
    for (i, (k, v)) in params.iter().enumerate() {
        if i > 0 {
            out.push('&');
        }
        out.push_str(&urlenc(k));
        out.push('=');
        out.push_str(&urlenc(v));
    }
    out
}

#[cfg(test)]
mod claims_tests {
    use super::*;
    use std::collections::HashMap;

    fn params(claims: &str) -> AuthzParams {
        let mut map = HashMap::new();
        map.insert("claims".to_string(), claims.to_string());
        map.insert("scope".to_string(), "openid profile email".to_string());
        AuthzParams::from_map(&map)
    }

    #[test]
    fn unknown_claims_are_rejected() {
        let error = parse_claims_request(r#"{"id_token":{"password":null}}"#).unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn claim_values_are_only_allowed_for_acr() {
        let error = parse_claims_request(r#"{"id_token":{"email":{"value":"a@b"}}}"#)
            .unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn oversized_claims_are_rejected() {
        let raw = format!(r#"{{"userinfo":{{"sub":{{"essential":true}}}},{}"#,
            " ".repeat(5000));
        let error = parse_claims_request(&raw).unwrap_err();
        assert_eq!(error.code, "invalid_request");
    }

    #[test]
    fn claims_are_canonicalized() {
        let normalized = normalized_claims(&params(
            r#"{"id_token":{"email":{"essential":true}},"userinfo":{"name":null}}"#,
        ))
        .expect("valid claims");
        let raw = normalized.expect("claims present");
        assert!(raw.contains("\"essential\":true"));
        assert!(raw.contains("\"name\":null"));
    }

    #[test]
    fn essential_email_requires_the_email_scope() {
        let mut map = HashMap::new();
        map.insert(
            "claims".to_string(),
            r#"{"id_token":{"email":{"essential":true}}}"#.to_string(),
        );
        map.insert("scope".to_string(), "openid profile".to_string());
        let params = AuthzParams::from_map(&map);
        let user = crate::db::User {
            id: "user-1".to_string(),
            username: "alice".to_string(),
            display_name: "Alice".to_string(),
            email: Some("alice@example.com".to_string()),
            email_verified: true,
            created_at: 0,
        };
        let session = crate::db::Session {
            id: "session-1".to_string(),
            user_id: "user-1".to_string(),
            auth_time: 0,
            amr: vec!["passkey".to_string()],
            acr: crate::auth::ACR_PASSKEY.to_string(),
            expires_at: 0,
            created_at: 0,
            last_seen_at: 0,
            user_agent: None,
            ip: None,
        };
        let client = crate::db::Client {
            id: "client-1".to_string(),
            name: "test".to_string(),
            secret_hash: None,
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            grant_types: vec!["authorization_code".to_string()],
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            auth_method: "none".to_string(),
            jwks: None,
            require_dpop: false,
            require_par: false,
            id_token_alg: "ES256".to_string(),
            registration_token_hash: None,
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
        };
        let error = essential_claims_satisfied(&params, &client, &user, &session)
            .expect_err("email is outside the granted scope");
        assert!(error.contains("email"));
    }

    #[test]
    fn acr_claim_constraint_is_enforced() {
        let mut map = HashMap::new();
        map.insert(
            "claims".to_string(),
            r#"{"id_token":{"acr":{"value":"urn:kagi:acr:recovery"}}}"#.to_string(),
        );
        let params = AuthzParams::from_map(&map);
        let session = crate::db::Session {
            id: "s".to_string(),
            user_id: "u".to_string(),
            auth_time: 0,
            amr: vec!["passkey".to_string()],
            acr: crate::auth::ACR_PASSKEY.to_string(),
            expires_at: 0,
            created_at: 0,
            last_seen_at: 0,
            user_agent: None,
            ip: None,
        };
        assert!(!acr_satisfied(&params, &session));
    }
}
