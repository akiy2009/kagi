//! Server-rendered HTML. No template engine: these are small, auditable pages
//! and every interpolation goes through `esc`.

use crate::db::{AuditEvent, Consent, Credential, Session, User};
use crate::oidc::split_scope;
use crate::util::esc;
use serde_json::Value;

fn page(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex, nofollow">
<meta name="description" content="kagi — パスキーでサインインできる OIDC アイデンティティプロバイダー。">
<meta name="theme-color" content='#ffffff' media="(prefers-color-scheme: light)">
<meta name="theme-color" content='#0a0a0a' media="(prefers-color-scheme: dark)">
<title>{title} · Kagi Identity</title>
<link rel="stylesheet" href="/static/style.css">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'><circle cx='7.5' cy='15.5' r='4.5' fill='none' stroke='black' stroke-width='2'/><path d='M10.7 12.3 21 2m-3 3 3 3m-6 0 2 2' fill='none' stroke='black' stroke-width='2'/></svg>">
<script src="/static/theme.js"></script>
</head>
<body>
<a class="skip-link" href='#main'>本文へスキップ</a>
<main class="shell" id="main" tabindex="-1">
{body}
</main>
{theme}
<script src="/static/app.js" defer></script>
</body>
</html>
"#,
        title = esc(title),
        body = body,
        theme = theme_toggle()
    )
}

fn config_script(value: &Value) -> String {
    let raw = serde_json::to_string(value).unwrap_or_else(|_| "{}".into());
    let safe = raw
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026");
    format!(r#"<script type="application/json" id="kagi-config">{safe}</script>"#)
}

fn brand_svg() -> &'static str {
    r#"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="7.5" cy="15.5" r="4.5"/><path d="M10.7 12.3 21 2m-3 3 3 3m-6 0 2 2"/></svg>"#
}

fn brand() -> String {
    format!(
        r#"<div class="brand">{}<span>Kagi Identity</span></div>"#,
        brand_svg()
    )
}

/// Theme switcher. The label is updated by `static/app.js`; the initial value
/// is always "auto" and `static/theme.js` applies an explicit saved choice
/// before the first paint.
fn theme_toggle() -> &'static str {
    r#"<button class="theme-toggle" id="theme-toggle" type="button" aria-label="テーマ: 自動" title="テーマ: 自動（クリックで切り替え）">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 0 0 18Z" fill="currentColor" stroke="none"/></svg>
<span class="theme-label">自動</span>
</button>"#
}

pub fn error_page(code: &str, message: &str) -> String {
    page(
        "エラー",
        &format!(
            r#"<section class="card narrow">
{brand}
<p class="eyebrow">Error {code}</p>
<h1>処理できませんでした</h1>
<p class="muted">{message}</p>
<p class="hint">問題が続く場合は、時間をおいてもう一度お試しください。</p>
<p class="foot"><a href="/">ホームに戻る</a> ・ <a href="/login">サインイン</a></p>
</section>"#,
            brand = brand(),
            code = esc(code),
            message = esc(message)
        ),
    )
}

pub fn login_page(rid: &str, csrf: &str) -> String {
    let config = config_script(&serde_json::json!({
        "flow": "login",
        "rid": rid,
        "csrf": csrf,
    }));
    page(
        "サインイン",
        &format!(
            r#"<section class="card narrow">
{brand}
<p class="eyebrow">Sign in</p>
<h1>パスキーでサインイン</h1>
<p class="muted">生体認証・画面ロック・セキュリティキーで認証します。パスワードは保存されません。</p>
<form id="login-form">
  <label class="field">
    <span>ユーザー名 <em>任意</em></span>
    <input id="username" name="username" autocomplete="username webauthn" placeholder="username" autofocus aria-describedby="username-hint">
    <small class="field-hint" id="username-hint">この端末にパスキーが1つだけなら、空欄のままでも進めます。</small>
  </label>
  <button class="primary" id="btn-login" type="submit">
    <span class="label">パスキーで続行</span>
  </button>
</form>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<details class="help">
  <summary>パスキーが使えないとき</summary>
  <div class="help-body">
    <p>Chrome・Edge・Safari・Firefox の最新版と、HTTPS（または localhost）が必要です。</p>
    <p>別の端末のパスキーを使う場合は、その端末でこのページを開いてください。保存済みの<a href="/recover{recover_q}">リカバリーコード</a>でもサインインできます。</p>
  </div>
</details>
<p class="foot">アカウントをお持ちでない方は <a href="/signup{signup_q}">新規登録</a></p>
{config}
</section>"#,
            brand = brand(),
            signup_q = if rid.is_empty() {
                String::new()
            } else {
                format!("?rid={}", crate::util::urlenc(rid))
            },
            recover_q = if rid.is_empty() {
                String::new()
            } else {
                format!("?rid={}", crate::util::urlenc(rid))
            },
            config = config
        ),
    )
}

pub fn signup_page(rid: Option<&str>) -> String {
    let config = config_script(&serde_json::json!({
        "flow": "signup",
        "rid": rid,
    }));
    page(
        "新規登録",
        &format!(
            r#"<section class="card narrow">
{brand}
<p class="eyebrow">Create account</p>
<h1>パスキーで始める</h1>
<p class="muted">アカウントはパスキーだけで保護されます。パスワードもメール認証も不要です。</p>
<form id="signup-form" autocomplete="off">
  <label class="field">
    <span>ユーザー名</span>
    <input id="username" name="username" autocomplete="username" placeholder="alice" required minlength="3" maxlength="64" pattern="[A-Za-z0-9._\-]+" aria-describedby="username-hint">
    <small class="field-hint" id="username-hint">3〜64文字。英数字と <code>._-</code> が使えます。</small>
  </label>
  <label class="field">
    <span>表示名</span>
    <input id="display_name" name="display_name" autocomplete="name" placeholder="Alice" required maxlength="80">
  </label>
  <label class="field">
    <span>メールアドレス <em>任意</em></span>
    <input id="email" name="email" type="email" autocomplete="email" placeholder="alice@example.com" aria-describedby="email-hint">
    <small class="field-hint" id="email-hint">OIDC の <code>email</code> スコープで共有されます。</small>
  </label>
  <button class="primary" id="btn-signup" type="submit">
    <span class="label">パスキーを作成</span>
  </button>
</form>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<p class="foot">すでにアカウントをお持ちの方は <a href="/login">サインイン</a></p>
{config}
</section>"#,
            brand = brand(),
            config = config
        ),
    )
}

pub fn consent_page(
    rid: &str,
    csrf: &str,
    client_name: &str,
    username: &str,
    scope: &str,
    redirect_host: &str,
) -> String {
    let scopes = split_scope(scope)
        .into_iter()
        .filter(|s| s != "openid")
        .map(|s| {
            let (title, detail) = match s.as_str() {
                "profile" => ("プロフィール", "表示名とユーザー名を共有します"),
                "email" => ("メールアドレス", "メールアドレスと確認状態を共有します"),
                "offline_access" => (
                    "オフラインアクセス",
                    "サインインしていない間も更新トークンでアクセスできます",
                ),
                other => ("追加の権限", other),
            };
            format!(
                r#"<li><div class="scope-title">{}</div><div class="scope-detail">{}</div></li>"#,
                esc(title),
                esc(detail)
            )
        })
        .collect::<String>();

    let scopes = if scopes.is_empty() {
        r#"<li><div class="scope-title">サインイン</div><div class="scope-detail">あなたの識別子 (sub) のみを共有します</div></li>"#.to_string()
    } else {
        scopes
    };

    page(
        "認可",
        &format!(
            r#"<section class="card">
{brand}
<p class="eyebrow">認可リクエスト</p>
<h1>{client}</h1>
<p class="muted"><strong>{user}</strong> としてサインイン中。次の情報へのアクセスを許可します。</p>
<ul class="scopes">{scopes}</ul>
<p class="callout">許可すると <strong>{client}</strong> は上記の情報を、解除するまで利用できます。許可したアプリはアカウント画面の「連携アプリ」からいつでも解除できます。</p>
<p class="hint">リダイレクト先 <code>{host}</code></p>
<form method="post" action="/consent" class="row choice">
  <input type="hidden" name="rid" value="{rid}">
  <input type="hidden" name="csrf" value="{csrf}">
  <button class="primary" type="submit" name="decision" value="allow"><span class="label">許可</span></button>
  <button class="ghost" type="submit" name="decision" value="deny">拒否</button>
</form>
</section>"#,
            brand = brand(),
            client = esc(client_name),
            user = esc(username),
            scopes = scopes,
            host = esc(redirect_host),
            rid = esc(rid),
            csrf = esc(csrf),
        ),
    )
}

/// RFC 8628 verification page. The user types the code shown on their device
/// and explicitly approves or denies the grant.
pub fn device_page(rid: &str, csrf: &str, prefill: &str, username: &str) -> String {
    page(
        "デバイスの承認",
        &format!(
            r#"<section class="card narrow">
{brand}
<p class="eyebrow">デバイス承認</p>
<h1>デバイスを接続</h1>
<p class="muted"><strong>{user}</strong> としてサインイン中。デバイスに表示されたコードを入力してください。</p>
<ol class="steps">
  <li>デバイスに表示されたコードを確認します。</li>
  <li>下の欄に入力します。小文字でも自動で大文字になります。</li>
  <li>内容を確認して「許可」を選びます。</li>
</ol>
<form method="post" action="/device" class="stack">
  <input type="hidden" name="rid" value="{rid}">
  <input type="hidden" name="csrf" value="{csrf}">
  <label class="field">
    <span>デバイスコード</span>
    <input id="user_code" name="user_code" value="{prefill}" autocomplete="one-time-code"
      autocapitalize="characters" spellcheck="false" placeholder="ABCD-EFGH" required
      maxlength="24" autofocus class="code-input" data-code-format="device"
      aria-describedby="device-code-hint">
    <small class="field-hint" id="device-code-hint">8文字のコードです。ハイフンは自動で入ります。</small>
  </label>
  <div class="row choice">
    <button class="primary" type="submit" name="decision" value="allow"><span class="label">許可</span></button>
    <button class="ghost" type="submit" name="decision" value="deny">拒否</button>
  </div>
</form>
<p class="hint">心当たりのないコードは許可しないでください。コードは第三者に伝えないでください。</p>
</section>"#,
            brand = brand(),
            user = esc(username),
            rid = esc(rid),
            csrf = esc(csrf),
            prefill = esc(prefill),
        ),
    )
}

pub fn device_result_page(title: &str, message: &str) -> String {
    page(
        title,
        &format!(
            r#"<section class="card narrow">
{brand}
<h1>{title}</h1>
<p class="muted">{message}</p>
<p class="foot"><a href="/">アカウントに戻る</a></p>
</section>"#,
            brand = brand(),
            title = esc(title),
            message = esc(message),
        ),
    )
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

/// Compact UTC timestamp. kagi deliberately avoids a date-time dependency:
/// this single function covers the console's needs.
fn fmt_datetime(ts: i64) -> String {
    if ts <= 0 {
        return "—".to_string();
    }
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y}/{m:02}/{d:02} {:02}:{:02} UTC",
        secs / 3_600,
        (secs % 3_600) / 60
    )
}

fn fmt_ago(ts: i64) -> String {
    if ts <= 0 {
        return "—".to_string();
    }
    let diff = crate::util::now() - ts;
    if diff < 60 {
        "たった今".to_string()
    } else if diff < 3_600 {
        format!("{}分前", diff / 60)
    } else if diff < 86_400 {
        format!("{}時間前", diff / 3_600)
    } else if diff < 2_592_000 {
        format!("{}日前", diff / 86_400)
    } else {
        fmt_datetime(ts)
    }
}

fn device_label(user_agent: Option<&str>) -> String {
    let Some(ua) = user_agent.filter(|s| !s.is_empty()) else {
        return "不明なデバイス".to_string();
    };
    let browser = if ua.contains("Edg/") {
        "Edge"
    } else if ua.contains("OPR/") {
        "Opera"
    } else if ua.contains("Chrome/") {
        "Chrome"
    } else if ua.contains("Firefox/") {
        "Firefox"
    } else if ua.contains("Safari/") {
        "Safari"
    } else {
        "ブラウザ"
    };
    let os = if ua.contains("Windows") {
        "Windows"
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        "iOS"
    } else if ua.contains("Android") {
        "Android"
    } else if ua.contains("Mac OS X") {
        "macOS"
    } else if ua.contains("Linux") {
        "Linux"
    } else {
        ""
    };
    if os.is_empty() {
        browser.to_string()
    } else {
        format!("{browser} · {os}")
    }
}

fn event_label(kind: &str) -> &'static str {
    match kind {
        "auth.login" => "サインイン",
        "auth.logout" => "サインアウト",
        "auth.signup" => "アカウント作成",
        "auth.login_failed" => "サインイン失敗",
        "passkey.add" => "パスキー追加",
        "passkey.rename" => "パスキー名変更",
        "passkey.delete" => "パスキー削除",
        "session.revoke" => "セッション終了",
        "session.revoke_others" => "他のデバイスをサインアウト",
        "consent.grant" => "アクセス許可",
        "consent.deny" => "アクセス拒否",
        "consent.revoke" => "アクセス取り消し",
        "profile.update" => "プロフィール更新",
        "recovery.generate" => "リカバリーコード生成",
        "recovery.use" => "リカバリーコード使用",
        "recovery.failed" => "リカバリー失敗",
        "account.delete" => "アカウント削除",
        _ => "セキュリティイベント",
    }
}

/// Render the signed-in account console. The arguments are the page's data
/// sources; they are grouped here because every section is rendered together.
#[allow(clippy::too_many_arguments)]
pub fn account_page(
    user: &User,
    creds: &[Credential],
    sessions: &[Session],
    current_sid: &str,
    consents: &[Consent],
    events: &[AuditEvent],
    recovery_count: i64,
    recovery_enabled: bool,
) -> String {
    let config = config_script(&serde_json::json!({
        "flow": "account",
        "username": user.username,
        "recovery": recovery_enabled,
    }));

    let can_delete_passkey = creds.len() > 1;
    let passkeys = if creds.is_empty() {
        r#"<li class="empty">パスキーが登録されていません</li>"#.to_string()
    } else {
        creds
            .iter()
            .map(|c| {
                let name = c.name.as_deref().unwrap_or("パスキー");
                let short: String = c.id.chars().take(12).collect();
                let synced = if c.backup_eligible {
                    r#"<span class="tag">同期対応</span>"#
                } else {
                    r#"<span class="tag">この端末のみ</span>"#
                };
                let remove = if can_delete_passkey {
                    format!(
                        r#"<button class="mini danger" type="button" data-action="delete-passkey" data-id="{id}">削除</button>"#,
                        id = esc(&c.id)
                    )
                } else {
                    String::new()
                };
                format!(
                    r#"<li class="item">
  <div class="item-main">
    <div class="item-title">{name} {synced}</div>
    <div class="item-sub">{created} に追加 · {short}…</div>
  </div>
  <div class="item-actions">
    <button class="mini" type="button" data-action="rename-passkey" data-id="{id}" data-name="{attr}">名前変更</button>
    {remove}
  </div>
</li>"#,
                    name = esc(name),
                    synced = synced,
                    created = esc(&fmt_datetime(c.created_at)),
                    short = esc(&short),
                    id = esc(&c.id),
                    attr = esc(name),
                    remove = remove,
                )
            })
            .collect::<String>()
    };

    let session_items = if sessions.is_empty() {
        r#"<li class="empty">サインイン中のデバイスはありません</li>"#.to_string()
    } else {
        sessions
            .iter()
            .map(|s| {
                let current = s.id == current_sid;
                let badge = if current {
                    r#"<span class="tag solid">このデバイス</span>"#
                } else {
                    ""
                };
                let ip = s.ip.as_deref().filter(|v| !v.is_empty()).unwrap_or("—");
                format!(
                    r#"<li class="item">
  <div class="item-main">
    <div class="item-title">{device} {badge}</div>
    <div class="item-sub">{ip} · 最終利用 {seen}</div>
  </div>
  <div class="item-actions">
    <button class="mini" type="button" data-action="revoke-session" data-id="{id}">{label}</button>
  </div>
</li>"#,
                    device = esc(&device_label(s.user_agent.as_deref())),
                    badge = badge,
                    ip = esc(ip),
                    seen = esc(&fmt_ago(s.last_seen_at)),
                    id = esc(&s.id),
                    label = if current {
                        "サインアウト"
                    } else {
                        "終了"
                    },
                )
            })
            .collect::<String>()
    };

    let consent_items = if consents.is_empty() {
        r#"<li class="empty">連携中のアプリはありません</li>"#.to_string()
    } else {
        consents
            .iter()
            .map(|c| {
                format!(
                    r#"<li class="item">
  <div class="item-main">
    <div class="item-title">{name}</div>
    <div class="item-sub">{scopes}</div>
  </div>
  <div class="item-actions">
    <button class="mini danger" type="button" data-action="revoke-consent" data-client="{id}">解除</button>
  </div>
</li>"#,
                    name = esc(&c.client_name),
                    scopes = esc(&split_scope(&c.scope).join(" · ")),
                    id = esc(&c.client_id),
                )
            })
            .collect::<String>()
    };

    let event_items = if events.is_empty() {
        r#"<li class="empty">まだイベントはありません</li>"#.to_string()
    } else {
        events
            .iter()
            .map(|e| {
                let ip = e.ip.as_deref().filter(|v| !v.is_empty());
                let meta = match ip {
                    Some(ip) => format!("{} · {}", e.detail, ip),
                    None => e.detail.clone(),
                };
                format!(
                    r#"<li class="event">
  <span class="dot" aria-hidden="true"></span>
  <div class="item-main">
    <div class="item-title">{label} <span class="item-time">{time}</span></div>
    <div class="item-sub">{meta}</div>
  </div>
</li>"#,
                    label = esc(event_label(&e.kind)),
                    time = esc(&fmt_ago(e.created_at)),
                    meta = esc(&meta),
                )
            })
            .collect::<String>()
    };

    let recovery = if !recovery_enabled {
        r#"<p class="muted small">このサーバーではリカバリーコードが無効になっています。</p>"#
            .to_string()
    } else {
        let remaining = if recovery_count > 0 {
            format!(
                r#"<p class="metric"><strong>{recovery_count}</strong><span>残りのコード</span></p>"#
            )
        } else {
            r#"<p class="metric"><strong>0</strong><span>未生成</span></p>"#.to_string()
        };
        format!(
            r#"<p class="muted small">パスキーが使えなくなったとき、リカバリーコードでサインインできます。コードは一度しか使えません。</p>
{remaining}
<button class="ghost small" id="btn-generate-recovery" type="button">新しいコードを生成</button>
<div id="recovery-output" class="codes" hidden>
  <p class="small muted">このコードは再表示できません。安全な場所に保管してください。</p>
  <ol id="recovery-list"></ol>
  <button class="mini" id="btn-copy-recovery" type="button">コピー</button>
</div>"#,
            remaining = remaining,
        )
    };

    let initial = user
        .display_name
        .chars()
        .next()
        .map(|c| c.to_uppercase().to_string())
        .unwrap_or_else(|| "?".to_string());

    let consent_count = consents.len();
    let recovery_stat = if recovery_enabled {
        recovery_count.to_string()
    } else {
        "—".to_string()
    };

    page(
        "アカウント",
        &format!(
            r#"<header class="topbar">
  <a class="brand" href="/">{brand_svg}<span>kagi</span></a>
  <form method="post" action="/account/logout">
    <button class="mini" type="submit">サインアウト</button>
  </form>
</header>

<section class="account-head">
  <div class="avatar" aria-hidden="true">{initial}</div>
  <div class="account-id">
    <h1>{name}</h1>
    <p class="muted">@{username} ・ {created} から利用</p>
  </div>
</section>

<div class="stat-strip" role="group" aria-label="アカウントの概要">
  <div class="stat"><strong>{passkey_count}</strong><span>パスキー</span></div>
  <div class="stat"><strong>{session_count}</strong><span>デバイス</span></div>
  <div class="stat"><strong>{consent_count}</strong><span>連携アプリ</span></div>
  <div class="stat"><strong>{recovery_stat}</strong><span>リカバリーコード</span></div>
</div>

<nav class="section-nav" aria-label="アカウント内のセクション">
  <a href='#profile'>プロフィール</a>
  <a href='#passkeys'>パスキー</a>
  <a href='#sessions'>デバイス</a>
  <a href='#apps'>連携アプリ</a>
  <a href='#recovery'>リカバリー</a>
  <a href='#activity'>イベント</a>
  <a href='#delete'>削除</a>
</nav>

<p class="msg" id="msg" role="status" aria-live="polite"></p>

<div class="grid">
  <section class="panel" id="profile">
    <div class="panel-head"><h2>プロフィール</h2></div>
    <form id="profile-form" class="stack" autocomplete="off">
      <label class="field">
        <span>表示名</span>
        <input id="profile-display-name" name="display_name" value="{name}" maxlength="80" required>
      </label>
      <label class="field">
        <span>メールアドレス <em>任意</em></span>
        <input id="profile-email" name="email" type="email" value="{email}" placeholder="you@example.com">
      </label>
      <button class="primary small" type="submit"><span class="label">保存</span></button>
    </form>
  </section>

  <section class="panel" id="passkeys">
    <div class="panel-head">
      <h2>パスキー</h2>
      <span class="count">{passkey_count}</span>
    </div>
    <ul class="list">{passkeys}</ul>
    <button class="ghost small" id="btn-add-passkey" type="button">パスキーを追加</button>
  </section>

  <section class="panel wide" id="sessions">
    <div class="panel-head">
      <h2>サインイン中のデバイス</h2>
      <span class="count">{session_count}</span>
    </div>
    <ul class="list">{session_items}</ul>
    <button class="ghost small" id="btn-revoke-others" type="button">他のデバイスをすべてサインアウト</button>
  </section>

  <section class="panel" id="apps">
    <div class="panel-head"><h2>連携アプリ</h2></div>
    <ul class="list">{consent_items}</ul>
  </section>

  <section class="panel" id="recovery">
    <div class="panel-head"><h2>リカバリーコード</h2></div>
    {recovery}
  </section>

  <section class="panel wide" id="activity">
    <div class="panel-head"><h2>最近のセキュリティイベント</h2></div>
    <ul class="timeline">{event_items}</ul>
  </section>

  <section class="panel wide danger-zone" id="delete">
    <div class="panel-head"><h2>アカウント削除</h2></div>
    <p class="muted small">アカウントを削除すると、パスキー・セッション・連携情報がすべて削除されます。この操作は取り消せません。</p>
    <form id="delete-form" autocomplete="off">
      <label class="field">
        <span>確認のため <code>{username}</code> と入力してください</span>
        <input id="confirm-username" name="confirm_username" autocomplete="off" required>
      </label>
      <button class="danger-btn" type="submit">アカウントを完全に削除</button>
    </form>
  </section>
</div>
{config}"#,
            brand_svg = brand_svg(),
            initial = esc(&initial),
            name = esc(&user.display_name),
            username = esc(&user.username),
            created = esc(&fmt_datetime(user.created_at)),
            email = esc(user.email.as_deref().unwrap_or("")),
            passkey_count = creds.len(),
            passkeys = passkeys,
            session_count = sessions.len(),
            session_items = session_items,
            consent_count = consent_count,
            consent_items = consent_items,
            recovery_stat = esc(&recovery_stat),
            recovery = recovery,
            event_items = event_items,
            config = config,
        ),
    )
}

/// Recovery-code sign-in. Used only when the operator enabled recovery codes.
pub fn recover_page(rid: Option<&str>) -> String {
    let config = config_script(&serde_json::json!({
        "flow": "recover",
        "rid": rid,
    }));
    page(
        "リカバリー",
        &format!(
            r#"<section class="card narrow">
{brand}
<p class="eyebrow">Recovery</p>
<h1>コードでサインイン</h1>
<p class="muted">パスキーが使えないとき、保存しておいたリカバリーコードでサインインできます。コードは一度だけ使えます。</p>
<form id="recover-form" autocomplete="off">
  <label class="field">
    <span>ユーザー名</span>
    <input id="recover-username" name="username" autocomplete="username" placeholder="alice" autofocus required>
  </label>
  <label class="field">
    <span>リカバリーコード</span>
    <input id="recover-code" name="code" autocomplete="one-time-code" placeholder="ABCDE-FGHJK"
      autocapitalize="characters" spellcheck="false" required class="code-input"
      data-code-format="recovery" aria-describedby="recover-code-hint">
    <small class="field-hint" id="recover-code-hint">10文字のコードです。小文字でも自動で大文字になります。</small>
  </label>
  <button class="primary" id="btn-recover" type="submit"><span class="label">サインイン</span></button>
</form>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<p class="foot"><a href="/login">パスキーでサインイン</a> ・ <a href="/">アカウントに戻る</a></p>
{config}
</section>"#,
            brand = brand(),
            config = config
        ),
    )
}

/// Built-in demo relying party. Demonstrates the same browser flow an external
/// site would use through `/static/kagi.js`.
pub fn demo_page(issuer: &str, seeded: bool) -> String {
    let redirect = format!("{issuer}/demo/callback");
    let config = config_script(&serde_json::json!({
        "flow": "demo",
        "issuer": issuer,
        "client_id": "demo-web",
        "redirect_uri": redirect,
        "scope": "openid profile email",
    }));

    let notice = if seeded {
        String::new()
    } else {
        r#"<p class="hint">このデモを使うには <code>KAGI_SEED_DEMO=1</code> でサーバーを起動してください。</p>"#.to_string()
    };

    let snippet = format!(
        r#"<script src="{issuer}/static/kagi.js"></script>
<script>
  Kagi.configure({{
    issuer: "{issuer}",
    clientId: "your-client-id",
    redirectUri: location.origin + "/callback"
  }});
  Kagi.login();          // 認可エンドポイントへリダイレクト (PKCE)
  // コールバックで:
  // const session = await Kagi.handleCallback();
  // const user = await Kagi.userinfo();
</script>"#
    );

    let body = format!(
        r#"<section class="card">
{brand}
<p class="eyebrow">Demo relying party</p>
<h1>kagi でサインイン</h1>
<p class="lead">このページは、kagi を自分のサイトに組み込むときの最小構成です。ボタンは実際の認可コード + PKCE フローを実行し、ID トークンと UserInfo を表示します。</p>
{notice}
<div class="actions">
  <button class="primary" id="demo-login" type="button"><span class="label">kagi でサインイン</span></button>
  <button class="ghost" id="demo-logout" type="button" hidden>サインアウト</button>
</div>
<p class="msg" id="msg" role="status" aria-live="polite"></p>
<pre id="demo-output" hidden></pre>
<hr class="rule">
<h2>組み込み方</h2>
<p class="muted">任意のサイトに次の 2 行を置くだけです。クライアントは <code>/register</code> または管理画面から登録します。</p>
<pre><code>{snippet}</code></pre>
<p class="hint">コールバック URL はクライアント登録時の <code>redirect_uris</code> と完全一致している必要があります。</p>
{config}
</section>"#,
        brand = brand(),
        notice = notice,
        snippet = esc(&snippet),
        config = config
    );

    format!(
        r#"<!doctype html>
<html lang="ja">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="robots" content="noindex, nofollow">
<meta name="description" content="kagi — パスキーでサインインできる OIDC アイデンティティプロバイダー。">
<meta name="theme-color" content='#ffffff' media="(prefers-color-scheme: light)">
<meta name="theme-color" content='#0a0a0a' media="(prefers-color-scheme: dark)">
<title>デモ · kagi</title>
<link rel="stylesheet" href="/static/style.css">
<script src="/static/theme.js"></script>
</head>
<body>
<a class="skip-link" href='#main'>本文へスキップ</a>
<main class="shell" id="main" tabindex="-1">
{body}
</main>
{theme}
<script src="/static/kagi.js?v=2"></script>
<script src="/static/app.js" defer></script>
</body>
</html>
"#,
        body = body,
        theme = theme_toggle()
    )
}
