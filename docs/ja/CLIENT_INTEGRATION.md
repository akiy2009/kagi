# クライアント連携

このガイドでは、Web アプリケーション（RP: Relying Party）が Kagi Identity を IdP として利用する手順を説明します。本番アプリでは、メンテナンスされている OIDC クライアントライブラリの利用を推奨します。組み込み SDK は最小限のデモ用であり、自前の認証ロジックを実装する際は自分の脅威モデルと照合してください。

## 1. クライアントを登録する

コールバック URI は**完全一致**で登録します。スキーム、ホスト、ポート、パス、末尾スラッシュまで一致させる必要があります。ワイルドカードは使用できません。

ローカルデモでは `demo-web` が自動登録されます。新しいパブリッククライアントは、管理トークンで保護された動的クライアント登録エンドポイント（`POST /register`）で登録します。

```bash
export KAGI_REGISTRATION_TOKEN='秘密管理領域から取得した値'
curl --fail-with-body --request POST 'https://id.example.com/register' \
  --header "Authorization: Bearer $KAGI_REGISTRATION_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{
    "client_name": "Example Web App",
    "redirect_uris": ["https://app.example.com/auth/callback"],
    "post_logout_redirect_uris": ["https://app.example.com/"],
    "grant_types": ["authorization_code", "refresh_token"],
    "scope": "openid profile email offline_access",
    "token_endpoint_auth_method": "none"
  }'
```

- `token_endpoint_auth_method` は `none`（パブリック）、`client_secret_basic`、`client_secret_post`、`private_key_jwt` のいずれかです。
- `private_key_jwt` を使う場合は、秘密鍵を含まない**公開 JWK Set** を `jwks` にインラインで指定します。`jwks_uri` は SSRF 回避のため受け付けません。
- `redirect_uris` は HTTPS 必須です。HTTP は `localhost`、`127.0.0.0/8`、`::1` などの実際のループバックホストに限り許可されます。`http://localhost.evil.example` のような紛らわしいホストは拒否されます。
- `scope` には `openid` が必須です。
- `client_name` は 1〜120 文字の印刷可能文字です。

登録レスポンスは機密情報として扱ってください。クライアントシークレットが発行された場合、ログに残さないでください。

パブリッククライアント（ブラウザー / モバイル）はシークレットを秘匿できないため、**Authorization Code + PKCE（S256）** を必ず使用します。機密クライアントは信頼できるバックエンドでトークン交換を行い、対応するクライアント認証方式を使ってください。

## 2. ブラウザー SDK の最小例

Kagi Identity のオリジンから SDK を読み込みます。

```html
<script src="https://id.example.com/static/kagi.js"></script>
<button id="sign-in" type="button">サインイン</button>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  document.querySelector("#sign-in").addEventListener("click", () => {
    Kagi.login();
  });
</script>
```

コールバックルートでは、同じ issuer / clientId / redirectUri を設定してからコールバックを処理します。

```html
<script src="https://id.example.com/static/kagi.js"></script>
<script>
  Kagi.configure({
    issuer: "https://id.example.com",
    clientId: "YOUR_CLIENT_ID",
    redirectUri: location.origin + "/auth/callback",
    scope: "openid profile email"
  });

  (async () => {
    const session = await Kagi.handleCallback();
    const profile = await Kagi.userinfo();
    // アプリに必要なプロフィール項目だけを描画する
    console.log({ subject: profile.sub, session });
  })();
</script>
```

SDK の API は変更される可能性があります。デプロイするコミットの `/demo` と `static/kagi.js` を確認してください。コールバックが成功しただけでは不十分です。アプリケーションに必要なトークン検証とプロトコル要件を必ず実施してください。

## 3. Discovery と署名鍵

エンドポイントをハードコードせず、Discovery ドキュメントから取得します。

```bash
curl --fail 'https://id.example.com/.well-known/openid-configuration'
curl --fail 'https://id.example.com/jwks.json'
```

- `issuer` は設定した公開 Issuer と完全一致する必要があります。
- JWKS は RP ライブラリの指針に従ってキャッシュし、未知の `kid` に遭遇したら再取得できるようにします。単一の署名鍵を無期限にピン留めしないでください。
- ID トークンは、署名、`iss`、`aud`（自分の client_id）、`exp`、`nonce`、`state` を検証します。
- アクセストークンは UserInfo などの保護リソースで検証されます。RP 側で JWT を独自検証する場合も `typ`、`iss`、`aud`、期限を確認してください。

### Discovery で確認できる主なメタデータ

| 項目 | 内容 |
| --- | --- |
| `issuer` | 公開 Issuer |
| `authorization_endpoint` / `token_endpoint` | 認可・トークンエンドポイント |
| `pushed_authorization_request_endpoint` | PAR エンドポイント（RFC 9126） |
| `code_challenge_methods_supported` | `S256` のみ |
| `acr_values_supported` | `urn:kagi:acr:passkey` / `urn:kagi:acr:recovery` |
| `prompt_values_supported` | `none` / `login` / `consent` / `select_account` |
| `device_authorization_endpoint` | RFC 8628 デバイス認可エンドポイント |
| `backchannel_logout_supported` / `backchannel_logout_session_supported` | Back-Channel Logout 対応 |
| `claims_parameter_supported` | `true`（対応クレームは後述） |

## 4. 任意の OIDC 機能

以下は実装済みですが任意機能です。利用する前に、デプロイするコミットと設定で実際にどう動くかを確認してください。機能があること自体は、規範への適合や認証を意味しません。

### 特定のクレームを要求する（`claims` パラメーター）

標準の `claims` パラメーターに JSON を渡します。対応するのは `sub`、`auth_time`、`acr`、`amr`、`sid`、`name`、`preferred_username`、`email`、`email_verified`、`iss` です。未知の名前、過大な値、`acr` 以外への `value` / `values` は拒否されます。スコープが外側の境界であり、付与されていないスコープの必須クレームを要求した場合は、不完全なトークンを返さず認可エラーになります。

```json
{
  "id_token": { "email": { "essential": true } },
  "userinfo": { "name": null }
}
```

`userinfo` を指定した場合、UserInfo はそこに列挙したクレームだけを返します。`email_verified` が必要なら明示的に要求してください。

### デバイス認可グラント（RFC 8628）

テレビ、CLI など入力が難しい端末向けです。クライアントの `grant_types` に `urn:ietf:params:oauth:grant-type:device_code` を含めて登録します。

```bash
curl --fail-with-body 'https://id.example.com/device_authorization' \
  --data-urlencode 'client_id=YOUR_CLIENT_ID' \
  --data-urlencode 'scope=openid profile offline_access'
# -> device_code, user_code, verification_uri, expires_in, interval

curl --fail-with-body 'https://id.example.com/token' \
  --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:device_code' \
  --data-urlencode 'device_code=DEVICE_CODE' \
  --data-urlencode 'client_id=YOUR_CLIENT_ID'
```

利用者には `user_code` と `verification_uri` を表示します。ポーリングは `interval` 秒以上あけ、`authorization_pending` と `slow_down` を処理します（`slow_down` 後は 5 秒延ばす）。コードは 1 回限りで、`KAGI_DEVICE_TTL`（既定 600 秒）で失効します。

### クライアント管理（RFC 7592）

登録レスポンスには `registration_access_token` と `registration_client_uri` が含まれます。トークンは一度しか表示されず、サーバーにはハッシュだけが保存されるため、秘密として保管してください。

```bash
export REGISTRATION_ACCESS_TOKEN='登録レスポンスの値'

curl --fail-with-body 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN"

curl --fail-with-body --request PUT 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{"redirect_uris":["https://app.example.com/auth/callback"],
           "backchannel_logout_uri":"https://app.example.com/oidc/logout"}'

# クライアントシークレットをローテーションする（新しい値は一度だけ返る）
curl --fail-with-body --request PUT 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN" \
  --header 'Content-Type: application/json' \
  --data '{"rotate_client_secret":true,
           "redirect_uris":["https://app.example.com/auth/callback"]}'

curl --fail-with-body --request DELETE 'https://id.example.com/register/CLIENT_ID' \
  --header "Authorization: Bearer $REGISTRATION_ACCESS_TOKEN"
```

削除すると、そのクライアントのトークン、同意、デバイスグラント、保留中のフローも削除されます。更新のたびに redirect URI、スコープ、グラント種別、JWKS、Back-Channel URI が再検証されます。

### Back-Channel Logout 1.0

登録時または管理更新で `backchannel_logout_uri` を登録します。ブラウザーセッションが終了すると（サインアウト、セッション失効、アカウント削除）、Kagi は署名済みの `logout_token` を `application/x-www-form-urlencoded` で POST します。

- `iss`、`aud`、`iat`、`jti`、`sub`、および `http://schemas.openid.net/event/backchannel-logout` を含む `events` を検証します。
- 現在の JWKS で署名を検証し、`jti` の再利用を拒否します。
- `backchannel_logout_session_required` が true の場合、トークンには `sid` が含まれるため RP のセッションと照合します。
- 配信はベストエフォートです。Kagi はリダイレクト、URL 内の資格情報、本番での非 HTTPS、プライベート / リンクローカルアドレスを拒否します。ループバック HTTP はローカル開発時のみ許可されます。

## 5. 認可リクエストの例

```text
GET https://id.example.com/authorize?
  client_id=YOUR_CLIENT_ID
  &redirect_uri=https%3A%2F%2Fapp.example.com%2Fauth%2Fcallback
  &response_type=code
  &scope=openid%20profile%20email%20offline_access
  &state=RANDOM_STATE
  &nonce=RANDOM_NONCE
  &code_challenge=BASE64URL_SHA256_OF_VERIFIER
  &code_challenge_method=S256
```

PAR を使う場合は、まず `POST /par` に同じパラメーターを送り、返却された `request_uri` を `/authorize` に渡します。`KAGI_REQUIRE_PAR=1` の環境では PAR が必須です。

DPoP を使う場合は、`/par` と `/token` の両方に `DPoP` ヘッダーで証明を付けます。トークン応答の `token_type` は `DPoP` になり、`/userinfo` では `ath`（アクセストークンのハッシュ）を含む証明が必要です。

## 6. リダイレクトとトークンの安全性

- redirect URI は完全一致で登録し、ワイルドカードを使わない。
- Authorization Code + PKCE（S256）を使い、Implicit フローを使わない。
- `state` と `nonce` は暗号学的にランダムな値にし、コールバックで検証する。
- トークンをクエリ文字列、分析イベント、アプリケーションログに含めない。
- 長期間有効な資格情報をブラウザーから読める永続ストレージに置かない。
- アクセストークンは短命にし、必要なスコープだけを要求する。
- サーバー側セッションを使う場合、トークンはバックエンドに保持し、アプリのセッション Cookie には `Secure`、`HttpOnly`、適切な `SameSite` を設定する。
- 認可コードは 1 回しか使えない。交換に失敗した場合も、同じコードを再利用しない。
- リフレッシュトークンはローテーションされる。古いトークンを再利用するとファミリー全体が失効する。

組み込み SDK は評価用の便宜的な手段であり、本番の認証ロジックを手書きすることを推奨するものではありません。
