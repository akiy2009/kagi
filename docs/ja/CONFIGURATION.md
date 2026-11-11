# 設定リファレンス

すべての設定値はプロセス起動時に読み込まれます。変更後は Kagi Identity を再起動してください。空または未設定の値は、原則として `src/config.rs` の既定値にフォールバックします。

> 秘密情報（`KAGI_ADMIN_TOKEN`、`KAGI_REGISTRATION_TOKEN`、`KAGI_DATABASE_URL` など）はソースコードや `.env` のコミットで管理せず、秘密管理領域に置いてください。

## 基本設定

| 変数 | 既定値 | 意味 |
| --- | --- | --- |
| `KAGI_ENV` | `development`（Vercel では `production`） | `development` / `test` / `production`。`production` では HTTPS、PostgreSQL、Secure Cookie / HSTS、PAR、信頼済みプロキシ、レート制限、デモ無効、自動マイグレーション無効、十分な強度の管理・登録トークンが必須になります。1 つでも欠けると起動に失敗します。 |
| `KAGI_ISSUER` | `http://localhost:8080` | 公開 Issuer オリジン。パス、クエリ、フラグメント、末尾スラッシュは禁止です。 |
| `KAGI_BIND` | `127.0.0.1:8080` | バインドするアドレスとポート。コンテナでは `0.0.0.0:8080` を使います。 |
| `KAGI_RP_ID` | Issuer から導出したホスト | WebAuthn の RP ID。スキームやポートを含まないベアホスト名 / ドメインです。 |
| `KAGI_RP_NAME` | `Kagi Identity` | パスキー UI に表示されるサービス名。 |
| `KAGI_ORIGIN` | Issuer と同じ | WebAuthn 検証で期待するブラウザーオリジン。 |
| `KAGI_DB` | `kagi.db` | SQLite データベースのパス。 |
| `KAGI_DATABASE_URL` | 未設定 | PostgreSQL / Supabase の接続文字列。設定時は `KAGI_DB` より優先されます。 |
| `KAGI_AUTO_MIGRATE` | `1` | 起動時にスキーマを適用します。サーバーレス本番では一度だけ手動適用し、`0` にしてください。 |
| `DATABASE_URL` | 未設定 | `KAGI_DATABASE_URL` が未設定のときの PostgreSQL フォールバック。 |

## 機能とポリシー

| 変数 | 既定値 | 意味 |
| --- | --- | --- |
| `KAGI_ALLOW_SIGNUP` | `1` | セルフサービス登録を許可します。 |
| `KAGI_SEED_DEMO` | `0` | 開発用 `demo-web` クライアントを登録します。本番では無効にしてください。 |
| `KAGI_REQUIRE_PAR` | `0` | Pushed Authorization Request を必須にします。 |
| `KAGI_REQUIRE_DPOP` | `0` | 対象フローで DPoP を必須にします。 |
| `KAGI_ADMIN_TOKEN` | 未設定 | `/admin/keys/rotate` と `/admin/stats` を保護する Bearer トークン。未設定時は無効化されます。 |
| `KAGI_REGISTRATION_TOKEN` | 未設定 | 動的クライアント登録に必要な initial access token。未設定時は登録を拒否します。 |
| `KAGI_CORS_ORIGINS` | 未設定 | API 呼び出しを許可する HTTPS オリジンのカンマ区切りリスト。ワイルドカードは拒否されます。 |
| `KAGI_COOKIE_SECURE` | HTTPS Issuer から導出 | Cookie に `Secure` を付与します。HTTPS では `__Host-kagi_sid`、HTTP では `kagi_sid` を使います。 |
| `KAGI_HSTS` | HTTPS Issuer から導出 | HSTS ヘッダーを出力します。HTTPS が正しく終端されている場合のみ有効にしてください。 |
| `KAGI_TRUST_PROXY` | `0` | `X-Forwarded-For` の先頭ホップを信頼します。ヘッダーを上書きするプロキシの直後でのみ有効にしてください。 |
| `KAGI_RATE_LIMIT` | `1` | PostgreSQL の原子的カウンタによる共有レート制限を有効にします。 |
| `KAGI_RECOVERY_ENABLED` | `1` | パスキー代替の単回使用リカバリーコードを有効にします。 |
| `KAGI_MAX_PASSKEYS` | `10` | 1 アカウントあたりの最大パスキー数（1〜100 に丸め）。 |
| `KAGI_AUDIT_RETENTION_DAYS` | `90` | 監査イベントの保持日数。`0` は無期限。 |

## 有効期限

すべて秒単位で、正の値が必要です。ただしアイドル TTL は `0` でアイドル失効を無効化できます。

| 変数 | 既定値 | 意味 |
| --- | ---: | --- |
| `KAGI_SESSION_TTL` | `28800` | ブラウザーセッションの絶対有効期限（8 時間）。 |
| `KAGI_SESSION_IDLE_TTL` | `7200` | アイドルタイムアウト（2 時間）。`0` で無効。 |
| `KAGI_CODE_TTL` | `60` | 認可コードの有効期限。 |
| `KAGI_ACCESS_TTL` | `300` | アクセストークンの有効期限（5 分）。 |
| `KAGI_REFRESH_TTL` | `2592000` | リフレッシュトークンの有効期限（30 日）。 |
| `KAGI_ID_TTL` | `300` | ID トークンの有効期限（5 分）。 |
| `KAGI_PAR_TTL` | `90` | PAR の `request_uri` の有効期限。 |
| `KAGI_DEVICE_TTL` | `600` | RFC 8628 デバイスコードの有効期限。 |
| `KAGI_DEVICE_INTERVAL` | `5` | デバイスの最小ポーリング間隔（秒）。早すぎるポーリングは `slow_down` になり、間隔が 5 秒延びます。 |

## 本番環境のベースライン例

以下は出発点であり、完全なセキュリティポリシーではありません。ドメインを置き換え、秘密情報は秘密管理領域に保存してください。

```dotenv
KAGI_ENV=production
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
KAGI_ADMIN_TOKEN=秘密管理領域から取得
KAGI_REGISTRATION_TOKEN=秘密管理領域から取得
```

## 本番起動時のフェイルクローズ

`KAGI_ENV=production`（または Vercel 上の実行）では、次の条件を満たさない限り起動しません。

- `KAGI_ISSUER` と `KAGI_ORIGIN` が HTTPS かつ同一オリジン
- PostgreSQL が設定されている
- Secure Cookie と HSTS が有効
- デモ登録が無効
- PAR が必須
- 信頼済みプロキシが有効
- レート制限が有効
- 正確な HTTPS の CORS 許可リストが設定されている
- 管理トークンと登録トークンが十分な長さの異なるランダム値

`compose.production.yaml` と `.env.production.example` は、Caddy + Docker のセルフホスト用ベースラインを提供します。厳格なフラグは適合テストの代わりにはなりません。

## 設定変更時の注意

- `KAGI_ISSUER`、`KAGI_ORIGIN`、`KAGI_RP_ID` は必ず整合させてください。1 つでもずれるとパスキーのセレモニーが失敗します。
- Issuer を変更すると、既存トークンの `iss` と一致しなくなり、すべて無効になります。
- `KAGI_DATABASE_URL` を切り替える場合は、事前に `supabase/schema.sql` を適用し、データ移行とバックアップを確認してください。
- レート制限のカウンタはデータベース共有です。テスト時はスイートごとにデータベースを分けてください。
