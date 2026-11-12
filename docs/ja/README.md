# Kagi Identity 日本語ドキュメント

Kagi Identity（Kagi ID）は、Rust で実装されたパスキー中心の認証基盤です。WebAuthn によるパスキー登録・サインインと、OpenID Connect / OAuth 2.1 のエンドポイントを提供します。アプリケーションは認証を Kagi Identity に委譲し、認可コードフローの結果だけを受け取ります。

> **重要:** 本リポジトリは開発中のリファレンス実装です。CI の成功やデモの動作は、OIDC / OAuth / FAPI / WebAuthn の適合認証や本番運用の安全性を保証しません。公開前には脅威モデル、独立したセキュリティレビュー、対象プロファイルの適合テストを実施してください。

## はじめに読む順番

目的に合わせて次のガイドを参照してください。

| 目的 | ガイド |
| --- | --- |
| 数分でローカル環境を動かす | [クイックスタート](QUICKSTART.md) |
| アカウントコンソールとリカバリーコードを知る | [アカウント管理](ACCOUNT.md) |
| 自分の Web アプリと連携する | [クライアント連携](CLIENT_INTEGRATION.md) |
| 環境変数を確認する | [設定リファレンス](CONFIGURATION.md) |
| HTTPS 環境へデプロイする | [デプロイガイド](DEPLOYMENT.md) |
| テストとセキュリティ検証を行う | [テストと検証](TESTING.md) |
| 脆弱性を報告する | [セキュリティポリシー](SECURITY.md) |

英語の一次ドキュメントは [`docs/`](../README.md) にあります。実装と設定の最終的な正解は、デプロイするコミットのソースコードです。

## このプロジェクトが提供するもの

| 領域 | 機能 |
| --- | --- |
| 認証 | WebAuthn パスキー登録・サインイン、discoverable credential、conditional UI、`none` / `packed` 自己証明、署名カウンタによるクローン検出、BE/BS フラグ |
| 認可 | Authorization Code フロー、PKCE S256、state / nonce、同意画面、`prompt=none/login/consent/select_account`、同意の記憶、`max_age`、RFC 9207 の `iss`、OIDC `claims` パラメーター |
| OAuth / OIDC | Discovery、JWKS、UserInfo、Introspection、Revocation、RP-initiated Logout、動的クライアント登録（RFC 7591）、クライアント管理（RFC 7592）、デバイス認可グラント（RFC 8628）、Back-Channel Logout 1.0 |
| 高度なプロファイル | PAR（RFC 9126）、DPoP（RFC 9449、`cnf.jkt` / `ath` / `jti` リプレイ防止）、JAR（RFC 9101）、JARM（`response_mode=jwt/query.jwt/fragment.jwt`） |
| クライアント認証 | `client_secret_basic`、`client_secret_post`、`private_key_jwt`（RS256 / PS256 / ES256 / EdDSA）、パブリッククライアント |
| トークン | ES256 署名の JWT アクセストークン（`typ: at+jwt`）、リフレッシュトークンローテーションと再利用検出（ファミリー失効）、`at_hash`、`sid` |
| 鍵管理 | 署名鍵の永続化、JWKS 公開、管理トークンによる鍵ローテーションと猶予期間 |
| ストレージ | 既定は SQLite。`KAGI_DATABASE_URL` で PostgreSQL / Supabase に切り替え |
| 連携 | 組み込みデモ RP、ブラウザー SDK（`/static/kagi.js`）、CORS 制御された API |
| アカウントコンソール | プロフィール編集、パスキーの追加・名前変更・削除、端末（セッション）一覧と一括サインアウト、連携アプリの同意取消、リカバリーコード、監査イベント、アカウント削除 |
| UI / アクセシビリティ | 白黒基調のレスポンシブ UI、自動 / ライト / ダークテーマ（端末内に保存）、キーボードフォーカス、スキップリンク、reduced-motion 対応、ワンタイムコードの自動整形、処理中のインライン表示 |
| 運用 | レート制限、監査ログ、`/healthz` / `/readyz`（DB 検査付き）、`/admin/stats`、起動時の設定検証 |
| セキュリティ制御 | PKCE 強制、redirect URI の完全一致、Origin + `Sec-Fetch-Site` 検証、CSRF トークン、CSP / HSTS / COOP / CORP / Permissions-Policy、HttpOnly + SameSite=Lax セッション、保存時の SHA-256、SSRF 対策済み Back-Channel 配信 |

機能の存在は、各 RFC の全要件や認証プロファイルへの適合を意味しません。デプロイするコミットと設定で実際に確認してください。

### 任意の拡張機能

- **デバイス認可グラント（RFC 8628）**: 入力が難しい端末向けに `/device_authorization` と `/device` の承認画面を提供します。コードはハッシュのみ保存し、1 回限り・レート制限付きです。
- **クライアント管理（RFC 7592）**: 登録時に発行される `registration_access_token` で `GET` / `PUT` / `DELETE /register/{client_id}` を呼び出し、メタデータ更新、シークレットローテーション、削除ができます。
- **`claims` パラメーター**: ID トークンと UserInfo で要求するクレームを指定できます。未知のクレーム、過大な値、スコープ外の必須クレームは拒否されます。
- **Back-Channel Logout 1.0**: セッション終了時に署名済み `logout_token` を RP へ配信します。本番では HTTPS のみ、プライベート / リンクローカル宛先は拒否されます。

詳細とリクエスト例は [クライアント連携](CLIENT_INTEGRATION.md) を参照してください。

## 設計上の要点

- **パスワードを持たない。** ユーザー認証はパスキー（WebAuthn）のみです。復旧手段として単回使用のリカバリーコードを任意で有効化できます。
- **秘密はハッシュで保存。** 認可コード、リフレッシュトークン、セッション ID は SHA-256 ハッシュのみを保存します。アクセストークンは JWT ですが、`jti` を保存して即時失効と Introspection を可能にします。
- **クライアントシークレットは SHA-256。** 32 バイトのランダム値をサーバーが生成するため、オフライン総当たりの対象になりません。Argon2 を使う理由がないため認証遅延を一定に保っています。
- **DPoP はコード発行時点で束縛。** `dpop_jkt` を認可コードに記録し、トークン交換時に照合します。DPoP 束縛トークンを `Bearer` で提示した場合（またはその逆）は RFC 9449 §7.1 に従い 401 を返します。
- **同意はサーバー側に保存。** `prompt=none` は「セッションなし → `login_required`」「同意なし → `consent_required`」「両方あり → コード発行」の順で解決します。新しいスコープには再同意が必要です。
- **単一ノード前提の部分がある。** プロセス内キャッシュ（署名鍵・一部レート制限）は複数インスタンス間で完全共有されません。`request_uri` は `urn:ietf:params:oauth:request_uri:*` のみを受け付け、HTTPS フェッチによる SSRF を避けています。CIBA と SD-JWT VC は未実装です。

## ライセンス

Kagi Identity は **MIT License** で公開されているオープンソースソフトウェアです。全文はリポジトリ直下の [`LICENSE`](../../LICENSE) を参照してください。

- 商用利用、改変、再配布、サブライセンス、販売が可能です。
- 再配布時は著作権表示とライセンス全文を含めてください。
- 本ソフトウェアは「現状のまま」提供され、明示・黙示の保証はありません。

コントリビューションを歓迎します。変更を送る前に [テストと検証](TESTING.md) と [セキュリティポリシー](SECURITY.md) を確認してください。
