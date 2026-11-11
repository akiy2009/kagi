# テストと検証

テストは必ず分離された開発用データベースとローカルサーバーに対して実行してください。一部の E2E スクリプトはデータベースへ直接テスト行を挿入します。**本番データへ向けないでください。**

## 1. Rust の品質チェック

`Cargo.toml` がサポートする Rust ツールチェーンをインストールし、次を実行します。

```bash
cargo check --locked --all-targets
cargo test --locked --all-targets
cargo clippy --locked --all-targets
cargo build --locked --release
```

Vercel デプロイ用のガードレール検査も実行します。

```bash
python scripts/check_vercel_security.py
```

現時点でユニットテストは 40 件です。テストの追加・変更に応じて件数は増減します。

## 2. Python テスト依存関係のインストール

```bash
python -m venv .venv
# Linux / macOS
. .venv/bin/activate
# Windows PowerShell
.venv\Scripts\Activate.ps1
python -m pip install -r requirements-test.txt
```

`requirements-test.txt` には `requests`、`cryptography`、PostgreSQL を使う場合の `psycopg2-binary` が含まれます。

## 3. ローカルサーバーの起動

専用のテストデータベースを使い、デモクライアントを有効にします。1 つのターミナルで起動したままにします。

```bash
KAGI_SEED_DEMO=1 \
KAGI_ADMIN_TOKEN=test-admin \
KAGI_REGISTRATION_TOKEN=reg-secret \
KAGI_RECOVERY_ENABLED=1 \
KAGI_DEVICE_INTERVAL=1 \
KAGI_DB=kagi-e2e.db \
cargo run --locked
```

別のターミナルで、データベースへ直接書き込むテストには同じ `KAGI_DB` を指定します。

```bash
KAGI_DB=kagi-e2e.db python scripts/e2e_oidc.py
KAGI_DB=kagi-e2e.db python scripts/e2e_advanced.py
KAGI_DB=kagi-e2e.db python scripts/e2e_security_races.py
KAGI_DB=kagi-e2e.db KAGI_REGISTRATION_TOKEN=reg-secret python scripts/e2e_complete_oidc.py
python scripts/e2e_rate_limit.py
python scripts/e2e_webauthn.py
python scripts/e2e_admin.py
```

スイートは 1 つずつ、新しいデータベースと起動し直したサーバーで実行してください。レート制限はプロセス単位で、Back-Channel Logout のテストはループバックの受信サーバーを立てるため、共有サーバーだと後の実行が不安定になります。`e2e_complete_oidc.py` はサーバーと同じ `KAGI_REGISTRATION_TOKEN` を必要とし、`KAGI_DEVICE_INTERVAL=1` にするとポーリングテストが短時間で終わります。

アカウント系は登録トークンを無効にした状態を想定します。

```bash
KAGI_SEED_DEMO=1 \
KAGI_RECOVERY_ENABLED=1 \
KAGI_ADMIN_TOKEN=test-admin \
KAGI_DB=kagi-account.db \
cargo run --locked
python scripts/e2e_account.py
```

- 管理系テストは上記の開発専用値（`test-admin` / `reg-secret`）を前提にしています。分離されたローカルテスト以外で再利用しないでください。
- WebAuthn のソフトウェア認証器テストは、既定のローカルオリジン（`http://localhost:8080`）と RP ID（`localhost`）を前提にしています。
- Windows では PowerShell で環境変数を設定するか、WSL / Linux コンテナで実行してください。POSIX のシェル構文を PowerShell へそのままコピーしないでください。

## 4. E2E スクリプトのカバレッジ

| スクリプト | 主な対象 |
| --- | --- |
| `e2e_oidc.py` | PAR、同意、PKCE、トークン、UserInfo、Introspection、リフレッシュローテーション / 再利用検出、失効、`prompt` 挙動、DPoP 束縛、`form_post` の CSP |
| `e2e_advanced.py` | JARM、PAR → code → token をまたぐ DPoP 鍵継続、CORS プリフライト、`max_age=0` |
| `e2e_webauthn.py` | ソフトウェア認証器によるパスキー登録 / サインイン、challenge / origin / type 検証、署名改ざん・カウンタ巻き戻しの拒否 |
| `e2e_admin.py` | 動的登録のゲート、`private_key_jwt`、JAR、鍵ローテーション、ログアウトリダイレクト検証、危険な redirect URI / 秘密 JWK / 不正 post-logout URI の拒否 |
| `e2e_account.py` | プロフィール更新、パスキー追加 / 名前変更 / 削除、複数セッションと一括失効、同意取消、リカバリーコード生成と単回使用、クロスオリジン POST 拒否、`/healthz`、`/admin/stats`、アカウント削除 |
| `e2e_complete_oidc.py` | RFC 8628 デバイス認可（承認・拒否・ポーリング・`slow_down`）、`claims` の検証とトークン / UserInfo のフィルタリング、RFC 7592 クライアント管理とシークレットローテーション、署名済み Back-Channel Logout の配信 |
| `e2e_security_races.py` | 同時認可コード交換、同時 DPoP 証明リプレイ、鍵ローテーション / JWKS の重複期間、Discovery メタデータ、同時同意でコードが 1 個だけ発行されること、`acr_values` の強制 |
| `e2e_rate_limit.py` | 共有固定ウィンドウレート制限と HTTP 429 / `Retry-After` |

セキュリティレースのスクリプトは、同時認可コード交換が正確に 1 回だけ成功し、共有 DPoP 証明が 1 回だけ受理されることを確認します。これらは回帰テストであり、完全な規範テストスイートではありません。

## 5. PostgreSQL / Supabase での実行

サーバー側の `KAGI_DATABASE_URL` を設定すると、同じ E2E スクリプトが PostgreSQL でも動作します。テスト側にも同じ `KAGI_DATABASE_URL` を渡してください。

```bash
export KAGI_DATABASE_URL='postgresql://kagi@127.0.0.1:5432/kagi_e2e'
KAGI_SEED_DEMO=1 KAGI_ADMIN_TOKEN=test-admin KAGI_REGISTRATION_TOKEN=reg-secret \
  cargo run --locked
KAGI_DATABASE_URL="$KAGI_DATABASE_URL" python scripts/e2e_oidc.py
```

注意点:

- レート制限カウンタはデータベース共有です。**スイートごとに新しいデータベースを作成**してください。前のスイートのカウンタが残ると誤検知します。
- `/register` はレート制限（既定 5 回/分）の対象です。1 つのスイートで 5 回を超えて登録しないでください。
- 複数のサーバーを同時に起動するとポート 8080 を奪い合い、誤検知の原因になります。E2E は 1 つずつ順次実行してください。
- テスト用データベースには実際のユーザーデータや本番の鍵を含めないでください。

## 6. OAuth / OIDC 適合性は別工程

ユニットテストと統合テストは、このリポジトリが実装したシナリオだけを検証します。OAuth 2.1、OpenID Connect Core、FAPI 2.0、WebAuthn、その他の認証プロファイルへの完全な適合を証明するものではありません。本番利用前に:

1. 対象プロファイルとバージョンを決める。
2. デプロイ構成に対して公式 / コミュニティの適合テストスイートを実行する。
3. 失敗・スキップされたテストをすべてレビューする。緑のバッジのために失敗を抑制しない。
4. 並行性とデプロイ境界を含む独立したセキュリティレビューを依頼する。
5. テストしたコミット、設定、テストスイートのバージョンをリリース証跡に記録する。

## 7. CI

GitHub Actions では次を実行します。

- `cargo check --locked --all-targets`
- `cargo test --locked --all-targets`
- `cargo clippy --locked --all-targets`
- `rustfmt --check api/index.rs`
- `scripts/e2e_security_races.py` と `scripts/e2e_rate_limit.py`
- ドキュメントサイト、RP デモ、Vercel ガードレール、Docker Compose のスモークテスト
- Rust 依存関係の脆弱性監査

CI の成功は、その CI で実行された範囲だけを証明します。実ブラウザー、実ホスト、本番データでの動作を自動的に保証するものではありません。
