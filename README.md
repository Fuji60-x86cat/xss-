
> **単一・複数入力フォーム向け 簡易XSS脆弱性診断スクリプト
> メディアデザインプロジェクトⅣ 開発成果物

---

## 1. 概要 (Overview)
- **対象ユーザー**: Webアプリケーション開発者およびセキュリティ初学者
- **解決する課題**: Web開発時の手動でのペイロード送信・レスポンス目視確認によるテスト工数の削減と、サニタイズ（エスケープ）漏れの防止。
- **機能概要**: 指定したURLとパラメータに対し、XSS検知用のテストパターン（マーカー付きペイロード）を自動順次送信し、レスポンス内の文字列反射およびエスケープ処理の有無を判定してリスクを一次スクリーニングします。

---

## 2. ディレクトリ構成 & 役割分担

```
NIT/
├── README.md                   # 本ドキュメント (プロジェクト仕様・利用手順)
├── requirements.txt            # 依存Pythonライブラリ (requests, flask)
├── xss_scanner.py              # メイン実行スクリプト (CLI引数パース・全体制御)
│
├── modules/                    # 機能モジュール群
│   ├── __init__.py
│   ├── payload_manager.py      # 【担当A】 XSSテスト用ペイロード管理・マーカー生成
│   ├── requester.py            # 【担当B】 HTTPリクエスト通信処理 (GET/POST, Session)
│   ├── analyzer.py             # 【担当B】 レスポンス解析・反射/エスケープ差分判定
│   ├── reporter.py             # 【担当C】 診断結果出力 (ターミナル表出力・CSV出力)
│   └── logger_config.py        # 【担当C】 通信ログ・システムログ記録 (logging)
│
├── test_server/                # 検証用ローカルWeb環境
│   ├── app.py                  # 【担当A】 検証用Flaskアプリ (脆弱/対策済エンドポイント)
│   └── templates/
│       └── index.html          # 検証用UIポータル画面
│
└── tests/                      # 単体テスト群
    ├── __init__.py
    └── test_scanner.py         # ユニットテスト (判定ロジック・CSV出力等の結合確認)
```

### 役割分担詳細
| 担当 | 主な担当内容 | 実装ファイル |
| :--- | :--- | :--- |
| **メンバーA** | 検証用テストページ（脆弱/安全なフォーム）の作成、XSSテスト用ペイロードリストの選定と作成 | `test_server/app.py`, `modules/payload_manager.py` |
| **メンバーB** | HTTPリクエスト送信部（通信処理）の実装、レスポンス分析・差分検出ロジック（判定処理）の実装 | `modules/requester.py`, `modules/analyzer.py` |
| **メンバーC** | 診断結果の出力（CSV出力・コンソール表表示）機能の実装、通信ログ（logging）機能の実装 | `modules/reporter.py`, `modules/logger_config.py` |
| **共同作業** | システム全体設計、CLIインタフェース結合、総合動作確認および判定精度の調整 | `xss_scanner.py`, `tests/test_scanner.py` |

---

## 3. 実現機能一覧

### 【必須機能】
1. **スキャン条件の指定機能 (`--url`, `--param`, `--method`)**:
   - コマンドライン引数から対象URL、検査パラメータ名、HTTPメソッド(GET/POST)を指定可能。
2. **ペイロードの自動送信機能**:
   - 一意のランダムマーカー文字列を含む10種類のXSSテストパターン（`<script>`, `<img>`, `<svg>`, 属性抜け出し `">`, JS抜け出し `';` 等）を自動生成して順次送信。
3. **レスポンス分析・差分検知機能**:
   - 生のタグがそのまま反射しているか (`VULNERABLE`)、HTMLエンティティ等に適切にエスケープされているか (`SANITIZED`)、レスポンスに含まれないか (`NOT REFLECTED`) を高精度に分類。
   - 脆弱性検知時は周辺のHTMLコードをエビデンス（証拠スニペット）として抽出。
4. **診断結果の出力機能**:
   - ANSIカラーによる視覚的なコンソールテーブル出力。
   - Excel対応（UTF-8 with BOM）のCSVレポートファイル自動生成。

### 【余裕があれば実現する機能（実装済み）】
1. **複数パラメータへの対応**:
   - `--param "keyword,category"` のようにカンマ区切りで複数フォームの一括連続診断が可能。
2. **セッション維持機能**:
   - `requests.Session()` をベースとしたCookie維持 (`--cookie`)、カスタムヘッダー付与 (`--header`) に対応。
3. **通信ログ記録機能**:
   - `logging` モジュールにより、全リクエストのペイロード、ステータスコード、応答時間(ms)、ヘッダーを `xss_scanner.log` に時系列記録。

---

## 4. セットアップ手順

### 必要環境
- Python 3.9 以上

### 依存パッケージのインストール
```bash
pip install -r requirements.txt
```

---

## 5. 使い方 (Usage)

### ステップ1: 検証用テストサーバーの起動
別ターミナルを開き、動作確認用のFlaskテストサーバーを起動します。
```bash
python test_server/app.py
```
> 起動後、ブラウザで `http://127.0.0.1:5000/` にアクセスすると、検証用ポータル画面を確認できます。

### ステップ2: XSS診断スクリプトの実行

#### ① 脆弱なGET検索フォームの診断 (`/search_vuln`)
```bash
python xss_scanner.py --url http://127.0.0.1:5000/search_vuln --param keyword
```
- **結果**: 10件すべてのペイロードで「VULNERABLE [要対策]」が検知され、反射された証拠スニペットが表示されます。

#### ② 対策済みGET検索フォームの診断 (`/search_safe`)
```bash
python xss_scanner.py --url http://127.0.0.1:5000/search_safe --param keyword
```
- **結果**: すべてのペイロードが「SANITIZED [対策済]」と判定され、PASSが表示されます。

#### ③ POSTフォームの診断 (`/comment_vuln`)
```bash
python xss_scanner.py --url http://127.0.0.1:5000/comment_vuln --param comment --method POST
```

#### ④ 複数パラメータの同時スキャン
```bash
python xss_scanner.py --url http://127.0.0.1:5000/search_vuln --param "keyword,category"
```

#### ⑤ Cookie認証付きエンドポイントの診断
```bash
python xss_scanner.py --url http://127.0.0.1:5000/profile --param bio --cookie "session_id=secret_session_token_123"
```

#### ⑥ CSV出力ファイル名を明示指定
```bash
python xss_scanner.py --url http://127.0.0.1:5000/search_vuln --param keyword --output-csv my_report.csv
```

---

## 6. コマンドライン引数リファレンス

| オプション | 短縮形 | 必須 | デフォルト値 | 説明 |
| :--- | :--- | :---: | :--- | :--- |
| `--url` | `-u` | ◯ | - | 診断対象のURL (例: `http://127.0.0.1:5000/search`) |
| `--param` | `-p` | ◯ | - | 対象パラメータ名 (カンマ区切りで複数指定可) |
| `--method` | `-m` | - | `GET` | HTTPメソッド (`GET` または `POST`) |
| `--cookie` | `-c` | - | `""` | リクエストに含めるCookie文字列 |
| `--header` | `-H` | - | - | 追加のカスタムHTTPヘッダー (複数回指定可) |
| `--output-csv` | `-o` | - | 自動生成 | 診断レポートCSVの保存先パス |
| `--log-file` | `-l` | - | `xss_scanner.log` | 通信ログ出力先ファイル |
| `--timeout` | `-t` | - | `5.0` | リクエストタイムアウト秒数 |
| `--delay` | `-d` | - | `0.0` | 各リクエスト間の待機秒数 |
| `--no-color` | - | - | `False` | コンソール出力の色付けを無効化 |
| `--verbose` | `-v` | - | `False` | 詳細デバッグログの出力 |

---

## 7. 単体テストの実行

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```
全6件のテストケース（ペイロード生成、生タグ反射検知、エスケープ検知、無反射判定、CSV出力）が実行され、モジュールの健全性が検証されます。
