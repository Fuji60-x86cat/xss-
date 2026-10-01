"""
[担当A] XSS検証用テストWebアプリケーション (test_server/app.py)
スキャナーの精度調整・動作確認・デモ用に、
わざとXSS脆弱性を持たせたエンドポイントと、
適切にエスケープ対策を施したエンドポイントを提供します。
"""

import html
from flask import Flask, render_template, request, make_response

app = Flask(__name__)


@app.route("/")
def index():
    """ポータル画面：各検証用エンドポイントの一覧"""
    return render_template("index.html")


# ==========================================
# 1. GET 検索フォーム (本文コンテキスト)
# ==========================================
@app.route("/search_vuln", methods=["GET"])
def search_vuln():
    """【脆弱】HTMLエスケープを行わずにそのまま反射するエンドポイント"""
    keyword = request.args.get("keyword", "")
    # 意図的に生HTMLとして文字列結合して返す
    html_content = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>検索結果 (脆弱性あり)</title>
    <style>body {{ font-family: sans-serif; padding: 20px; background: #fff5f5; }}</style>
</head>
<body>
    <h1>🔍 検索システム (※脆弱性デモ用)</h1>
    <p>ステータス: <strong style="color:red;">脆弱 (エスケープ未適用)</strong></p>
    <div>
        検索キーワード: <strong>{keyword}</strong> の検索結果 (0件)
    </div>
    <br>
    <a href="/">← トップへ戻る</a>
</body>
</html>"""
    return html_content


@app.route("/search_safe", methods=["GET"])
def search_safe():
    """【対策済】HTMLエスケープを施して反射するエンドポイント"""
    keyword = request.args.get("keyword", "")
    escaped_keyword = html.escape(keyword)

    html_content = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>検索結果 (対策済み)</title>
    <style>body {{ font-family: sans-serif; padding: 20px; background: #f0fff4; }}</style>
</head>
<body>
    <h1>🔍 検索システム (対策済み)</h1>
    <p>ステータス: <strong style="color:green;">安全 (HTMLエスケープ適用済)</strong></p>
    <div>
        検索キーワード: <strong>{escaped_keyword}</strong> の検索結果 (0件)
    </div>
    <br>
    <a href="/">← トップへ戻る</a>
</body>
</html>"""
    return html_content


# ==========================================
# 2. GET フォーム属性値コンテキスト (value="...")
# ==========================================
@app.route("/attr_vuln", methods=["GET"])
def attr_vuln():
    """【脆弱】HTML属性値のダブルクォート抜け出しが可能なエンドポイント"""
    query = request.args.get("q", "")
    html_content = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>属性値テスト (脆弱性あり)</title>
</head>
<body style="padding: 20px; background: #fff5f5;">
    <h1>🏷️ 属性値コンテキスト (脆弱)</h1>
    <form action="/attr_vuln" method="GET">
        <label>再検索: </label>
        <input type="text" name="q" value="{query}" size="50">
        <button type="submit">検索</button>
    </form>
    <p>入力値: {html.escape(query)}</p>
    <a href="/">← トップへ戻る</a>
</body>
</html>"""
    return html_content


@app.route("/attr_safe", methods=["GET"])
def attr_safe():
    """【対策済】属性値内も適切にエスケープするエンドポイント"""
    query = request.args.get("q", "")
    escaped_val = html.escape(query, quote=True)
    html_content = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>属性値テスト (対策済み)</title>
</head>
<body style="padding: 20px; background: #f0fff4;">
    <h1>🏷️ 属性値コンテキスト (対策済み)</h1>
    <form action="/attr_safe" method="GET">
        <label>再検索: </label>
        <input type="text" name="q" value="{escaped_val}" size="50">
        <button type="submit">検索</button>
    </form>
    <p>入力値: {escaped_val}</p>
    <a href="/">← トップへ戻る</a>
</body>
</html>"""
    return html_content


# ==========================================
# 3. POST コメント投稿フォーム
# ==========================================
@app.route("/comment_vuln", methods=["GET", "POST"])
def comment_vuln():
    """【脆弱】POSTデータが生のまま出力されるエンドポイント"""
    comment = request.form.get("comment", "") if request.method == "POST" else ""
    html_content = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>コメント投稿 (脆弱)</title>
    <style>body {{ font-family: sans-serif; padding: 20px; background: #fff5f5; }}</style>
</head>
<body>
    <h1>💬 コメント投稿フォーム (※POST 脆弱性デモ)</h1>
    <form action="/comment_vuln" method="POST">
        <textarea name="comment" rows="3" cols="40" placeholder="コメントを入力"></textarea><br>
        <button type="submit">投稿</button>
    </form>
    <hr>
    <h3>最新の投稿:</h3>
    <div style="border: 1px solid #ccc; padding: 10px; background: white;">
        {comment if comment else "(投稿はありません)"}
    </div>
    <br>
    <a href="/">← トップへ戻る</a>
</body>
</html>"""
    return html_content


@app.route("/comment_safe", methods=["GET", "POST"])
def comment_safe():
    """【対策済】POSTデータがエスケープされるエンドポイント"""
    comment = request.form.get("comment", "") if request.method == "POST" else ""
    escaped_comment = html.escape(comment) if comment else ""
    html_content = f"""<!DOCTYPE html>
<html lang="ja">
<head>
    <meta charset="UTF-8">
    <title>コメント投稿 (対策済)</title>
    <style>body {{ font-family: sans-serif; padding: 20px; background: #f0fff4; }}</style>
</head>
<body>
    <h1>💬 コメント投稿フォーム (POST 対策済)</h1>
    <form action="/comment_safe" method="POST">
        <textarea name="comment" rows="3" cols="40" placeholder="コメントを入力"></textarea><br>
        <button type="submit">投稿</button>
    </form>
    <hr>
    <h3>最新の投稿:</h3>
    <div style="border: 1px solid #ccc; padding: 10px; background: white;">
        {escaped_comment if escaped_comment else "(投稿はありません)"}
    </div>
    <br>
    <a href="/">← トップへ戻る</a>
</body>
</html>"""
    return html_content


# ==========================================
# 4. Cookie / セッション認証付きエンドポイント
# ==========================================
@app.route("/profile", methods=["GET"])
def profile():
    """Cookie認証を要求するエンドポイント (セッション維持の動作検証用)"""
    session_cookie = request.cookies.get("session_id")
    bio = request.args.get("bio", "")

    if session_cookie != "secret_session_token_123":
        return "<h3>401 Unauthorized - 正しい session_id Cookie が必要です。</h3>", 401

    return f"""<!DOCTYPE html>
<html>
<head><title>ユーザープロフィール</title></head>
<body style="padding:20px;">
    <h2>👤 ログイン中ユーザーのプロフィール (Cookie確認済)</h2>
    <p>自己紹介: {bio}</p>
</body>
</html>"""


if __name__ == "__main__":
    print("=======================================================")
    print(" [担当A] 検証用 Flask テストサーバーを起動しています...")
    print(" URL: http://127.0.0.1:5000/")
    print("=======================================================")
    app.run(host="127.0.0.1", port=5000, debug=False)
