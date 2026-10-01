"""
[担当B] レスポンス分析・差分検知モジュール (analyzer.py)
ベースライン応答とペイロード送信後応答を比較し、送信したマーカー文字列および
特殊文字が「生テキストとして反射しているか（脆弱）」または「エスケープ処理されているか（安全）」
を正確に分類・判定します。
"""

import html
import re
from dataclasses import dataclass
from enum import Enum
from logging import Logger
from typing import Optional
from modules.payload_manager import XSSPayload
from modules.requester import HTTPResponseData


class DetectionResult(Enum):
    """診断判定結果の区分"""
    VULNERABLE = "反射型XSSの疑いあり (VULNERABLE)"
    SANITIZED = "対策済み (SANITIZED / ESCAPED)"
    NOT_REFLECTED = "反射なし (NOT REFLECTED)"
    SERVER_ERROR = "サーバーエラー (SERVER ERROR)"
    CONNECTION_ERROR = "通信エラー (CONNECTION FAILED)"


@dataclass
class ScanItemResult:
    """個別ペイロード診断結果のデータ構造"""
    payload_id: str
    payload_name: str
    category: str
    param_name: str
    payload_sent: str
    marker: str
    status: DetectionResult
    http_status: int
    response_time_ms: float
    evidence_snippet: str
    details: str


class XSSAnalyzer:
    """レスポンスの反射およびエスケープ状態を解析するクラス"""

    def __init__(self, logger: Optional[Logger] = None):
        self.logger = logger

    @staticmethod
    def extract_evidence_snippet(text: str, target: str, window: int = 50) -> str:
        """
        対象文字列の周辺テキストを抜き出し、レポート用の証拠スニペットを作成します。
        """
        idx = text.find(target)
        if idx == -1:
            return ""

        start = max(0, idx - window)
        end = min(len(text), idx + len(target) + window)
        snippet = text[start:end].replace("\r", " ").replace("\n", " ")

        prefix = "..." if start > 0 else ""
        suffix = "..." if end < len(text) else ""
        return f"{prefix}{snippet}{suffix}"

    def analyze(
        self,
        payload: XSSPayload,
        param_name: str,
        response: HTTPResponseData,
        baseline: Optional[HTTPResponseData] = None
    ) -> ScanItemResult:
        """
        単一のHTTPレスポンスを解析し、脆弱性の有無を判定します。

        Args:
            payload: 送信したXSSPayload
            param_name: 対象パラメータ名
            response: ペイロード送信後のHTTPレスポンス
            baseline: 通常時のベースラインHTTPレスポンス

        Returns:
            ScanItemResult: 判定結果詳細
        """
        # 1. 通信エラーまたは500系エラーのハンドリング
        if response.error:
            if self.logger:
                self.logger.warning(f"[{payload.id}] 通信エラー: {response.error}")
            return ScanItemResult(
                payload_id=payload.id,
                payload_name=payload.name,
                category=payload.category,
                param_name=param_name,
                payload_sent=payload.payload_str,
                marker=payload.marker,
                status=DetectionResult.CONNECTION_ERROR,
                http_status=response.status_code,
                response_time_ms=response.response_time_ms,
                evidence_snippet="",
                details=f"通信失敗: {response.error}"
            )

        if response.status_code >= 500:
            if self.logger:
                self.logger.warning(f"[{payload.id}] サーバーエラー (HTTP {response.status_code})")
            return ScanItemResult(
                payload_id=payload.id,
                payload_name=payload.name,
                category=payload.category,
                param_name=param_name,
                payload_sent=payload.payload_str,
                marker=payload.marker,
                status=DetectionResult.SERVER_ERROR,
                http_status=response.status_code,
                response_time_ms=response.response_time_ms,
                evidence_snippet="",
                details=f"サーバー内部エラー応答 (HTTP {response.status_code})"
            )

        res_text = response.text
        sent_str = payload.payload_str
        marker = payload.marker

        # エスケープパターンの生成 (Jinja2 / PHP htmlspecialchars / HTML Entities)
        escaped_str_std = html.escape(sent_str, quote=True)
        escaped_str_single = sent_str.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#39;")
        escaped_str_hex = sent_str.replace("<", "&lt;").replace(">", "&gt;").replace("'", "&#x27;")

        # 2. そのままのペイロード文字列（生タグ/属性抜け出し）が含まれているか検証
        if sent_str in res_text:
            snippet = self.extract_evidence_snippet(res_text, sent_str)
            details = "危険: 送信したHTMLタグ/スクリプト文字列がエスケープされずにそのまま反射されています。"

            # Content-TypeがHTML系でない場合の補足情報
            if "text/html" not in response.content_type.lower() and response.content_type:
                details += f" (※ Content-Typeが '{response.content_type}' のためブラウザの直接描画設定を確認してください)"

            if self.logger:
                self.logger.info(f"[{payload.id}] 【脆弱性検知】 パラメータ: {param_name} -> 未エスケープ反射")

            return ScanItemResult(
                payload_id=payload.id,
                payload_name=payload.name,
                category=payload.category,
                param_name=param_name,
                payload_sent=sent_str,
                marker=marker,
                status=DetectionResult.VULNERABLE,
                http_status=response.status_code,
                response_time_ms=response.response_time_ms,
                evidence_snippet=snippet,
                details=details
            )

        # 3. エスケープされた文字列が存在するか検証
        if (escaped_str_std in res_text) or (escaped_str_single in res_text) or (escaped_str_hex in res_text):
            found_str = escaped_str_std if escaped_str_std in res_text else (
                escaped_str_single if escaped_str_single in res_text else escaped_str_hex
            )
            snippet = self.extract_evidence_snippet(res_text, found_str)
            details = "安全: 特殊文字 (<, >, \", ') が適切にHTMLエンティティ (&lt;, &gt;, &quot; 等) へエスケープされています。"

            if self.logger:
                self.logger.info(f"[{payload.id}] 【対策済み確認】 パラメータ: {param_name} -> 適切にエスケープ処理済")

            return ScanItemResult(
                payload_id=payload.id,
                payload_name=payload.name,
                category=payload.category,
                param_name=param_name,
                payload_sent=sent_str,
                marker=marker,
                status=DetectionResult.SANITIZED,
                http_status=response.status_code,
                response_time_ms=response.response_time_ms,
                evidence_snippet=snippet,
                details=details
            )

        # 4. マーカー文字列のみが含まれる（タグやクォートが除去/フィルタされた）場合
        if marker in res_text:
            snippet = self.extract_evidence_snippet(res_text, marker)
            # マーカーの前後にある危険文字をチェック
            has_dangerous_chars = any(c in snippet for c in ["<script", "<img", "<svg", "onerror=", "onload=", "onfocus="])
            if has_dangerous_chars:
                status = DetectionResult.VULNERABLE
                details = "警告: 危険なタグまたはイベント属性が残存した状態でマーカーが反射されています。"
            else:
                status = DetectionResult.SANITIZED
                details = "対策済み: 危険なHTMLタグ/属性文字が除去またはサニタイズされた上でマーカーが出力されています。"

            return ScanItemResult(
                payload_id=payload.id,
                payload_name=payload.name,
                category=payload.category,
                param_name=param_name,
                payload_sent=sent_str,
                marker=marker,
                status=status,
                http_status=response.status_code,
                response_time_ms=response.response_time_ms,
                evidence_snippet=snippet,
                details=details
            )

        # 5. 反射が一切確認できない場合
        return ScanItemResult(
            payload_id=payload.id,
            payload_name=payload.name,
            category=payload.category,
            param_name=param_name,
            payload_sent=sent_str,
            marker=marker,
            status=DetectionResult.NOT_REFLECTED,
            http_status=response.status_code,
            response_time_ms=response.response_time_ms,
            evidence_snippet="",
            details="情報: 入力された文字列はレスポンス内に反射されていません（サーバー側で保持または無視）。"
        )
