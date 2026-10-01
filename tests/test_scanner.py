"""
Unit Tests for Simple XSS Scanner
モジュール単体テストおよび検知ロジックの検証
"""

import html
import os
import tempfile
import unittest
from pathlib import Path

from modules.analyzer import DetectionResult, XSSAnalyzer
from modules.payload_manager import PayloadManager
from modules.reporter import XSSReporter
from modules.requester import HTTPResponseData, XSSRequester


class TestPayloadManager(unittest.TestCase):
    """担当A: ペイロード生成モジュールのテスト"""

    def setUp(self):
        self.manager = PayloadManager()

    def test_random_marker_generation(self):
        marker1 = self.manager.generate_random_marker(prefix="TEST")
        marker2 = self.manager.generate_random_marker(prefix="TEST")
        self.assertTrue(marker1.startswith("TEST_"))
        self.assertNotEqual(marker1, marker2)

    def test_payload_rendering(self):
        marker = "MARKER_ABC_123"
        payloads = self.manager.get_payloads(marker=marker)
        self.assertGreater(len(payloads), 0)
        for p in payloads:
            self.assertIn(marker, p.payload_str)
            self.assertEqual(p.marker, marker)


class TestAnalyzer(unittest.TestCase):
    """担当B: レスポンス判定ロジックのテスト"""

    def setUp(self):
        self.analyzer = XSSAnalyzer()
        self.manager = PayloadManager()
        self.marker = "TEST_PROBE_999"
        self.payloads = self.manager.get_payloads(marker=self.marker)

    def test_vulnerable_raw_reflection(self):
        """生タグがそのまま反射している場合の検知判定"""
        payload = self.payloads[0]  # <script>/*{marker}*/</script>
        mock_html = f"<html><body>Search results for: {payload.payload_str}</body></html>"
        resp = HTTPResponseData(
            url="http://test.local/search",
            method="GET",
            status_code=200,
            response_time_ms=15.0,
            text=mock_html,
            content_type="text/html"
        )
        result = self.analyzer.analyze(payload=payload, param_name="q", response=resp)
        self.assertEqual(result.status, DetectionResult.VULNERABLE)
        self.assertIn(payload.payload_str, result.evidence_snippet)

    def test_sanitized_escaped_reflection(self):
        """適切にHTMLエスケープされている場合の判定"""
        payload = self.payloads[0]  # <script>/*{marker}*/</script>
        escaped_val = html.escape(payload.payload_str)
        mock_html = f"<html><body>Search results for: {escaped_val}</body></html>"
        resp = HTTPResponseData(
            url="http://test.local/search",
            method="GET",
            status_code=200,
            response_time_ms=12.0,
            text=mock_html,
            content_type="text/html"
        )
        result = self.analyzer.analyze(payload=payload, param_name="q", response=resp)
        self.assertEqual(result.status, DetectionResult.SANITIZED)

    def test_not_reflected(self):
        """レスポンス内に一切反射がない場合の判定"""
        payload = self.payloads[0]
        mock_html = "<html><body>No results found.</body></html>"
        resp = HTTPResponseData(
            url="http://test.local/search",
            method="GET",
            status_code=200,
            response_time_ms=10.0,
            text=mock_html,
            content_type="text/html"
        )
        result = self.analyzer.analyze(payload=payload, param_name="q", response=resp)
        self.assertEqual(result.status, DetectionResult.NOT_REFLECTED)


class TestReporter(unittest.TestCase):
    """担当C: レポート出力（CSV等）のテスト"""

    def test_csv_export(self):
        reporter = XSSReporter(use_color=False)
        manager = PayloadManager()
        payloads = manager.get_payloads(marker="CSV_TEST")
        analyzer = XSSAnalyzer()

        # サンプル結果を作成
        payload = payloads[0]
        mock_resp = HTTPResponseData(
            url="http://localhost:5000/test",
            method="GET",
            status_code=200,
            response_time_ms=20.0,
            text=payload.payload_str
        )
        result = analyzer.analyze(payload=payload, param_name="keyword", response=mock_resp)

        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            saved_file = reporter.export_csv(
                results=[result],
                target_url="http://localhost:5000/test",
                method="GET",
                output_path=tmp_path
            )
            self.assertTrue(os.path.exists(saved_file))
            with open(saved_file, "r", encoding="utf-8-sig") as f:
                content = f.read()
                self.assertIn("Timestamp", content)
                self.assertIn("PAYLOAD-01", content)
                self.assertIn("VULNERABLE", content)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)


if __name__ == "__main__":
    unittest.main()
