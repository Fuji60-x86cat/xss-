#!/usr/bin/env python3
"""
Simple XSS Scanner (XSS PayloadProbe)
単一・複数入力フォーム向け 簡易XSS脆弱性診断スクリプト

Webアプリ開発者およびセキュリティ初学者向けに、
指定したURLとパラメータに対して基本的なXSSテスト文字列を送信し、
サニタイズ（エスケープ）の有無を判定・可視化します。
"""

import argparse
import datetime
import os
import sys
import time
from typing import Dict, List, Optional
import urllib.parse

# WindowsコンソールでのUTF-8出力対応
if os.name == "nt":
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from modules.analyzer import DetectionResult, ScanItemResult, XSSAnalyzer
from modules.logger_config import setup_logger
from modules.payload_manager import PayloadManager, XSSPayload
from modules.reporter import XSSReporter
from modules.requester import HTTPResponseData, XSSRequester


def parse_arguments() -> argparse.Namespace:
    """コマンドライン引数の解析"""
    parser = argparse.ArgumentParser(
        description="Simple XSS Scanner (XSS PayloadProbe) - 単一/複数フォーム向け簡易XSS診断ツール",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用例:
  # 基本的なGETフォーム診断
  python xss_scanner.py --url http://127.0.0.1:5000/search_vuln --param keyword

  # POSTフォームの診断
  python xss_scanner.py --url http://127.0.0.1:5000/comment_vuln --param comment --method POST

  # Cookie認証の維持とCSV出力指定
  python xss_scanner.py --url http://127.0.0.1:5000/user/profile --param bio --cookie "session=abc123" --output-csv report.csv

  # 複数パラメータの同時スキャン
  python xss_scanner.py --url http://127.0.0.1:5000/search --param "q,category"
        """
    )

    parser.add_argument(
        "--url", "-u",
        required=True,
        help="[必須] 診断対象のURL (例: http://127.0.0.1:5000/search)"
    )
    parser.add_argument(
        "--param", "-p",
        required=True,
        help="[必須] 診断対象のパラメータ名 (複数ある場合はカンマ区切り: 例 'keyword' または 'q,category')"
    )
    parser.add_argument(
        "--method", "-m",
        choices=["GET", "POST"],
        default="GET",
        help="HTTPリクエストメソッド (デフォルト: GET)"
    )
    parser.add_argument(
        "--cookie", "-c",
        default="",
        help="リクエストに含めるCookie文字列 (例: 'session_id=12345; user=alice')"
    )
    parser.add_argument(
        "--header", "-H",
        action="append",
        help="追加のカスタムHTTPヘッダー (複数指定可: 例 -H 'X-CSRF-Token: abc' -H 'Authorization: Bearer xyz')"
    )
    parser.add_argument(
        "--output-csv", "-o",
        default="",
        help="診断結果CSVの保存先パス (指定なしの場合はタイムスタンプ付きファイル名を自動生成)"
    )
    parser.add_argument(
        "--log-file", "-l",
        default="xss_scanner.log",
        help="通信ログおよびシステムログの出力先ファイル (デフォルト: xss_scanner.log)"
    )
    parser.add_argument(
        "--timeout", "-t",
        type=float,
        default=5.0,
        help="各HTTPリクエストのタイムアウト秒数 (デフォルト: 5.0秒)"
    )
    parser.add_argument(
        "--delay", "-d",
        type=float,
        default=0.0,
        help="各リクエスト間の待機時間 (秒) (デフォルト: 0.0秒)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="コンソール出力の色付け（ANSIカラー）を無効化"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="詳細デバッグログを出力"
    )

    return parser.parse_args()


def parse_custom_headers(header_list: Optional[List[str]]) -> Dict[str, str]:
    """-H 引数のリストを辞書に変換"""
    headers = {}
    if not header_list:
        return headers
    for h in header_list:
        if ":" in h:
            k, v = h.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


def main():
    args = parse_arguments()

    # 1. ログおよびレポーターの初期化
    logger = setup_logger(log_file=args.log_file, verbose=args.verbose)
    reporter = XSSReporter(use_color=not args.no_color)
    reporter.print_banner()

    logger.info("=== Simple XSS Scanner 診断セッション開始 ===")
    logger.info(f"対象URL: {args.url} | メソッド: {args.method} | パラメータ: {args.param}")

    # 2. パラメータのパース
    target_params = [p.strip() for p in args.param.split(",") if p.strip()]
    if not target_params:
        print("[エラー] 対象パラメータ名が空です。--param を確認してください。", file=sys.stderr)
        sys.exit(1)

    # 3. リクエスターの初期化
    custom_headers = parse_custom_headers(args.header)
    requester = XSSRequester(
        logger=logger,
        timeout=args.timeout,
        headers=custom_headers
    )
    if args.cookie:
        requester.set_cookie_string(args.cookie)

    # 4. ベースライン疎通テスト (接続性確認)
    print(f"[*] 対象サーバーへの接続性を確認中: {args.url} ...")
    baseline_resp = requester.get_baseline(
        url=args.url,
        method=args.method,
        param_name=target_params[0]
    )

    if baseline_resp.error:
        print(f"[!] サーバーへの接続に失敗しました: {baseline_resp.error}", file=sys.stderr)
        logger.error(f"ベースライン接続テスト失敗: {baseline_resp.error}")
        sys.exit(1)

    print(f"[+] 接続成功 (HTTP {baseline_resp.status_code}, 応答時間: {baseline_resp.response_time_ms:.1f}ms)")
    if "text/html" not in baseline_resp.content_type.lower() and baseline_resp.content_type:
        print(f"[*] 注意: Content-Type が '{baseline_resp.content_type}' です。HTMLとして解釈されない可能性があります。")

    # 5. ペイロードマネージャーとアナライザーの初期化
    payload_manager = PayloadManager()
    analyzer = XSSAnalyzer(logger=logger)

    # スキャン実行
    all_results: List[ScanItemResult] = []
    start_time = time.perf_counter()

    for param in target_params:
        print(f"\n[*] パラメータ '{param}' に対するXSS診断を開始します...")
        # パラメータごとに固有のマーカー文字列を生成
        marker = payload_manager.generate_random_marker(prefix="NIT_XSS")
        payloads = payload_manager.get_payloads(marker=marker)

        for idx, payload in enumerate(payloads, start=1):
            # リクエスト送信
            if args.method.upper() == "GET":
                resp = requester.send(args.url, method="GET", params={param: payload.payload_str})
            else:
                resp = requester.send(args.url, method="POST", data={param: payload.payload_str})

            # レスポンス解析
            result = analyzer.analyze(
                payload=payload,
                param_name=param,
                response=resp,
                baseline=baseline_resp
            )
            all_results.append(result)

            # コンソールへのリアルタイム進捗表示
            status_indicator = "●"
            if result.status == DetectionResult.VULNERABLE:
                status_indicator = "[! VULN]"
            elif result.status == DetectionResult.SANITIZED:
                status_indicator = "[+ SAFE]"
            elif result.status == DetectionResult.NOT_REFLECTED:
                status_indicator = "[- NONE]"
            else:
                status_indicator = "[? ERR ]"

            print(f"  [{idx}/{len(payloads)}] {status_indicator:<8} {payload.id} ({payload.name}) - HTTP {resp.status_code} ({resp.response_time_ms:.1f}ms)")

            # 遅延設定がある場合
            if args.delay > 0:
                time.sleep(args.delay)

    total_duration = time.perf_counter() - start_time

    # 6. コンソール結果サマリー表示
    reporter.print_summary_table(
        target_url=args.url,
        method=args.method,
        parameters=target_params,
        results=all_results,
        duration_sec=total_duration
    )

    # 7. CSVレポートの保存
    csv_file = args.output_csv
    if not csv_file:
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        csv_file = f"xss_report_{timestamp}.csv"

    saved_path = reporter.export_csv(
        results=all_results,
        target_url=args.url,
        method=args.method,
        output_path=csv_file
    )
    print(f"[+] 診断レポート(CSV)を出力しました: {saved_path}")
    print(f"[+] 通信ログファイル: {args.log_file}")
    logger.info(f"スキャン完了。総テスト数: {len(all_results)}, CSV出力: {saved_path}")


if __name__ == "__main__":
    main()
