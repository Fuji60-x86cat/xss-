"""
[担当C] 診断結果出力モジュール (reporter.py)
検知結果をコンソール（色付きテーブル表示）および
CSVファイル形式でわかりやすく出力します。
"""

import csv
import datetime
import os
import sys
from pathlib import Path
from typing import List, Optional
from modules.analyzer import DetectionResult, ScanItemResult


# Windowsおよび各OS用のANSIカラーコード定義
class Colors:
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"
    DIM = "\033[2m"
    RESET = "\033[0m"


class XSSReporter:
    """スキャン結果の集計およびレポート出力を行うクラス"""

    def __init__(self, use_color: bool = True):
        # Windowsのコマンドプロンプト等でANSIエスケープシーケンスとUTF-8出力を有効化
        if os.name == "nt":
            os.system("")
            try:
                if hasattr(sys.stdout, "reconfigure"):
                    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
                if hasattr(sys.stderr, "reconfigure"):
                    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass
        self.use_color = use_color

    def _c(self, text: str, color_code: str) -> str:
        """カラー出力を適用（無効時はプレーンテキスト）"""
        if not self.use_color:
            return text
        return f"{color_code}{text}{Colors.RESET}"

    def print_banner(self) -> None:
        """ツール起動バナーの表示"""
        banner = r"""
==============================================================================
   ___  ___ _____ ___                 _               _   ___           _         
  | _ \/ _ \_   _| _ \__ _ _  _ _ __ | |   ___  __ _ / | | _ \_ _ ___  | |__  ___ 
  |  _/ (_) || | |  _/ _` | || | '_ \| |__/ _ \/ _` || | |  _/ '_/ _ \ | '_ \/ -_)
  |_|  \___/ |_| |_| \__,_|\_, | .__/|____\___/\__,_||_| |_| |_| \___/ |_.__/\___|
                           |__/|_|                                                
       Simple XSS Vulnerability Scanner & Sanitization Screener (v1.0)
==============================================================================
"""
        print(self._c(banner, Colors.CYAN))

    def print_summary_table(
        self,
        target_url: str,
        method: str,
        parameters: List[str],
        results: List[ScanItemResult],
        duration_sec: float
    ) -> None:
        """
        コンソール上に詳細結果テーブルと統計サマリーを出力します。
        """
        print("\n" + "=" * 90)
        print(self._c("【診断実行サマリー】", Colors.BOLD))
        print(f" 対象URL     : {target_url}")
        print(f" メソッド    : {method}")
        print(f" 対象パラメータ: {', '.join(parameters)}")
        print(f" 実行日時    : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f" 総所要時間  : {duration_sec:.2f} 秒")
        print("=" * 90)

        # テーブルヘッダー
        header = f"{'ID':<11} | {'Payload Name':<28} | {'Param':<10} | {'Status Code':<8} | {'Result':<24} | {'Time (ms)':<9}"
        print(self._c(header, Colors.BOLD))
        print("-" * 90)

        vuln_count = 0
        sanitized_count = 0
        not_ref_count = 0
        error_count = 0

        for r in results:
            # 状態に応じたカラーとカウント
            if r.status == DetectionResult.VULNERABLE:
                status_str = self._c("VULNERABLE [要対策]", Colors.RED + Colors.BOLD)
                vuln_count += 1
            elif r.status == DetectionResult.SANITIZED:
                status_str = self._c("SANITIZED [対策済]", Colors.GREEN)
                sanitized_count += 1
            elif r.status == DetectionResult.NOT_REFLECTED:
                status_str = self._c("NOT REFLECTED", Colors.DIM)
                not_ref_count += 1
            else:
                status_str = self._c("ERROR", Colors.YELLOW)
                error_count += 1

            short_name = (r.payload_name[:25] + "...") if len(r.payload_name) > 28 else r.payload_name
            param_display = (r.param_name[:8] + "..") if len(r.param_name) > 10 else r.param_name
            http_disp = str(r.http_status) if r.http_status > 0 else "ERR"

            row = f"{r.payload_id:<11} | {short_name:<28} | {param_display:<10} | {http_disp:<11} | {status_str:<33} | {r.response_time_ms:>7.1f}ms"
            print(row)

            # 脆弱性検知時は証拠スニペットを強調表示
            if r.status == DetectionResult.VULNERABLE and r.evidence_snippet:
                snippet_line = f"    └── {self._c('反射証拠: ', Colors.YELLOW)}{self._c(r.evidence_snippet, Colors.DIM)}"
                print(snippet_line)

        print("-" * 90)

        # 総合判定結果
        print("\n" + self._c("【総合診断結果】", Colors.BOLD))
        print(f" 総テスト数       : {len(results)} 件")
        print(f" 脆弱性検知 (危険): {self._c(str(vuln_count), Colors.RED + Colors.BOLD)} 件")
        print(f" エスケープ (安全): {self._c(str(sanitized_count), Colors.GREEN)} 件")
        print(f" 反射なし   (無害): {not_ref_count} 件")
        if error_count > 0:
            print(f" エラー発生       : {self._c(str(error_count), Colors.YELLOW)} 件")

        print("\n" + "-" * 50)
        if vuln_count > 0:
            msg = f" 判定: [ALERT] {vuln_count} 件のXSS脆弱性の疑いが検知されました。\n" \
                  f"       入力値のエスケープ処理（htmlspecialchars / Jinja2自動エスケープ等）\n" \
                  f"       またはコンテキストに応じた適切なサニタイズを確認してください。"
            print(self._c(msg, Colors.RED + Colors.BOLD))
        else:
            msg = f" 判定: [PASS] 未エスケープのXSS反射は検出されませんでした。\n" \
                  f"       基本的なサニタイズ処理が機能しています。"
            print(self._c(msg, Colors.GREEN + Colors.BOLD))
        print("-" * 50 + "\n")

    def export_csv(
        self,
        results: List[ScanItemResult],
        target_url: str,
        method: str,
        output_path: str
    ) -> str:
        """
        診断結果をCSVファイル（UTF-8 with BOM: Excel直接互換）に出力します。
        """
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        fieldnames = [
            "Timestamp",
            "Target_URL",
            "HTTP_Method",
            "Parameter",
            "Payload_ID",
            "Payload_Name",
            "Category",
            "Payload_Sent",
            "Result_Status",
            "HTTP_Status",
            "Response_Time_ms",
            "Evidence_Snippet",
            "Details"
        ]

        with open(path, mode="w", newline="", encoding="utf-8-sig") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                writer.writerow({
                    "Timestamp": now_str,
                    "Target_URL": target_url,
                    "HTTP_Method": method,
                    "Parameter": r.param_name,
                    "Payload_ID": r.payload_id,
                    "Payload_Name": r.payload_name,
                    "Category": r.category,
                    "Payload_Sent": r.payload_sent,
                    "Result_Status": r.status.value,
                    "HTTP_Status": r.http_status,
                    "Response_Time_ms": f"{r.response_time_ms:.2f}",
                    "Evidence_Snippet": r.evidence_snippet,
                    "Details": r.details
                })

        return str(path.resolve())
