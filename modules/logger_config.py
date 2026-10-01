"""
[担当C] 通信ログ記録モジュール (logger_config.py)
送信したペイロード、HTTPステータスコード、応答時間などを
loggingモジュールを用いてファイルおよびコンソールに時系列で記録します。
"""

import logging
import sys
from pathlib import Path
from typing import Optional


def setup_logger(
    log_file: Optional[str] = "xss_scanner.log",
    verbose: bool = False,
    logger_name: str = "XSS_Scanner"
) -> logging.Logger:
    """
    ロガーの初期化と設定を行います。

    Args:
        log_file: ログ出力先のファイルパス (None の場合はファイル出力なし)
        verbose: True の場合は DEBUG レベル、False の場合は INFO レベルで出力
        logger_name: ロガーの名前

    Returns:
        設定済みの logging.Logger インスタンス
    """
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG)  # ベースレベルは常にDEBUG

    # 既存のハンドラーをクリア（二重出力を防止）
    if logger.hasHandlers():
        logger.handlers.clear()

    # ログフォーマットの定義
    file_formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)-7s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_formatter = logging.Formatter(
        "[%(levelname)-7s] %(message)s"
    )

    # 1. コンソール出力ハンドラー
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)

    # 2. ファイル出力ハンドラー (指定がある場合)
    if log_file:
        try:
            log_path = Path(log_file)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            file_handler = logging.FileHandler(log_path, encoding="utf-8", mode="a")
            file_handler.setLevel(logging.DEBUG)  # ファイルには詳細ログ(DEBUG以上)を全記録
            file_handler.setFormatter(file_formatter)
            logger.addHandler(file_handler)
        except Exception as e:
            logger.warning(f"ログファイル '{log_file}' の作成に失敗しました: {e}")

    return logger
