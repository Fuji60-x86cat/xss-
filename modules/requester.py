"""
[担当B] 通信処理モジュール (requester.py)
Pythonのrequestsライブラリを利用し、単一/複数パラメータへの
HTTPリクエスト（GET/POST）の送信、Cookieやセッション維持、
および応答時間・ステータスコードの測定を行います。
"""

import time
import urllib.parse
from dataclasses import dataclass, field
from logging import Logger
from typing import Any, Dict, Optional
import requests


@dataclass
class HTTPResponseData:
    """HTTPレスポンスの計測データ構造"""
    url: str
    method: str
    status_code: int
    response_time_ms: float
    text: str
    headers: Dict[str, str] = field(default_factory=dict)
    error: Optional[str] = None
    content_type: str = ""

    @property
    def is_success(self) -> bool:
        """ステータスコードが2xxまたは3xxであるか判定"""
        return 200 <= self.status_code < 400


class XSSRequester:
    """HTTP通信を統括するリクエスタークラス"""

    DEFAULT_USER_AGENT = "SimpleXSSScanner/1.0 (Developer QA Security Screener)"

    def __init__(
        self,
        logger: Optional[Logger] = None,
        timeout: float = 5.0,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[Dict[str, str]] = None,
        verify_ssl: bool = True
    ):
        self.logger = logger
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.session = requests.Session()

        # ヘッダーの初期化
        default_headers = {"User-Agent": self.DEFAULT_USER_AGENT}
        if headers:
            default_headers.update(headers)
        self.session.headers.update(default_headers)

        # Cookieの初期化
        if cookies:
            self.session.cookies.update(cookies)

    def set_cookie_string(self, cookie_str: str) -> None:
        """Cookie文字列（'key=val; key2=val2'）をパースしてセッションに設定"""
        if not cookie_str:
            return
        for item in cookie_str.split(";"):
            item = item.strip()
            if "=" in item:
                k, v = item.split("=", 1)
                self.session.cookies.set(k.strip(), v.strip())

    def send(
        self,
        url: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None
    ) -> HTTPResponseData:
        """
        HTTPリクエストを送信し、応答時間やレスポンス本文を取得します。

        Args:
            url: 対象URL
            method: HTTPメソッド ('GET' または 'POST')
            params: GETクエリパラメータ
            data: POSTフォームデータ (application/x-www-form-urlencoded)
            json_body: POST JSONデータ (application/json)

        Returns:
            HTTPResponseData
        """
        method_upper = method.upper()
        start_time = time.perf_counter()

        if self.logger:
            self.logger.debug(f"HTTP送信開始: [{method_upper}] {url} | Params: {params} | Data: {data}")

        try:
            if method_upper == "GET":
                resp = self.session.get(
                    url,
                    params=params,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
            elif method_upper == "POST":
                resp = self.session.post(
                    url,
                    params=params,
                    data=data,
                    json=json_body,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                    allow_redirects=True
                )
            else:
                raise ValueError(f"未対応のHTTPメソッドです: {method}")

            duration_ms = (time.perf_counter() - start_time) * 1000.0
            content_type = resp.headers.get("Content-Type", "")

            if self.logger:
                self.logger.debug(
                    f"HTTP受信完了: Status={resp.status_code} | "
                    f"Time={duration_ms:.2f}ms | Size={len(resp.text)} bytes"
                )

            return HTTPResponseData(
                url=resp.url,
                method=method_upper,
                status_code=resp.status_code,
                response_time_ms=duration_ms,
                text=resp.text,
                headers=dict(resp.headers),
                content_type=content_type,
                error=None
            )

        except requests.exceptions.Timeout:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            msg = f"タイムアウトエラー ({self.timeout}秒超過)"
            if self.logger:
                self.logger.error(f"HTTP通信失敗: {url} - {msg}")
            return HTTPResponseData(
                url=url,
                method=method_upper,
                status_code=0,
                response_time_ms=duration_ms,
                text="",
                error=msg
            )
        except requests.exceptions.RequestException as e:
            duration_ms = (time.perf_counter() - start_time) * 1000.0
            msg = f"接続エラー: {str(e)}"
            if self.logger:
                self.logger.error(f"HTTP通信失敗: {url} - {msg}")
            return HTTPResponseData(
                url=url,
                method=method_upper,
                status_code=0,
                response_time_ms=duration_ms,
                text="",
                error=msg
            )

    def get_baseline(
        self,
        url: str,
        method: str,
        param_name: str,
        base_value: str = "NIT_Baseline_Check"
    ) -> HTTPResponseData:
        """
        通常時（ベースライン）の応答を取得します。
        """
        if method.upper() == "GET":
            return self.send(url, method="GET", params={param_name: base_value})
        else:
            return self.send(url, method="POST", data={param_name: base_value})
