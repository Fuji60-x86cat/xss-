"""
[担当A] XSSテスト用ペイロード管理モジュール (payload_manager.py)
マーカー文字列を含む基本的なXSS検知用テストパターン（HTMLタグ、属性値抜け出し、
イベントハンドラ、Scriptタグ内など）を管理・生成します。
"""

import random
import string
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class XSSPayload:
    """XSSテスト用ペイロードのデータ構造"""
    id: str
    name: str
    category: str
    template: str
    description: str
    marker: str = ""
    payload_str: str = ""

    def render(self, marker: str) -> str:
        """マーカー文字列を埋め込んだ実際のテスト文字列を生成"""
        self.marker = marker
        self.payload_str = self.template.format(marker=marker)
        return self.payload_str


class PayloadManager:
    """XSS診断用ペイロードの定義および生成を統括するマネージャークラス"""

    DEFAULT_TEMPLATES = [
        {
            "id": "PAYLOAD-01",
            "name": "Basic Script Tag",
            "category": "HTML Body Context",
            "template": "<script>/*{marker}*/</script>",
            "description": "最も基本的な<script>タグの挿入テスト。HTML本文で直接実行されるかを検証。"
        },
        {
            "id": "PAYLOAD-02",
            "name": "HTML Element Injection",
            "category": "HTML Body Context",
            "template": "<h1>{marker}</h1>",
            "description": "HTMLタグ自体がサニタイズされずにそのまま出力されるかを検証。"
        },
        {
            "id": "PAYLOAD-03",
            "name": "Attribute Breakout (Double Quote)",
            "category": "Attribute Context (Double Quote)",
            "template": "\"><script>/*{marker}*/</script>",
            "description": "ダブルクォートで囲まれたHTML属性（value=\"...\"など）から抜け出せるかを検証。"
        },
        {
            "id": "PAYLOAD-04",
            "name": "Attribute Breakout (Single Quote)",
            "category": "Attribute Context (Single Quote)",
            "template": "'><script>/*{marker}*/</script>",
            "description": "シングルクォートで囲まれたHTML属性（value='...'など）から抜け出せるかを検証。"
        },
        {
            "id": "PAYLOAD-05",
            "name": "Inline Event Handler (Double Quote)",
            "category": "Event Handler Context",
            "template": "\" onfocus=\"/*{marker}*/\" autofocus=\"",
            "description": "属性内にイベントハンドラ(onfocus/autofocus)を注入可能かを検証。"
        },
        {
            "id": "PAYLOAD-06",
            "name": "Inline Event Handler (Single Quote)",
            "category": "Event Handler Context",
            "template": "' onfocus='/*{marker}*/' autofocus='",
            "description": "シングルクォート属性内にイベントハンドラを注入可能かを検証。"
        },
        {
            "id": "PAYLOAD-07",
            "name": "Image Tag Event Injection",
            "category": "HTML Body Context",
            "template": "<img src=x onerror=\"/*{marker}*/\">",
            "description": "<script>が遮断された場合でも<img>タグとonerrorによる実行が可能か検証。"
        },
        {
            "id": "PAYLOAD-08",
            "name": "SVG Tag Event Injection",
            "category": "HTML Body Context",
            "template": "<svg onload=\"/*{marker}*/\">",
            "description": "<svg>タグのonloadイベントによるスクリプト実行が可能か検証。"
        },
        {
            "id": "PAYLOAD-09",
            "name": "JavaScript Context Breakout",
            "category": "Script Block Context",
            "template": "';/*{marker}*/;//",
            "description": "<script>ブロック内部のJS文字列変数展開から抜け出せるかを検証。"
        },
        {
            "id": "PAYLOAD-10",
            "name": "Case Sensitivity Evasion",
            "category": "Filter Evasion Context",
            "template": "<sCrIpt>/*{marker}*/</sCrIpT>",
            "description": "小文字の<script>のみをフィルタリングする簡易WAF・独自正規表現のすり抜けを検証。"
        }
    ]

    def __init__(self, custom_templates: Optional[List[dict]] = None):
        self.templates = custom_templates or self.DEFAULT_TEMPLATES

    @staticmethod
    def generate_random_marker(prefix: str = "XSS_PROBE", length: int = 6) -> str:
        """
        テスト対象ごとに一意のランダムマーカー文字列を生成します。
        （例: XSS_PROBE_a8f9c2）
        """
        random_suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=length))
        return f"{prefix}_{random_suffix}"

    def get_payloads(self, marker: Optional[str] = None) -> List[XSSPayload]:
        """
        すべての定義済みペイロードにマーカーを適用したインスタンスリストを取得します。
        """
        if not marker:
            marker = self.generate_random_marker()

        payload_list = []
        for item in self.templates:
            payload = XSSPayload(
                id=item["id"],
                name=item["name"],
                category=item["category"],
                template=item["template"],
                description=item["description"]
            )
            payload.render(marker)
            payload_list.append(payload)

        return payload_list
