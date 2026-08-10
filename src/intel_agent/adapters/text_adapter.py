"""纯文本 / JSON / XML 适配器 — 兜底"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from .base import ContentAdapter

logger = logging.getLogger(__name__)

# 支持的文本类 Content-Type
TEXT_TYPES = {
    "text/plain",
    "text/csv",
    "text/xml",
    "application/json",
    "application/xml",
    "application/x-ndjson",
    "text/markdown",
}


class TextAdapter(ContentAdapter):
    """直接读取纯文本类响应体，不做额外处理。"""

    def can_handle(self, content_type: str, url: str) -> bool:
        ct = content_type.lower().split(";")[0].strip()
        return ct in TEXT_TYPES

    def extract(self, url: str, response: Optional[requests.Response] = None) -> str:
        if response is None:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

        # 尝试 UTF-8，失败回退到 response 自动检测的编码
        try:
            text = response.content.decode("utf-8")
        except UnicodeDecodeError:
            text = response.text

        logger.info("TextAdapter: %d 字 (Content-Type: %s)", len(text),
                     response.headers.get("Content-Type", "未知"))
        return text
