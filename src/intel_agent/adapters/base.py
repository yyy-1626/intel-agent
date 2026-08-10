"""适配器基类 — 内容类型 → 文本提取的统一接口"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

import requests


class ContentAdapter(ABC):
    """内容适配器抽象基类。每个适配器处理一种内容类型，提取纯文本。"""

    @abstractmethod
    def can_handle(self, content_type: str, url: str) -> bool:
        """判断是否能处理此内容类型。"""

    @abstractmethod
    def extract(self, url: str, response: Optional[requests.Response] = None) -> str:
        """提取纯文本。失败抛异常，由 fetch_node 捕获。"""
