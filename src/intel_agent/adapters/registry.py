"""适配器注册表 — 按优先级遍历匹配"""

from __future__ import annotations

from .base import ContentAdapter
from .youtube_adapter import YouTubeAdapter
from .office_adapter import OfficeAdapter
from .pdf_adapter import PDFAdapter
from .text_adapter import TextAdapter


_ADAPTERS: list[ContentAdapter] = []


def _init_adapters() -> list[ContentAdapter]:
    if _ADAPTERS:
        return _ADAPTERS

    _ADAPTERS.extend([
        YouTubeAdapter(),
        OfficeAdapter(),
        PDFAdapter(),
        TextAdapter(),
    ])
    return _ADAPTERS


def get_adapters() -> list[ContentAdapter]:
    return _init_adapters()
