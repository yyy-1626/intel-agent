"""适配器注册表 — 按优先级遍历匹配"""

from __future__ import annotations

from .base import ContentAdapter
from .text_adapter import TextAdapter
from .pdf_adapter import PDFAdapter


# 适配器按优先级排列：越具体的越靠前
_ADAPTERS: list[ContentAdapter] = []


def _init_adapters() -> list[ContentAdapter]:
    """初始化适配器列表（按优先级）。"""
    if _ADAPTERS:
        return _ADAPTERS

    _ADAPTERS.extend([
        PDFAdapter(),
        TextAdapter(),   # 兜底：纯文本，放最后
    ])
    return _ADAPTERS


def get_adapters() -> list[ContentAdapter]:
    """获取所有已注册的适配器（按优先级排序）。"""
    return _init_adapters()
