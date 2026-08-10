"""适配器模块"""

from .base import ContentAdapter
from .registry import get_adapters

__all__ = ["ContentAdapter", "get_adapters"]
