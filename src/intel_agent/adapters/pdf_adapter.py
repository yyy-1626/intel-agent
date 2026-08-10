"""PDF 适配器 — 用 pdfplumber 提取文本"""

from __future__ import annotations

import io
import logging
from typing import Optional

import requests

from .base import ContentAdapter

logger = logging.getLogger(__name__)

# 是否有 PDF 能力（pdfplumber 已安装）
_PDF_AVAILABLE: Optional[bool] = None


def _check_pdfplumber() -> bool:
    global _PDF_AVAILABLE
    if _PDF_AVAILABLE is None:
        try:
            import pdfplumber  # noqa: F401
            _PDF_AVAILABLE = True
        except ImportError:
            _PDF_AVAILABLE = False
    return _PDF_AVAILABLE


class PDFAdapter(ContentAdapter):
    """从 PDF 文件中提取文本层内容。扫描版 PDF 返回空字符串。"""

    def can_handle(self, content_type: str, url: str) -> bool:
        if not _check_pdfplumber():
            return False

        ct = content_type.lower()
        if "application/pdf" in ct:
            return True

        # URL 后缀也作为判断依据
        url_lower = url.lower().split("?")[0]
        if url_lower.endswith(".pdf"):
            return True

        return False

    def extract(self, url: str, response: Optional[requests.Response] = None) -> str:
        if response is None:
            response = requests.get(url, timeout=30)
            response.raise_for_status()

        import pdfplumber

        pdf_bytes = response.content
        pages_text: list[str] = []

        with pdfplumber.open(io.BytesIO(pdf_bytes)) as pdf:
            for i, page in enumerate(pdf.pages):
                text = page.extract_text()
                if text:
                    pages_text.append(text)

            total_pages = len(pdf.pages)
            pages_with_text = len(pages_text)

            if pages_text:
                combined = "\n".join(pages_text)
                logger.info(
                    "PDFAdapter: %d/%d 页有文本，共 %d 字",
                    pages_with_text, total_pages, len(combined),
                )
                return combined
            else:
                logger.warning(
                    "PDFAdapter: %d 页均无文本层，可能是扫描版 PDF", total_pages
                )
                return ""
