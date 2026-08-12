"""
抓取节点 — URL -> 正文纯文本

约束：
- 异常不抛，写结构化错误字段让 router 早退
- 不调 LLM
- requests+readability 为主，Playwright 兜底
- 非 HTML 内容通过适配器提取（PDF/纯文本等）
- URL 型适配器（YouTube）在 HTML 之前优先判断
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _try_url_adapters(url: str) -> Optional[str]:
    """URL 型适配器优先判断（如 YouTube），不需要等待 HTTP 响应。"""
    try:
        from ..adapters import get_adapters
    except ImportError:
        return None

    for adapter in get_adapters():
        if adapter.can_handle("", url):
            logger.info("[adapter-url] 尝试 %s", type(adapter).__name__)
            try:
                text = adapter.extract(url)
                if text and len(text.strip()) >= 200:
                    logger.info("[adapter-url] %s 成功: %d 字", type(adapter).__name__, len(text))
                    return text
            except Exception as e:
                logger.warning("[adapter-url] %s 失败: %s", type(adapter).__name__, e)
    return None


def _try_adapters(url: str, content_type: str, response) -> tuple[Optional[str], Optional[str]]:
    """遍历适配器尝试提取文本（PDF/纯文本等非 HTML 内容）。"""
    try:
        from ..adapters import get_adapters
    except ImportError:
        return None, "适配器模块不可用"

    for adapter in get_adapters():
        if adapter.can_handle(content_type, url):
            logger.info("[adapter] 尝试 %s 处理 %s", type(adapter).__name__, url)
            try:
                text = adapter.extract(url, response)
                if text and len(text.strip()) >= 200:
                    logger.info("[adapter] %s 成功: %d 字", type(adapter).__name__, len(text))
                    return text, None
                if text and len(text.strip()) > 0:
                    logger.warning("[adapter] %s 文本过短：%d 字", type(adapter).__name__, len(text))
                    return text, None
                logger.warning("[adapter] %s 返回空文本", type(adapter).__name__)
                return None, f"{type(adapter).__name__} 返回空文本"
            except Exception as e:
                logger.warning("[adapter] %s 失败: %s", type(adapter).__name__, e)
                continue

    return None, None


def fetch_report_text(url: str, timeout: int = 15) -> tuple[Optional[str], Optional[str]]:
    """抓取报告正文。策略：
    1. URL 型适配器优先（YouTube 等，不依赖 Content-Type）
    2. requests + readability-lxml 处理 HTML
    3. 非 HTML 内容通过 Content-Type 适配器（PDF 等）
    4. Playwright 兜底
    """
    import requests
    from bs4 import BeautifulSoup

    # ---- 0. URL 型适配器优先 ----
    url_text = _try_url_adapters(url)
    if url_text:
        return url_text, None

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7",
    }

    # ---- 第一阶段：requests + readability ----
    try:
        resp = requests.get(url, timeout=timeout, headers=headers, allow_redirects=True)
        resp.raise_for_status()

        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            adapter_text, adapter_error = _try_adapters(url, content_type, resp)
            if adapter_text is not None:
                return adapter_text, None
            if adapter_error is not None:
                return None, adapter_error
            text = resp.text.strip()
            if len(text) >= 200:
                return text, None
            return None, f"Content-Type 非 HTML ({content_type})，正文 {len(text)} 字"

        try:
            from readability import Document
            doc = Document(resp.text)
            html_content = doc.summary()
        except ImportError:
            html_content = resp.text

        text = BeautifulSoup(html_content, "lxml").get_text(" ", strip=True)

        if len(text) >= 200:
            logger.info("requests+readability 成功: %d 字", len(text))
            return text, None

        logger.info("正文过短（%d 字），尝试 Playwright 兜底", len(text))

    except requests.exceptions.Timeout:
        logger.warning("requests 超时: %s", url)
    except requests.exceptions.HTTPError as e:
        logger.warning("HTTP 错误: %s", e)
        return None, f"HTTP 错误: {e}"
    except requests.exceptions.RequestException as e:
        logger.warning("requests 请求异常: %s", e)
    except Exception as e:
        logger.warning("requests 解析异常: %s", e)

    # ---- 第二阶段：Playwright 兜底 ----
    try:
        text = _fetch_with_playwright(url, timeout)
        if text and len(text) >= 200:
            logger.info("Playwright 兜底成功: %d 字", len(text))
            return text, None
        return None, f"Playwright 兜底后正文仍过短（{len(text) if text else 0} 字）"
    except ImportError:
        return None, "requests 失败且 Playwright 未安装（pip install playwright）"
    except Exception as e:
        logger.warning("Playwright 兜底失败: %s", e)
        return None, f"requests 和 Playwright 均失败: {e}"


def _fetch_with_playwright(url: str, timeout: int = 15) -> Optional[str]:
    """使用 Playwright 抓取 JS 渲染页面"""
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        try:
            page.goto(url, timeout=timeout * 1000, wait_until="domcontentloaded")
            page.wait_for_timeout(2000)
            text = page.inner_text("body")
            return text.strip()
        finally:
            browser.close()


def fetch_node(state: dict) -> dict:
    url = state["url"]
    logger.info("[fetch] 开始抓取: %s", url)
    report_text, error = fetch_report_text(url)
    if error:
        logger.warning("[fetch] 失败: %s", error)
        return {"report_text": None, "fetch_error": error, "execution_log": [f"fetch 失败: {error}"]}
    logger.info("[fetch] 成功: %d 字", len(report_text))
    return {"report_text": report_text, "fetch_error": None, "execution_log": [f"fetch 成功: {len(report_text)} 字"]}
