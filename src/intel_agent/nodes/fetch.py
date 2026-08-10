"""
抓取节点 — URL -> 正文纯文本

约束：
- 异常不抛，写结构化错误字段让 router 早退
- 不调 LLM
- requests+readability 为主，Playwright 兜底
- 非 HTML 内容通过适配器提取（PDF/纯文本等）
"""

from __future__ import annotations

import logging
from typing import Optional

logger = logging.getLogger(__name__)


def _try_adapters(url: str, content_type: str, response) -> tuple[Optional[str], Optional[str]]:
    """
    遍历适配器尝试提取文本（PDF/纯文本等非 HTML 内容）。

    Returns:
        (report_text, error) — 成功时 error 为 None
    """
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
                    logger.warning("[adapter] %s 提取文本过短：%d 字", type(adapter).__name__, len(text))
                    return text, None
                logger.warning("[adapter] %s 返回空文本（可能是扫描版 PDF）", type(adapter).__name__)
                return None, f"{type(adapter).__name__} 返回空文本（可能是扫描版）"
            except Exception as e:
                logger.warning("[adapter] %s 失败: %s", type(adapter).__name__, e)
                continue

    return None, None  # 无适配器匹配


def fetch_report_text(url: str, timeout: int = 15) -> tuple[Optional[str], Optional[str]]:
    """
    抓取报告正文。

    策略：
    1. requests + readability-lxml 处理 HTML
    2. 非 HTML 内容通过适配器（PDF/纯文本等）提取
    3. Playwright 兜底

    Args:
        url: 报告 URL
        timeout: 请求超时（秒）

    Returns:
        (report_text, error) — 成功时 error 为 None，失败时 report_text 为 None
    """
    import requests
    from bs4 import BeautifulSoup

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

        # 检查是否为 HTML 内容
        content_type = resp.headers.get("Content-Type", "")
        if "text/html" not in content_type and "application/xhtml" not in content_type:
            # 非 HTML → 先尝试适配器（PDF/纯文本等）
            adapter_text, adapter_error = _try_adapters(url, content_type, resp)
            if adapter_text is not None:
                return adapter_text, None
            if adapter_error is not None:
                return None, adapter_error
            # 适配器不匹配，回退到直接读响应文本
            text = resp.text.strip()
            if len(text) >= 200:
                return text, None
            return None, f"Content-Type 非 HTML ({content_type})，正文 {len(text)} 字"

        # readability 抽取正文
        try:
            from readability import Document
            doc = Document(resp.text)
            html_content = doc.summary()
        except ImportError:
            html_content = resp.text

        # 清洗 HTML 标签
        text = BeautifulSoup(html_content, "lxml").get_text(" ", strip=True)

        if len(text) >= 200:
            logger.info("requests+readability 成功: %d 字", len(text))
            return text, None

        # 正文过短，尝试 Playwright 兜底
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
            page.wait_for_timeout(2000)  # 额外等待 JS 渲染
            text = page.inner_text("body")
            return text.strip()
        finally:
            browser.close()


def fetch_node(state: dict) -> dict:
    """
    抓取节点（LangGraph 节点函数）。

    返回部分 state，框架按 reducer 合并。
    """
    url = state["url"]
    logger.info("[fetch] 开始抓取: %s", url)

    report_text, error = fetch_report_text(url)

    if error:
        logger.warning("[fetch] 失败: %s", error)
        return {
            "report_text": None,
            "fetch_error": error,
            "execution_log": [f"fetch 失败: {error}"],
        }

    logger.info("[fetch] 成功: %d 字", len(report_text))
    return {
        "report_text": report_text,
        "fetch_error": None,
        "execution_log": [f"fetch 成功: {len(report_text)} 字"],
    }
