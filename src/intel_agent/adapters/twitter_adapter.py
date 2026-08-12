"""Twitter/X 适配器 — 通过 fxtwitter API 提取推文文本"""

from __future__ import annotations

import logging
import re
from typing import Optional

import requests

from .base import ContentAdapter

logger = logging.getLogger(__name__)

# Twitter/X URL 模式
TWITTER_PATTERN = re.compile(
    r"(?:twitter\.com|x\.com)/(\w+)/status/(\d+)",
    re.IGNORECASE,
)


class TwitterAdapter(ContentAdapter):
    """提取 Twitter/X 推文文本。通过 fxtwitter API 获取结构化数据。"""

    def can_handle(self, content_type: str, url: str) -> bool:
        return bool(TWITTER_PATTERN.search(url))

    def extract(self, url: str, response: Optional[requests.Response] = None) -> str:
        match = TWITTER_PATTERN.search(url)
        if not match:
            return ""

        user, tweet_id = match.group(1), match.group(2)

        # 方案1: fxtwitter API（返回 JSON，含推文全文）
        text = self._try_fxtwitter(user, tweet_id)
        if text:
            return text

        # 方案2: 直接请求 + HTML 解析
        text = self._try_direct(url)
        if text:
            return text

        return ""

    def _try_fxtwitter(self, user: str, tweet_id: str) -> str:
        """通过 fxtwitter/vxtwitter API 获取推文。"""
        apis = [
            f"https://api.fxtwitter.com/{user}/status/{tweet_id}",
            f"https://api.vxtwitter.com/{user}/status/{tweet_id}",
        ]
        for api_url in apis:
            try:
                resp = requests.get(api_url, timeout=15, headers={
                    "User-Agent": "Mozilla/5.0 (compatible; intel-agent/1.0)"
                })
                if resp.status_code != 200:
                    continue
                data = resp.json()
                tweet = data.get("tweet") or data
                tweet_text = tweet.get("text", "")
                if tweet_text:
                    # 拼接引用推文
                    quote = tweet.get("quote")
                    if quote and quote.get("text"):
                        tweet_text += "\n\n[引用推文] " + quote["text"]
                    logger.info("TwitterAdapter(fxtwitter): %d 字", len(tweet_text))
                    return tweet_text
            except Exception as e:
                logger.debug("TwitterAdapter(fxtwitter) %s 失败: %s", api_url, e)

        return ""

    def _try_direct(self, url: str) -> str:
        """直接请求 HTML，尝试从 meta/og 标签提取。"""
        try:
            headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/120.0.0.0 Safari/537.36"
                ),
                "Accept-Language": "en-US,en;q=0.9",
            }
            resp = requests.get(url, timeout=15, headers=headers)
            if resp.status_code != 200:
                return ""

            html = resp.text

            # 尝试 og:description（Twitter 会把推文内容放这里）
            og_match = re.search(
                r'<meta[^>]+property="og:description"[^>]+content="([^"]+)"',
                html,
            )
            if og_match:
                text = og_match.group(1)
                logger.info("TwitterAdapter(direct): og:description %d 字", len(text))
                return text

        except Exception:
            pass

        return ""
