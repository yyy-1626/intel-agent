"""YouTube 适配器 — 提取视频自动字幕"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Optional

import requests

from .base import ContentAdapter

logger = logging.getLogger(__name__)

# YouTube URL 模式
YOUTUBE_PATTERNS = [
    "youtube.com/watch",
    "youtu.be/",
    "m.youtube.com/watch",
    "youtube.com/shorts",
    "youtube.com/live",
]

_YTDLP_AVAILABLE: Optional[bool] = None


def _check_ytdlp() -> bool:
    global _YTDLP_AVAILABLE
    if _YTDLP_AVAILABLE is None:
        try:
            import yt_dlp  # noqa: F401
            _YTDLP_AVAILABLE = True
        except ImportError:
            _YTDLP_AVAILABLE = False
    return _YTDLP_AVAILABLE


class YouTubeAdapter(ContentAdapter):
    """提取 YouTube 视频的自动字幕（中/英文优先）。"""

    def can_handle(self, content_type: str, url: str) -> bool:
        if not _check_ytdlp():
            return False
        url_lower = url.lower()
        return any(p in url_lower for p in YOUTUBE_PATTERNS)

    def extract(self, url: str, response: Optional[requests.Response] = None) -> str:
        import yt_dlp

        with tempfile.TemporaryDirectory() as tmpdir:
            opts = {
                "quiet": True,
                "no_warnings": True,
                "writeautomaticsub": True,
                "subtitleslangs": ["zh-Hans", "zh", "en"],
                "skip_download": True,
                "outtmpl": os.path.join(tmpdir, "%(id)s"),
                "ignoreerrors": True,
            }

            with yt_dlp.YoutubeDL(opts) as ydl:
                info = ydl.extract_info(url, download=False)
                if info is None:
                    return ""

                # 检查是否有字幕
                subs = info.get("subtitles") or {}
                auto_subs = info.get("automatic_captions") or {}
                all_subs = {**auto_subs, **subs}  # 手动字幕优先

                if not all_subs:
                    logger.warning("YouTubeAdapter: 该视频无字幕")
                    return ""

                # 下载字幕
                ydl.download([url])

            # 在 tmpdir 中找 .vtt/.srt 文件
            subtitle_files = [
                os.path.join(tmpdir, f)
                for f in os.listdir(tmpdir)
                if f.endswith((".vtt", ".srt"))
            ]

            if not subtitle_files:
                logger.warning("YouTubeAdapter: 字幕下载失败")
                return ""

            # 解析每个字幕文件
            all_text: list[str] = []
            for sf in sorted(subtitle_files):
                text = _parse_subtitle(sf)
                if text:
                    lang = os.path.splitext(sf)[0].split(".")[-1]
                    all_text.append(f"[字幕-{lang}]\n{text}")

            combined = "\n\n".join(all_text)
            logger.info("YouTubeAdapter: 提取 %d 个字幕文件，共 %d 字",
                        len(subtitle_files), len(combined))
            return combined


def _parse_subtitle(filepath: str) -> str:
    """解析 .srt 或 .vtt 字幕文件，提取纯文本行。"""
    lines: list[str] = []

    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    # VTT 格式：去掉头部 WEBVTT 和时序行
    if filepath.endswith(".vtt"):
        content = content.replace("\r\n", "\n")

    for line in content.split("\n"):
        line = line.strip()
        # 跳过序号、时间戳、空行、HTML 标签
        if not line:
            continue
        if line.isdigit():
            continue
        if "-->" in line:
            continue
        if line.startswith("WEBVTT") or line.startswith("Kind:"):
            continue
        if line.startswith("<") and line.endswith(">"):
            continue
        # 去 HTML 标签（如 <c>、</c>）
        import re
        line = re.sub(r"<[^>]+>", "", line)
        line = line.strip()
        if line:
            lines.append(line)

    return " ".join(lines)
