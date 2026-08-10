"""
IOC 正则工具 — 规则在 config/ioc_regex.yaml，本文件只做加载/匹配逻辑

两个职责：
1. 召回（格式召回，不判级）：extract_* 系列从文本中提取 IOC 候选
2. 判定：classify_ioc_value 判断单个值属于 7 类 IOC（IP/Domain/Email/URL/Hash/CVE/TTP）中的哪一类，
   供 ioc_filter 节点过滤 LLM 误抓的非 IOC
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

# 默认配置文件路径
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "ioc_regex.yaml"

# 7 类规范 IOC 类型（与 schemas.IOCTypeEnum 一致）
IOC_TYPES = ("IP", "Domain", "Email", "URL", "Hash", "CVE", "TTP")

# 需要词边界包裹的类别：避免把长字符串内部的子串误召回（如 64 位 hex 中误匹配 32 位）
_WORD_BOUNDED_CATEGORIES = {"IP", "Domain", "Email", "Hash", "CVE", "TTP"}


class IOCRegexConfig:
    """IOC 正则配置：加载 config/ioc_regex.yaml 并编译规则"""

    def __init__(self, config_path: Path | None = None):
        self._config_path = config_path or DEFAULT_CONFIG_PATH
        self._extract_regexes: list[dict] = []          # [{label, category, regex}]
        self._verification: dict[str, list[re.Pattern]] = {}  # category -> [fullmatch patterns]
        self._load_config()

    def _load_config(self) -> None:
        if not self._config_path.exists():
            logger.error("ioc_regex.yaml 不存在: %s，规则为空", self._config_path)
            return

        with open(self._config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        for entry in config.get("patterns", []):
            label = entry.get("name", "")
            category = entry.get("category", "")
            pattern = entry.get("pattern", "")
            if not label or not pattern:
                continue

            if category in _WORD_BOUNDED_CATEGORIES:
                regex = re.compile(rf'(?<!\w)(?:{pattern})(?!\w)', re.IGNORECASE)
            else:
                regex = re.compile(pattern, re.IGNORECASE)

            self._extract_regexes.append({
                "label": label,
                "category": category,
                "regex": regex,
            })

            if category in IOC_TYPES:
                # 类型判定用原 pattern 做整体匹配（fullmatch），边界已由调用方保证
                self._verification.setdefault(category, []).append(
                    re.compile(pattern, re.IGNORECASE)
                )

        logger.info(
            "加载 ioc_regex.yaml: %d 条规则, %d 类",
            len(self._extract_regexes),
            len(self._verification),
        )

    def extract_labels(self) -> list[dict]:
        """返回 [{label, category, regex}] 全部召回规则"""
        return self._extract_regexes

    def classify(self, value: str) -> str | None:
        """判断单个 IOC 值属于 7 类中的哪一类，不属于返回 None"""
        v = value.strip()
        if not v:
            return None
        for category, patterns in self._verification.items():
            for pat in patterns:
                if pat.fullmatch(v):
                    return category
        return None


# 全局单例
_regex_config: IOCRegexConfig | None = None


def get_regex_config(config_path: Path | None = None) -> IOCRegexConfig:
    """获取 IOC 正则配置单例"""
    global _regex_config
    if _regex_config is None:
        _regex_config = IOCRegexConfig(config_path)
    return _regex_config


def _extract_by_label(label: str, text: str) -> list[tuple[str, str]]:
    """按标签提取，返回 [(value, label), ...]"""
    results: list[tuple[str, str]] = []
    for entry in get_regex_config().extract_labels():
        if entry["label"] == label:
            for m in entry["regex"].finditer(text):
                results.append((m.group(), label))
    return results


def classify_ioc_value(value: str) -> str | None:
    """
    判断单个 IOC 值属于 7 类（IP/Domain/Email/URL/Hash/CVE/TTP）中的哪一类。

    Args:
        value: IOC 值，如 '192.168.1.1' / 'evil.com' / 'a.exe'

    Returns:
        规范类型名（'IP'/'Domain'/...），不属于 7 类返回 None
    """
    return get_regex_config().classify(value)


# ============================================================
# 召回函数（格式召回，不判级）
# ============================================================

def extract_ipv4(text: str) -> list[tuple[str, str]]:
    """提取 IPv4 地址"""
    return _extract_by_label("IPv4", text)


def extract_ipv6(text: str) -> list[tuple[str, str]]:
    """提取 IPv6 地址"""
    return _extract_by_label("IPv6", text)


def extract_domain(text: str) -> list[tuple[str, str]]:
    """提取域名"""
    return _extract_by_label("Domain", text)


def extract_url(text: str) -> list[tuple[str, str]]:
    """提取 URL"""
    return _extract_by_label("URL", text)


def extract_hash(text: str) -> list[tuple[str, str]]:
    """提取各类哈希值（MD5/SHA1/SHA256）"""
    results: list[tuple[str, str]] = []
    for label in ("MD5", "SHA1", "SHA256"):
        results.extend(_extract_by_label(label, text))
    return results


def extract_file_path(text: str) -> list[tuple[str, str]]:
    """提取文件路径"""
    return _extract_by_label("FilePath", text)


def extract_registry(text: str) -> list[tuple[str, str]]:
    """提取注册表项"""
    return _extract_by_label("Registry", text)


def extract_email(text: str) -> list[tuple[str, str]]:
    """提取邮箱地址"""
    return _extract_by_label("Email", text)


def extract_all_ioc_candidates(text: str) -> list[tuple[str, str]]:
    """
    从文本中召回所有 IOC 候选。

    Args:
        text: 报告正文（纯文本）

    Returns:
        [(value, candidate_type), ...] 按配置顺序 + 原文出现顺序，已去重
    """
    all_candidates: list[tuple[str, str]] = []
    for entry in get_regex_config().extract_labels():
        for m in entry["regex"].finditer(text):
            all_candidates.append((m.group(), entry["label"]))

    # 按值去重，保持首次出现顺序
    seen: set = set()
    deduped: list[tuple[str, str]] = []
    for val, typ in all_candidates:
        key = (val.strip().lower(), typ)
        if key not in seen:
            seen.add(key)
            deduped.append((val, typ))

    return deduped
