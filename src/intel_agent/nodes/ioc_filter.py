"""
IOC 过滤节点 — 在 extract_details 之后，对 LLM 抽取的 IOC 做两道纯 Python 过滤

1. 类型过滤：只保留属于 7 类 IOC（IP/Domain/Email/URL/Hash/CVE/TTP）的值，
   过滤掉 LLM 误抓的非 IOC（如 a.exe、普通文件名、注册表项等），并把 type 规范化为枚举值
2. 白名单过滤：滤掉云/CDN/安全厂商/公共 DNS/私有 IP 等良性资产

纯 Python，不调 LLM，不依赖 report_text。
编排（graph.py）稍后统一处理；节点函数签名 (state) -> dict，可挂入 fan-out 或 barrier 后。
"""

from __future__ import annotations

import logging

from ..tools.ioc_regex import classify_ioc_value
from ..tools.whitelist import get_whitelist

logger = logging.getLogger(__name__)


import re

# 威胁报告中常见的 defang（反自动化抓取）写法 → 全局替换，在 strip 之前执行
_DEFANG_REPLACEMENTS: list[tuple[str, str]] = [
    # 协议 defang：hxxp/hxxps → http/https
    (r'\bhxxp(?=s?://)', 'http'),
    # 点号 defang：[.] (.) {.} → .
    (r'\[\.\]', '.'),
    (r'\(\.\)', '.'),
    (r'\{\.\}', '.'),
    # 冒号 defang：[:] (:) → :
    (r'\[:\]', ':'),
    (r'\(:\)', ':'),
    # @ 符号 defang：[at] [@] (at) → @
    (r'\[at\]', '@'),
    (r'\[@\]', '@'),
    (r'\(at\)', '@'),
    # 协议分隔符 defang：[://] → ://
    (r'\[://\]', '://'),
]

# 预编译 defang 正则
_DEFANG_PATTERNS: list[tuple[re.Pattern, str]] = [
    (re.compile(p, re.IGNORECASE), r) for p, r in _DEFANG_REPLACEMENTS
]


def _normalize_value(value: str) -> str:
    """去掉常见包裹/尾部标点与 defang 写法，返回干净的值"""
    v = (value or "").strip()

    # 0. 全局 defang 替换（在 strip 之前，因为替换后可能产生新的首尾字符）
    for pattern, replacement in _DEFANG_PATTERNS:
        v = pattern.sub(replacement, v)

    v = v.strip("\"'“”‘’[]()<>")
    # 不剥冒号：IPv6 压缩形式可能以 "::" 结尾（如 2001:db8::）
    v = v.rstrip(".,;!?")
    return v.strip()


def filter_ioc_list(iocs: list[dict]) -> tuple[list[dict], dict]:
    """
    对单个 IOC 列表做类型过滤 + 白名单过滤。

    Args:
        iocs: 每个元素为 {value, type, threat_level, tags, context}

    Returns:
        (保留列表, 丢弃统计)。丢弃统计: {"invalid_type": [...], "whitelisted": [...]}
    """
    whitelist = get_whitelist()
    kept: list[dict] = []
    dropped = {"invalid_type": [], "whitelisted": []}

    for ioc in iocs or []:
        value = _normalize_value(ioc.get("value", ""))
        if not value:
            logger.debug("[ioc_filter] 丢弃空值: %r", ioc.get("value"))
            dropped["invalid_type"].append(ioc)
            continue
        ioc["value"] = value

        # 1. 类型过滤：只保留 7 类 IOC
        canonical_type = classify_ioc_value(value)
        if canonical_type is None:
            logger.debug("[ioc_filter] 类型过滤丢弃: %r (声明类型=%s)", value, ioc.get("type"))
            dropped["invalid_type"].append(ioc)
            continue

        # 2. 白名单过滤：滤掉良性资产
        if whitelist.is_whitelisted(value, canonical_type):
            logger.debug("[ioc_filter] 白名单丢弃: %r", value)
            dropped["whitelisted"].append(ioc)
            continue

        # type 规范化为 7 类枚举值，避免 LLM 返回 IPv4/MD5/File 等非法值导致聚合校验失败
        ioc["type"] = canonical_type
        kept.append(ioc)

    return kept, dropped


def ioc_filter_node(state: dict) -> dict:
    """
    IOC 过滤节点（LangGraph 节点函数）。

    读取 state["actor_details"]（每个 actor 含 iocs），对每个 actor 的 iocs 做过滤，
    结果经 reducer 写回 actor_details。extract_details 之后挂入即可。

    支持两种编排位置：
    - fan-out 内逐 actor（state 中只有一个 actor 的 detail）
    - fan-out barrier 后整体过滤（state 中含全部 actor 的 detail）
    """
    actor_details = state.get("actor_details", [])
    if not actor_details:
        logger.info("[ioc_filter] 无 actor_details，跳过")
        return {"execution_log": ["ioc_filter: 无 actor_details，跳过"]}

    total_kept = total_invalid = total_whitelisted = 0
    for detail in actor_details:
        iocs = detail.get("iocs", [])
        kept, dropped = filter_ioc_list(iocs)
        detail["iocs"] = kept
        total_kept += len(kept)
        total_invalid += len(dropped["invalid_type"])
        total_whitelisted += len(dropped["whitelisted"])

    logger.info(
        "[ioc_filter] 保留 %d，类型过滤 %d，白名单 %d",
        total_kept, total_invalid, total_whitelisted,
    )
    return {
        "actor_details": actor_details,
        "execution_log": [
            f"ioc_filter: 保留 {total_kept}，类型过滤 {total_invalid}，白名单 {total_whitelisted}"
        ],
    }
