"""
IOC 富化节点 — 威胁情报平台查询 + 威胁等级重判

在 validate_ioc 之后、aggregate 之前执行：
1. 从 state["actor_details"] 收集所有 IOC
2. 去重后批量查询 VT + OTX（并行）
3. 应用硬编码规则重判 threat_level
4. 记录情报来源到 intel_source
"""

from __future__ import annotations

import logging
from typing import List, Tuple

from ..state import recalculate_threat_level
from ..tools.threat_intel import query_iocs_batch

logger = logging.getLogger(__name__)


def enrich_ioc_node(state: dict) -> dict:
    """
    富化 IOC（LangGraph 节点函数）。

    直接修改 state["actor_details"] 中每个 IOC 的 threat_level 和 intel_source。
    """
    actor_details = state.get("actor_details", [])
    if not actor_details:
        logger.info("[enrich_ioc] 无 actor_details，跳过")
        return {"execution_log": ["enrich_ioc: 无数据，跳过"]}

    # ---- 第一步：收集所有 IOC（去重） ----
    ioc_collect: List[Tuple[str, str]] = []
    for actor in actor_details:
        for ioc in actor.get("iocs", []):
            value = ioc.get("value", "").strip()
            ioc_type = ioc.get("type", "")
            if value and ioc_type:
                ioc_collect.append((value, ioc_type))

    if not ioc_collect:
        logger.info("[enrich_ioc] 无 IOC 可查询")
        return {"execution_log": ["enrich_ioc: 无 IOC"]}

    logger.info("[enrich_ioc] 开始查询 %d 个 IOC...", len(ioc_collect))

    # ---- 第二步：批量查询威胁情报平台 ----
    intel_results = query_iocs_batch(ioc_collect)

    # ---- 第三步：遍历 actor，更新每个 IOC ----
    total_updated = 0
    for actor in actor_details:
        actor_name = actor.get("name", "unknown")
        for ioc in actor.get("iocs", []):
            value = ioc.get("value", "").strip()
            if value not in intel_results:
                continue

            intel_data = intel_results[value]
            llm_level = ioc.get("threat_level", "未知")

            # 应用硬编码规则重判等级
            new_level, intel_summary = recalculate_threat_level(
                llm_level=llm_level,
                vt_stats=intel_data.get("vt"),
                otx_stats=intel_data.get("otx"),
            )

            # 更新威胁等级
            if new_level != llm_level:
                logger.debug(
                    "[enrich_ioc] %s: %s %s -> %s (vt=%s, otx=%s)",
                    actor_name, value, llm_level, new_level,
                    intel_data.get("vt", {}).get("detections", "N/A") if intel_data.get("vt") else "无数据",
                    intel_data.get("otx", {}).get("pulses", "N/A") if intel_data.get("otx") else "无数据",
                )

            ioc["threat_level"] = new_level
            ioc["intel_source"] = intel_summary
            total_updated += 1

    logger.info("[enrich_ioc] 富化完成，更新 %d 个 IOC", total_updated)
    return {
        "execution_log": [f"enrich_ioc: 查询 {len(intel_results)} 个 IOC，更新 {total_updated} 个"],
    }