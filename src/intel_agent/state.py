"""
ExtractionState — LangGraph 状态定义

约束：
- 多个节点并行写同一字段必须配 reducer，否则后写覆盖先写（fan-out 致命坑）
- fan-out 并写场景：actor_details 按 actor_id 去重归并、errors 追加
- actors 字段仅在 identify_actors 单次 LLM 调用中写入，不存在并行写冲突
"""

from __future__ import annotations

import operator
from typing import Annotated, Optional, TypedDict


def merge_actor_details(left: list[dict], right: list[dict]) -> list[dict]:
    """
    Reducer: 按 actor_id 去重归并 actor_details。

    fan-out 并行写时使用，同 actor_id 后到达的覆盖。
    """
    merged: dict[str, dict] = {}
    for a in left:
        merged[a.get("actor_id", a.get("name", ""))] = a
    for a in right:
        merged[a.get("actor_id", a.get("name", ""))] = a
    return list(merged.values())


class ExtractionState(TypedDict):
    """情报抽取流水线状态"""

    # ---- 输入 ----
    url: str
    """报告 URL"""

    report_text: Optional[str]
    """报告正文纯文本。抓取后填充，或通过 --text 直接传入"""

    # ---- 抓取 ----
    fetch_error: Optional[str]
    """抓取错误信息。非空时 router 早退到 export"""

    # ---- 基础信息 ----
    basic: Optional[dict]
    """基础信息抽取结果（BasicInfo 的 dict 形式）"""

    # ---- 攻击者 ----
    actors: list[dict]
    """
    识别到的攻击者列表（identify_actors 单次 LLM 调用产出）。
    每个元素: {actor_id, name, theme, aliases_matched, is_new_org, new_org_notice,
               iocs, tools, vulnerabilities, ttps}
    tools/vulnerabilities/ttps 在此节点已由 LLM 完整抽取。
    """

    new_org_flags: list[str]
    """新组织提醒列表"""

    # ---- 逐 actor 抽取（fan-out 并行，仅 IOC） ----
    actor_details: Annotated[list[dict], merge_actor_details]
    """
    fan-out 并行抽取的 IOC 详情，reducer 按 actor_id 归并。
    每个元素: {actor_id, name, iocs, tools, vulnerabilities, ttps}
    其中 tools/vulnerabilities/ttps 从 _current_actor 透传，iocs 由 LLM 抽取。
    """

    # ---- 最终输出 ----
    final_report: Optional[dict]
    """聚合后的最终报告（ReportOutput 的 dict 形式）"""

    # ---- 执行状态 ----
    execution_log: Annotated[list[str], operator.add]
    """执行日志（追加）"""

    errors: Annotated[list[str], operator.add]
    """错误列表（追加）"""

    # ---- fan-out 内部使用 ----
    _current_actor: Optional[dict]
    """临时字段：fan-out 分发给 extract_details 的当前 actor 信息"""

def recalculate_threat_level(
    llm_level: str,
    vt_stats: dict | None = None,
    otx_stats: dict | None = None,
) -> tuple[str, dict]:
    """
    根据 LLM 原始等级 + 威胁情报平台数据，重新计算威胁等级。

    硬编码规则（优先级从高到低）：
    1. OTX 有活跃脉冲 → 恶意（社区共识）
    2. VT 检测数 > 10 → 恶意（高置信度）
    3. VT 检测数 5-10 → 恶意（中置信度）
    4. VT 检测数 1-4：若 LLM 判恶意 → 保持恶意（不冤枉）；否则 → 可疑
    5. VT 检测数 = 0：若 LLM 判恶意 → 降级为可疑（合法工具被滥用场景，如 Telegram C2）
    6. 任何平台查询失败 → 保留 LLM 原始等级

    Args:
        llm_level: LLM 初始判定的威胁等级（恶意/可疑/未知/白名单）
        vt_stats: {'detections': int, 'total': int} | None
        otx_stats: {'pulses': int} | None

    Returns:
        (新威胁等级, 情报摘要 dict) 元组
    """
    vt_detections = vt_stats.get("detections", 0) if vt_stats else 0
    otx_pulses = otx_stats.get("pulses", 0) if otx_stats else 0

    intel_summary = {
        "vt_detections": vt_detections,
        "otx_pulses": otx_pulses,
    }

    # ---- 规则 1: OTX 活跃脉冲 -> 恶意 ----
    if otx_pulses > 0:
        return "恶意", intel_summary

    # ---- 规则 2 & 3: VT 高检测数 -> 恶意 ----
    if vt_detections > 10:
        return "恶意", intel_summary
    if vt_detections >= 5:
        return "恶意", intel_summary

    # ---- 规则 4: VT 低检测数 (1-4) ----
    if vt_detections >= 1:
        # 如果 LLM 认为是恶意，保持恶意（谨慎原则，不冤枉）
        if llm_level == "恶意":
            return "恶意", intel_summary
        # 否则保守为可疑
        return "可疑", intel_summary

    # ---- 规则 5: VT 检测数为 0 ----
    if vt_detections == 0:
        # 场景：LLM 认为是恶意，但 VT 没检出
        # 可能是合法工具被滥用（如 Telegram、TeamViewer、AnyDesk 被用作 C2）
        if llm_level == "恶意":
            # 降级为可疑，提醒分析师人工研判
            return "可疑", intel_summary
        # 如果 LLM 已经是可疑/未知，保持原样
        return llm_level, intel_summary

    # ---- 默认：保底返回 LLM 等级 ----
    return llm_level, intel_summary