"""
聚合校验导出节点 — 组装 ReportOutput -> Pydantic 校验 -> 去重/补缺省

约束：永远输出合法 JSON，校验不过也要输出带 error 的结构化 JSON，不能崩。
tools/vulns/ttps 已在 identify_actors 中由 LLM 完整抽取，此处直接转换。
"""

from __future__ import annotations

import logging

from ..schemas import (
    IOC,
    TTP,
    ReportOutput,
    ThreatActor,
    Tool,
    Vulnerability,
)

logger = logging.getLogger(__name__)


def aggregate_node(state: dict) -> dict:
    """
    聚合 + 校验（LangGraph 节点函数）。

    1. 从 actor_details 组装 ThreatActor 列表
    2. 组装 ReportOutput
    3. Pydantic 校验（自动去重、补缺省）
    4. 返回 final_report
    """
    logger.info("[aggregate] 聚合结果...")

    # ---- 构建 ThreatActor 列表 ----
    threator = []
    actor_details = state.get("actor_details", [])

    for ad in actor_details:
        # 转换 IOC
        iocs = []
        for ioc_dict in ad.get("iocs", []):
            iocs.append(IOC(
                value=ioc_dict.get("value", ""),
                type=ioc_dict.get("type", "Domain"),
                threat_level=ioc_dict.get("threat_level", "未知"),
                tags=ioc_dict.get("tags", []),
                context=ioc_dict.get("context"),
                intel_source=ioc_dict.get("intel_source"),
            ))

        # 转换工具（来自 identify_actors LLM 抽取）
        tools = []
        for t_dict in ad.get("tools", []):
            tools.append(Tool(
                name=t_dict.get("name", ""),
                category=t_dict.get("category"),
                description=t_dict.get("description"),
            ))

        # 转换漏洞（来自 identify_actors LLM 抽取）
        vulnerabilities = []
        for v_dict in ad.get("vulnerabilities", []):
            vulnerabilities.append(Vulnerability(
                cve_id=v_dict.get("cve_id"),
                name=v_dict.get("name"),
            ))

        # 转换 TTP（来自 identify_actors LLM 抽取，已含完整编号/名称/战术）
        ttps = []
        for ttp_dict in ad.get("ttps", []):
            ttps.append(TTP(
                technique_id=ttp_dict.get("technique_id"),
                technique_name=ttp_dict.get("technique_name", ""),
                tactic=ttp_dict.get("tactic"),
                description=ttp_dict.get("description"),
            ))

        threator.append(ThreatActor(
            actor_id=ad.get("actor_id", ""),
            name=ad.get("name", ""),
            aliases_matched=ad.get("aliases_matched", []),
            theme=ad.get("theme", "未知"),
            is_new_org=ad.get("is_new_org", False),
            new_org_notice=ad.get("new_org_notice"),
            iocs=iocs,
            tools=tools,
            vulnerabilities=vulnerabilities,
            ttps=ttps,
        ))

    # ---- 组装 ReportOutput ----
    basic = state.get("basic") or {}

    try:
        report = ReportOutput(
            report_name=basic.get("report_name", "未知报告"),
            publish_time=basic.get("publish_time", "未知"),
            summary=basic.get("summary", ""),
            targeted_industries=basic.get("targeted_industries", []),
            targeted_countries=basic.get("targeted_countries", []),
            threator=threator,
            new_org_flags=state.get("new_org_flags", []),
            errors=state.get("errors", []),
        )

        report_dict = report.model_dump()
        logger.info(
            "[aggregate] 完成: %d 个攻击者, %d 个新组织提醒",
            len(report_dict.get("threator", [])),
            len(report_dict.get("new_org_flags", [])),
        )

        return {
            "final_report": report_dict,
            "execution_log": ["aggregate 完成"],
        }

    except Exception as e:
        # 校验不过也要输出结构化 JSON
        logger.error("[aggregate] Pydantic 校验失败: %s", e)
        error_report = {
            "report_name": basic.get("report_name", "未知报告"),
            "publish_time": basic.get("publish_time", "未知"),
            "summary": basic.get("summary", ""),
            "targeted_industries": basic.get("targeted_industries", []),
            "targeted_countries": basic.get("targeted_countries", []),
            "threator": [],
            "new_org_flags": state.get("new_org_flags", []),
            "errors": state.get("errors", []) + [f"aggregate 校验失败: {e}"],
        }
        return {
            "final_report": error_report,
            "errors": [f"aggregate 校验失败: {e}"],
            "execution_log": [f"aggregate 校验失败: {e}"],
        }