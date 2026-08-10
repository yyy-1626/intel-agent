"""
LangGraph 编排 — 声明节点、边、条件 router、fan-out

约束：
- router 必须纯 Python，不调 LLM
- 节点函数签名统一 (state) -> dict
- 流程结构全在此文件可见，路由判断不藏进节点内部

节点链：
fetch -> extract_basic -> identify_actors -> fan-out(逐actor: extract_details(IOC))
      -> ioc_filter -> aggregate -> export -> END

条件分支：
- fetch 失败/空正文 -> 直奔 export
- identify_actors 无 actor -> 跳过 fan-out 直奔 aggregate
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path

from langgraph.checkpoint.base import BaseCheckpointSaver
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, StateGraph
from langgraph.types import Send

from .nodes.actors import identify_actors_node
from .nodes.aggregate import aggregate_node
from .nodes.basic import extract_basic_node
from .nodes.extract_details import extract_details_node
from .nodes.fetch import fetch_node
from .nodes.ioc_filter import ioc_filter_node
from .state import ExtractionState

logger = logging.getLogger(__name__)


# ============================================================
# Router 函数（纯 Python，不调 LLM — 原则 2）
# ============================================================

def route_after_fetch(state: ExtractionState) -> str:
    """
    fetch 后的路由。

    早退条件：fetch_error 非空 / 正文为空 / 正文过短 (<200字)
    """
    fetch_error = state.get("fetch_error")
    report_text = state.get("report_text") or ""

    if fetch_error or not report_text or len(report_text) < 200:
        logger.info("[router] fetch 早退: error=%s, text_len=%d", fetch_error, len(report_text))
        return "export"

    return "extract_basic"


def route_after_actors(state: ExtractionState) -> str:
    """
    identify_actors 后的路由。

    跳过条件：无 actor -> 直奔 aggregate
    """
    actors = state.get("actors", [])
    if not actors:
        logger.info("[router] 无攻击者，跳过 fan-out 直奔 aggregate")
        return "aggregate"

    return "fan_out_dispatcher"


def fan_out_dispatcher(state: ExtractionState) -> dict:
    """
    No-op 节点，作为 fan-out 的出口。

    因为 add_conditional_edges + list[Send] 只能接到一个节点上，
    而 identify_actors 需要分叉（无 actor -> aggregate / 有 actor -> fan-out），
    所以先 route 到 dispatcher，再从 dispatcher 做 fan-out。
    """
    return {}


def fan_out_actor_details(state: ExtractionState) -> list[Send]:
    """
    为每个 actor 派发一个 extract_details 实例，框架并行执行。

    返回 list[Send]，LangGraph 自动并行调度。
    """
    actors = state.get("actors", [])
    report_text = state.get("report_text", "")

    sends = []
    for actor in actors:
        sends.append(
            Send(
                "extract_details",
                {
                    "_current_actor": actor,
                    "report_text": report_text,
                },
            )
        )

    logger.info("[fan-out] 派发 %d 个并行抽取任务", len(sends))
    return sends


# ============================================================
# Export 节点
# ============================================================

def export_node(state: ExtractionState) -> dict:
    """
    导出节点：输出最终 JSON。

    如果 fetch_error 非空，输出 ErrorOutput；否则输出 final_report。
    """
    import json

    fetch_error = state.get("fetch_error")
    url = state.get("url", "")

    if fetch_error:
        error_output = {
            "error": fetch_error,
            "url": url,
            "errors": state.get("errors", []),
        }
        print(json.dumps(error_output, indent=2, ensure_ascii=False))
        return {"execution_log": ["export: 错误输出"]}

    final_report = state.get("final_report") or {}
    print(json.dumps(final_report, indent=2, ensure_ascii=False))
    return {"execution_log": ["export: 完成"]}


# ============================================================
# 构建图
# ============================================================

def build_graph(
    checkpointer: BaseCheckpointSaver | None = None,
    db_path: str | Path | None = None,
) -> StateGraph:
    """
    构建并编译 LangGraph 流水线。

    Args:
        checkpointer: 外部传入的 checkpointer（优先级最高）
        db_path: SQLite checkpointer 数据库路径。默认 checkpoints.db

    Returns:
        编译后的 StateGraph 实例
    """
    builder = StateGraph(ExtractionState)

    # ---- 注册节点 ----
    builder.add_node("fetch", fetch_node)
    builder.add_node("extract_basic", extract_basic_node)
    builder.add_node("identify_actors", identify_actors_node)
    builder.add_node("fan_out_dispatcher", fan_out_dispatcher)
    builder.add_node("extract_details", extract_details_node)
    builder.add_node("ioc_filter", ioc_filter_node)
    builder.add_node("aggregate", aggregate_node)
    builder.add_node("export", export_node)

    # ---- 声明边 ----
    builder.set_entry_point("fetch")

    # fetch -> extract_basic 或 export（早退）
    builder.add_conditional_edges(
        "fetch",
        route_after_fetch,
        {
            "extract_basic": "extract_basic",
            "export": "export",
        },
    )

    # extract_basic -> identify_actors
    builder.add_edge("extract_basic", "identify_actors")

    # identify_actors -> fan_out_dispatcher 或 aggregate（跳过）
    builder.add_conditional_edges(
        "identify_actors",
        route_after_actors,
        {
            "fan_out_dispatcher": "fan_out_dispatcher",
            "aggregate": "aggregate",
        },
    )

    # fan_out_dispatcher -> fan-out extract_details（并行）
    builder.add_conditional_edges("fan_out_dispatcher", fan_out_actor_details)

    # extract_details -> ioc_filter -> aggregate（barrier: 所有 fan-out 完成 → IOC 过滤 → 聚合）
    builder.add_edge("extract_details", "ioc_filter")
    builder.add_edge("ioc_filter", "aggregate")

    # aggregate -> export
    builder.add_edge("aggregate", "export")

    # export -> END
    builder.add_edge("export", END)

    # ---- 编译 ----
    if checkpointer is not None:
        return builder.compile(checkpointer=checkpointer)

    if db_path is not None:
        db_path = Path(db_path)
    else:
        db_path = Path("checkpoints.db")

    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    return builder.compile(checkpointer=SqliteSaver(conn))


def get_default_graph() -> StateGraph:
    """获取默认的编译后图实例（带 SQLite checkpointer）"""
    return build_graph()