"""
Pydantic 模型定义 — 单一真相源 (Single Source of Truth)

此文件同时服务于：
1. with_structured_output 的目标类型（LLM 结构化输出）
2. 运行时校验（Pydantic 自动校验）
3. JSON 导出（model_dump / model_dump_json）
4. 设计说明书中的 JSON Schema（model_json_schema()）

字段口径以需求 2.2 为准。
改字段只改此处，四处同步。
"""

from __future__ import annotations

from datetime import date
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ============================================================
# Enum 约束
# ============================================================

class ThemeEnum(str, Enum):
    """攻击者类型（theme 字段取值） 文档中只有 APT / 恶意代码家族 两个值"""
    APT = "APT"
    MALWARE_FAMILY = "恶意代码家族"
    UNKNOWN = "未知"


class IOCTypeEnum(str, Enum):
    """IOC 类型（type 字段取值）"""
    IP = "IP"
    DOMAIN = "Domain"
    EMAIL = "Email"
    URL = "URL"
    HASH = "Hash"
    CVE = "CVE"
    TTP = "TTP"

class ThreatLevelEnum(str, Enum):
    """威胁等级（threat_level 字段取值，必填，缺省为"未知"）"""
    MALICIOUS = "恶意"
    SUSPICIOUS = "可疑"
    UNKNOWN = "未知"
    WHITELIST = "白名单"


# ============================================================
# 子模型
# ============================================================

class BasicInfo(BaseModel):
    """基础信息抽取结果 — 节点 extract_basic 产出"""
    report_name: str = Field(
        description="报告原始标题，若无法确定则填'未知报告'",
        min_length=1,
    )
    publish_time: str = Field(
        description="发布时间，格式 YYYY-MM-DD。若报告无明确时间则用事件时间，仍无法确定则填'未知'",
        default="未知",
    )
    summary: str = Field(
        description="报告概述，简要描述报告主要内容，不超过 300 字",
    )
    targeted_industries: list[str] = Field(
        description="受攻击/影响的行业列表，如 ['政府', '金融', '能源']。若无法确定则为空列表",
        default_factory=list,
    )
    targeted_countries: list[str] = Field(
        description="涉及的国家/地区列表，如 ['中国', '美国']。若无法确定则为空列表",
        default_factory=list,
    )
    confidence: Optional[float] = Field(
        description="抽取置信度，0.0-1.0。用于 LLM 产信号、代码做路由（原则 4）",
        default=None,
        ge=0.0,
        le=1.0,
    )

    @field_validator("summary")
    @classmethod
    def check_summary_length(cls, v: str) -> str:
        if len(v) > 300:
            # 截断而不是报错，避免 LLM 输出超长导致整个抽取失败
            return v[:300] + "…"
        return v

    @field_validator("publish_time")
    @classmethod
    def check_publish_time_format(cls, v: str) -> str:
        if v == "未知":
            return v
        # 校验 YYYY-MM-DD 格式
        try:
            date.fromisoformat(v)
        except (ValueError, TypeError):
            raise ValueError(f"publish_time 格式错误: '{v}'，应为 YYYY-MM-DD 或 '未知'")
        return v


class IOC(BaseModel):
    """IOC 条目 — 节点 extract_ioc 产出"""
    value: str = Field(
        description="IOC 值，如 '192.168.1.1'、'malware.exe'、'abc123...'",
    )
    type: IOCTypeEnum = Field(
        description="IOC 类型：IP/Domain/URL/File/Email/TTP/CVE",
    )
    threat_level: ThreatLevelEnum = Field(
        description="威胁等级：恶意/可疑/未知/白名单。必填，无法确定时填'未知'",
        default=ThreatLevelEnum.UNKNOWN,
    )
    tags: list[str] = Field(
        description="附加标签，如 ['C2', 'Downloader', 'Phishing']",
        default_factory=list,
    )
    context: Optional[str] = Field(
        description="该 IOC 在报告中的上下文说明",
        default=None,
    )
    intel_source: Optional[dict] = Field(
        description="威胁情报平台查询结果摘要，如 {'vt_detections': 5, 'otx_pulses': 2}",
        default=None,
    )


class Tool(BaseModel):
    """工具/恶意软件 — 节点 extract_details 产出"""
    name: str = Field(description="工具/恶意软件名称")
    category: Optional[str] = Field(
        description="分类：RAT/Downloader/Dropper/Exploit Kit/后门/勒索软件/正常工具",
        default=None,
    )
    description: Optional[str] = Field(
        description="工具在报告中的使用描述",
        default=None,
    )


class Vulnerability(BaseModel):
    """漏洞 — 节点 extract_details 产出"""
    cve_id: Optional[str] = Field(
        description="CVE 编号，如 'CVE-2021-34527'",
        default=None,
    )
    name: Optional[str] = Field(
        description="漏洞名称，如 'PrintNightmare'",
        default=None,
    )



class TTP(BaseModel):
    """ATT&CK 技战术 — 节点 identify_actors 产出，LLM 直接给出完整编号/名称/战术"""
    technique_id: Optional[str] = Field(
        description="ATT&CK 技术编号，如 'T1566.001'",
        default=None,
    )
    technique_name: str = Field(
        description="技术名称，如 '鱼叉式钓鱼附件'",
    )
    tactic: Optional[str] = Field(
        description="所属战术，如 '初始访问'",
        default=None,
    )
    description: Optional[str] = Field(
        description="该技术在报告中的具体表现描述",
        default=None,
    )


class ThreatActor(BaseModel):
    """攻击者/威胁组织 — 节点 identify_actors + extract_details 产出"""
    actor_id: str = Field(
        description="攻击者唯一标识，配置中的 id 或根据名称生成",
    )
    name: str = Field(
        description="攻击者名称",
    )
    aliases_matched: list[str] = Field(
        description="在正文中匹配到的别名列表",
        default_factory=list,
    )
    theme: ThemeEnum = Field(
        description="攻击者类型：APT/恶意代码家族/未知",
        default=ThemeEnum.UNKNOWN,
    )
    is_new_org: bool = Field(
        description="是否为新组织（不在 actors.yaml 配置中）",
        default=False,
    )
    new_org_notice: Optional[str] = Field(
        description="新组织提醒文案：'该组织可能是新组织，建议核实后更新攻击组织档案库'",
        default=None,
    )
    iocs: list[IOC] = Field(
        description="该攻击者关联的 IOC 列表",
        default_factory=list,
    )
    tools: list[Tool] = Field(
        description="该攻击者使用的工具/恶意软件列表",
        default_factory=list,
    )
    vulnerabilities: list[Vulnerability] = Field(
        description="该攻击者利用的漏洞列表",
        default_factory=list,
    )
    ttps: list[TTP] = Field(
        description="该攻击者相关的 ATT&CK 技战术列表",
        default_factory=list,
    )


# ============================================================
# 顶层输出模型
# ============================================================

class ReportOutput(BaseModel):
    """情报抽取顶层输出 — 最终聚合校验后的完整报告"""
    report_name: str = Field(
        description="报告原始标题",
    )
    publish_time: str = Field(
        description="发布时间，格式 YYYY-MM-DD",
        default="未知",
    )
    summary: str = Field(
        description="报告概述，不超过 300 字",
    )
    targeted_industries: list[str] = Field(
        description="受攻击行业列表",
        default_factory=list,
    )
    targeted_countries: list[str] = Field(
        description="涉及国家/地区列表",
        default_factory=list,
    )
    threator: list[ThreatActor] = Field(
        description="识别到的威胁行为者/攻击组织列表（顶层键名按需求 2.2 为 threator）",
        default_factory=list,
    )
    new_org_flags: list[str] = Field(
        description="新组织提醒列表，每个元素为 'xxx 可能是新组织，建议核实后更新攻击组织档案库'",
        default_factory=list,
    )
    errors: list[str] = Field(
        description="抽取过程中记录的非致命错误",
        default_factory=list,
    )

    @field_validator("summary")
    @classmethod
    def check_summary_length(cls, v: str) -> str:
        if len(v) > 300:
            # 截断而不是报错，避免 LLM 输出超长导致整个抽取失败
            return v[:300] + "…"
        return v

    @model_validator(mode="after")
    def deduplicate_iocs(self) -> "ReportOutput":
        """全局 IOC 去重：按 value 去重，保留首次出现的条目"""
        seen = set()
        for actor in self.threator:
            deduped: list[IOC] = []
            for ioc in actor.iocs:
                key = (ioc.value.strip().lower(), ioc.type.value)
                if key not in seen:
                    seen.add(key)
                    deduped.append(ioc)
            actor.iocs = deduped
        return self

    @model_validator(mode="after")
    def fill_default_threat_level(self) -> "ReportOutput":
        """threat_level 缺省补'未知'"""
        for actor in self.threator:
            for ioc in actor.iocs:
                if ioc.threat_level is None:
                    ioc.threat_level = ThreatLevelEnum.UNKNOWN
        return self


# ============================================================
# 错误输出模型（抓取失败等异常场景）
# ============================================================

class ErrorOutput(BaseModel):
    """异常/失败场景的结构化输出"""
    error: str = Field(description="错误描述")
    url: str = Field(description="出错的 URL")
    errors: list[str] = Field(
        description="详细错误列表",
        default_factory=list,
    )


# ============================================================
# JSON Schema 导出（贴入设计说明书）
# ============================================================

def export_json_schema() -> dict:
    """导出 ReportOutput 的 JSON Schema，供设计说明书引用"""
    return ReportOutput.model_json_schema()


if __name__ == "__main__":
    import json
    schema = export_json_schema()
    print(json.dumps(schema, indent=2, ensure_ascii=False))