"""
威胁情报平台查询 

支持平台：
- VirusTotal v3 API
- AlienVault OTX API

特性：
- URL 类型：VT 用 base64url 编码，OTX 用 percent-encoding
- 并行查询（ThreadPoolExecutor）
- 无 API Key 时自动降级 mock
"""

from __future__ import annotations

import base64
import logging
import os
import time
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import requests

logger = logging.getLogger(__name__)

# ============================================================
# 配置
# ============================================================

DEFAULT_TIMEOUT = 30
MAX_WORKERS = 3  # VT 免费版限流 4次/分钟，3并发安全
RATE_LIMIT = 0.5  # 串行查询时每个 IOC 间隔（秒）


# ============================================================
# VT 查询（复用你的 skill 实现）
# ============================================================

def query_virustotal(ioc_type: str, ioc_value: str, api_key: str) -> Optional[dict]:
    """
    查询 VirusTotal v3 API。

    Args:
        ioc_type: 类型 (IP/Domain/Hash/URL)
        ioc_value: IOC 值
        api_key: VT API Key

    Returns:
        {'detections': int, 'total': int} 或 None（失败时）
    """
    if not api_key:
        return None

    # 类型映射（VT v3 endpoint）
    type_map = {
        "IP": "ip_addresses",
        "Domain": "domains",
        "MD5": "files",
        "SHA1": "files",
        "SHA256": "files",
        "Hash": "files",
    }

    # 处理 URL 类型：VT v3 要求 base64url 编码（去尾部 =）
    if ioc_type == "URL":
        url_id = base64.urlsafe_b64encode(ioc_value.encode()).decode().rstrip("=")
        endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    else:
        endpoint_name = type_map.get(ioc_type, "ip_addresses")
        endpoint = f"https://www.virustotal.com/api/v3/{endpoint_name}/{ioc_value}"

    headers = {
        "x-apikey": api_key,
        "Accept": "application/json",
    }

    try:
        resp = requests.get(endpoint, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        # 404 表示 VT 未收录该 IOC，视为 0 检测
        if resp.status_code == 404:
            return {"detections": 0, "total": 0}
        
        resp.raise_for_status()
        data = resp.json()

        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) if stats else 0

        return {
            "detections": malicious + suspicious,
            "total": total,
        }

    except requests.exceptions.RequestException as e:
        logger.warning("[VT] 查询失败 %s: %s", ioc_value, e)
        return None
    except Exception as e:
        logger.warning("[VT] 查询异常 %s: %s", ioc_value, e)
        return None


# ============================================================
# OTX 查询（复用你的 skill 实现）
# ============================================================

def query_otx(ioc_type: str, ioc_value: str, api_key: str) -> Optional[dict]:
    """
    查询 AlienVault OTX API。

    Args:
        ioc_type: 类型 (IP/Domain/Hash/URL)
        ioc_value: IOC 值
        api_key: OTX API Key

    Returns:
        {'pulses': int} 或 None（失败时）
    """
    if not api_key:
        return None

    # ---- 1. 预处理 IOC 值（针对安全报告中的防御性写法） ----
    # 替换 [.] 为 .（例如 kefas[.]id -> kefas.id）
    ioc_value = ioc_value.replace("[.]", ".")
    # 替换 hxxps:// 为 https://（常见于报告中的防御性 URL）
    ioc_value = ioc_value.replace("hxxps://", "https://")
    ioc_value = ioc_value.replace("hxxp://", "http://")

    # ---- 2. OTX 类型映射（必须放在外面，保证 else 分支能访问） ----
    type_map = {
        "IP": "IPv4",
        "Domain": "domain",
        "MD5": "file",
        "SHA1": "file",
        "SHA256": "file",
        "Hash": "file",
    }

    # ---- 3. 构建端点 ----
    if ioc_type == "URL":
        # OTX 要求对 URL 进行 percent-encoding
        encoded = urllib.parse.quote(ioc_value, safe="")
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/url/{encoded}/general"
    else:
        otx_type = type_map.get(ioc_type, "IPv4")
        endpoint = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{ioc_value}/general"

    headers = {"X-OTX-API-KEY": api_key}

    try:
        resp = requests.get(endpoint, headers=headers, timeout=DEFAULT_TIMEOUT)
        
        # 404 表示 OTX 未收录，视为 0 pulses
        if resp.status_code == 404:
            return {"pulses": 0}
        
        resp.raise_for_status()
        data = resp.json()

        pulses = data.get("pulse_info", {}).get("pulses", [])
        # 只统计有实际威胁情报的脉冲（有 tags 或 references）
        valid_pulses = [
            p for p in pulses
            if p.get("tags") or p.get("references")
        ]

        return {"pulses": len(valid_pulses)}

    except requests.exceptions.RequestException as e:
        logger.warning("[OTX] 查询失败 %s: %s", ioc_value, e)
        return None
    except Exception as e:
        logger.warning("[OTX] 查询异常 %s: %s", ioc_value, e)
        return None

# ============================================================
# 单个 IOC 全平台查询（并行内部）
# ============================================================

def query_single_ioc(value: str, ioc_type: str, vt_key: str, otx_key: str) -> Tuple[str, dict]:
    """
    查询单个 IOC 的所有平台（VT + OTX），内部并行。

    Returns:
        (value, intel_data)
        intel_data = {
            'vt': {'detections': int, 'total': int} | None,
            'otx': {'pulses': int} | None,
        }
    """
    intel_data = {"vt": None, "otx": None}

    # 判断哪些平台支持该类型
    vt_supported = ioc_type in ("IP", "Domain", "Hash", "URL")
    otx_supported = ioc_type in ("IP", "Domain", "Hash", "URL")

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = {}
        if vt_supported and vt_key:
            futures[executor.submit(query_virustotal, ioc_type, value, vt_key)] = "vt"
        if otx_supported and otx_key:
            futures[executor.submit(query_otx, ioc_type, value, otx_key)] = "otx"

        for future in as_completed(futures):
            platform = futures[future]
            try:
                result = future.result(timeout=DEFAULT_TIMEOUT)
                if result is not None:
                    intel_data[platform] = result
            except Exception as e:
                logger.debug("查询 %s (%s) 超时: %s", value, platform, e)

    return value, intel_data


# ============================================================
# 批量查询（并行 + 去重）
# ============================================================

def query_iocs_batch(ioc_list: List[Tuple[str, str]]) -> Dict[str, dict]:
    """
    批量并行查询 IOC。

    Args:
        ioc_list: [(value, type), ...]

    Returns:
        {value: {'vt': {'detections': int}, 'otx': {'pulses': int}}}
    """
    if not ioc_list:
        return {}

    # 加载 API Key（支持环境变量和 application.yaml）
    vt_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    otx_key = os.getenv("OTX_API_KEY", "")

    # 尝试从 application.yaml 读取
    if not vt_key or not otx_key:
        try:
            from pathlib import Path
            import yaml
            config_path = Path("application.yaml")
            if config_path.exists():
                with open(config_path, encoding="utf-8") as f:
                    config = yaml.safe_load(f) or {}
                if not vt_key:
                    vt_key = config.get("virustotal", {}).get("api_key", "")
                if not otx_key:
                    otx_key = config.get("otx", {}).get("api_key", "")
        except Exception:
            pass

    # 去重
    seen = set()
    unique: List[Tuple[str, str]] = []
    for v, t in ioc_list:
        key = v.strip().lower()
        if key not in seen:
            seen.add(key)
            unique.append((v, t))

    if not vt_key and not otx_key:
        logger.info("[ThreatIntel] 无 API Key，返回 mock 结果")
        return _mock_query_batch(unique)

    logger.info("[ThreatIntel] 开始查询 %d 个 IOC (VT=%s, OTX=%s)",
                len(unique), "可用" if vt_key else "不可用", "可用" if otx_key else "不可用")

    results: Dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {}
        for v, t in unique:
            # 只查询有至少一个平台支持的 IOC
            if t in ("IP", "Domain", "Hash", "URL"):
                future = executor.submit(query_single_ioc, v, t, vt_key, otx_key)
                futures[future] = v

        for future in as_completed(futures):
            value = futures[future]
            try:
                _, intel_data = future.result(timeout=25)
                results[value] = intel_data
            except Exception as e:
                logger.warning("查询 %s 失败: %s", value, e)
                results[value] = {"vt": None, "otx": None}

    return results


# ============================================================
# Mock 降级（无 API Key 时）
# ============================================================

def _mock_query_batch(ioc_list: List[Tuple[str, str]]) -> Dict[str, dict]:
    """无 API Key 时的模拟查询，返回空数据（规则函数会保留 LLM 等级）"""
    results = {}
    for v, _ in ioc_list:
        results[v] = {"vt": None, "otx": None}
    return results