"""
IOC 白名单过滤 — 前置过滤明确良性资产（云/CDN/安全厂商/公共 DNS/私有 IP）

约束：在 LLM 判级/输出之前过滤，降误报 + 省 token。
支持 YAML 配置（config/whitelist.yaml），可自定义。
参考前项目 IOC-Detector：URL 取 hostname、Email 取域名、IP 覆盖公共 DNS/云 CDN CIDR 与 IPv6。
"""

from __future__ import annotations

import ipaddress
from contextlib import suppress
from pathlib import Path
from urllib.parse import urlparse

import yaml

# 默认配置文件路径
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent.parent / "config" / "whitelist.yaml"


class WhitelistFilter:
    """白名单过滤器：滤掉云厂商/CDN/安全厂商域名与私有/公共 IP 段"""

    def __init__(self, config_path: Path | None = None):
        """
        Args:
            config_path: whitelist.yaml 路径，默认 config/whitelist.yaml
        """
        self._config_path = config_path or DEFAULT_CONFIG_PATH
        self._networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self._domain_suffixes: set[str] = set()
        self._exact_values: set[str] = set()
        self._load_config()

    def _load_config(self) -> None:
        """加载白名单配置"""
        if not self._config_path.exists():
            return

        with open(self._config_path, encoding="utf-8") as f:
            config = yaml.safe_load(f) or {}

        # IP 段（私有段 + 公共 DNS/云服务商段，合并检查）
        for cidr in config.get("private_ip_ranges", []) + config.get("public_ip_ranges", []):
            with suppress(ValueError):
                self._networks.append(ipaddress.ip_network(cidr, strict=False))

        # 域名后缀（合并 CDN/云/安全厂商/公共服务/示例域名）
        for section in [
            "cdn_and_cloud_domains",
            "security_vendor_domains",
            "public_service_domains",
            "example_domains",
        ]:
            for domain in config.get(section, []):
                self._domain_suffixes.add(domain.lower().strip().rstrip("."))

        # 精确值（如公共 DNS IP）
        for domain in config.get("public_service_domains", []):
            try:
                ipaddress.ip_address(domain.strip())
                self._exact_values.add(domain.strip())
            except ValueError:
                pass

    @staticmethod
    def _normalize_kind(candidate_type: str) -> str:
        """把候选类型归一到 7 类规范类型（IP/Domain/URL/Email），其余原样返回"""
        t = (candidate_type or "").strip()
        if t in ("IP", "IPv4", "IPv6", "ip", "ipv4", "ipv6"):
            return "IP"
        if t in ("Domain", "domain"):
            return "Domain"
        if t in ("URL", "url"):
            return "URL"
        if t in ("Email", "email"):
            return "Email"
        return t

    @staticmethod
    def _hostname(value: str, kind: str) -> str | None:
        """从 value 中取出待匹配的主机名/域名"""
        if kind == "URL":
            host = urlparse(value).hostname
            return host.lower() if host else None
        if kind == "Email":
            return value.rsplit("@", 1)[-1].strip().lower() if "@" in value else None
        return value.strip().lower().rstrip(".")

    def _is_safe_host(self, host: str) -> bool:
        """域名/主机名是否命中白名单后缀（含子域名匹配）"""
        return host in self._domain_suffixes or any(
            host.endswith("." + suffix) for suffix in self._domain_suffixes
        )

    def _is_safe_ip(self, ip_str: str) -> bool:
        """IP 是否属于私有/保留段或白名单 IP 段"""
        try:
            ip = ipaddress.ip_address(ip_str.strip())
        except ValueError:
            return False
        if (
            ip.is_private or ip.is_loopback or ip.is_multicast
            or ip.is_link_local or ip.is_reserved or ip.is_unspecified
        ):
            return True
        for net in self._networks:
            try:
                if ip in net:
                    return True
            except (TypeError, ValueError):
                continue
        return False

    def is_whitelisted(self, value: str, candidate_type: str) -> bool:
        """
        检查单个 IOC 是否在白名单中。

        Args:
            value: IOC 值
            candidate_type: 候选类型（IP/Domain/URL/Email 或 IPv4/IPv6 等）

        Returns:
            True 表示应过滤掉
        """
        if not value or not value.strip():
            return True

        kind = self._normalize_kind(candidate_type)
        raw = value.strip()

        # 精确匹配（公共 DNS 等精确 IP）
        if raw.strip().lower() in self._exact_values:
            return True

        # 白名单只对网络类 IOC 生效（Hash/CVE/TTP 无域名/IP 概念，直接放行）
        if kind not in ("IP", "Domain", "URL", "Email"):
            return False

        if kind == "IP":
            return self._is_safe_ip(raw)

        host = self._hostname(raw, kind)
        if not host:
            return False

        # 主机名本身是 IP（如 URL 指向内网 IP）
        if kind in ("Domain", "URL", "Email") and self._is_safe_ip(host):
            return True

        return self._is_safe_host(host)

    def filter_candidates(
        self, candidates: list[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        """
        过滤 IOC 候选列表。

        Args:
            candidates: [(value, candidate_type), ...]

        Returns:
            过滤后的候选列表
        """
        return [
            (val, typ)
            for val, typ in candidates
            if not self.is_whitelisted(val, typ)
        ]

    def reload(self) -> None:
        """重新加载白名单配置"""
        self._networks.clear()
        self._domain_suffixes.clear()
        self._exact_values.clear()
        self._load_config()


# 全局单例
_whitelist: WhitelistFilter | None = None


def get_whitelist(config_path: Path | None = None) -> WhitelistFilter:
    """获取白名单过滤器单例"""
    global _whitelist
    if _whitelist is None:
        _whitelist = WhitelistFilter(config_path)
    return _whitelist


def filter_ioc_candidates(
    candidates: list[tuple[str, str]],
    config_path: Path | None = None,
) -> list[tuple[str, str]]:
    """
    过滤 IOC 候选（便捷函数）。

    Args:
        candidates: [(value, candidate_type), ...]
        config_path: 可选配置文件路径

    Returns:
        过滤后的候选列表
    """
    return get_whitelist(config_path).filter_candidates(candidates)
