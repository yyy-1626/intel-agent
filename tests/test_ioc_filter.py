"""测试 IOC 过滤节点（类型过滤 + 白名单过滤）"""
from intel_agent.nodes.ioc_filter import _normalize_value, filter_ioc_list, ioc_filter_node
from intel_agent.tools.ioc_regex import classify_ioc_value


def _ioc(value, type="Domain", threat_level="未知"):
    return {"value": value, "type": type, "threat_level": threat_level, "tags": [], "context": None}


class TestTypeFilter:
    """7 类 IOC 类型过滤：非 7 类值（文件名/路径/注册表等）应被丢弃"""

    def test_drop_file_name(self):
        kept, dropped = filter_ioc_list([_ioc("a.exe", "File")])
        assert kept == []
        assert len(dropped["invalid_type"]) == 1

    def test_drop_dll_name(self):
        assert classify_ioc_value("malware.dll") is None

    def test_drop_registry(self):
        kept, dropped = filter_ioc_list([_ioc(r"HKLM\Software\Microsoft", "Registry")])
        assert kept == []

    def test_drop_windows_path(self):
        kept, dropped = filter_ioc_list([_ioc(r"C:\Windows\System32\malware.dll", "FilePath")])
        assert kept == []

    def test_keep_valid_types(self):
        valid = [
            ("45.33.32.156", "IP"),
            ("evil.com", "Domain"),
            ("https://evil.com/payload", "URL"),
            ("phishing@evil.com", "Email"),
            ("d41d8cd98f00b204e9800998ecf8427e", "Hash"),
            ("CVE-2021-34527", "CVE"),
            ("T1566.001", "TTP"),
        ]
        kept, dropped = filter_ioc_list([_ioc(v, t) for v, t in valid])
        assert len(kept) == 7
        assert dropped["invalid_type"] == []

    def test_type_normalized_to_enum_value(self):
        # LLM 返回 IPv4/MD5 等非枚举值，应规范化为 IP/Hash
        kept, dropped = filter_ioc_list([
            _ioc("45.33.32.156", "IPv4"),
            _ioc("d41d8cd98f00b204e9800998ecf8427e", "MD5"),
            _ioc("8.8.8.8", "IP"),
        ])
        types = {i["value"]: i["type"] for i in kept}
        assert types["45.33.32.156"] == "IP"
        assert types["d41d8cd98f00b204e9800998ecf8427e"] == "Hash"
        # 8.8.8.8 属于公共 DNS，应被白名单过滤
        assert "8.8.8.8" not in types

    def test_trailing_punctuation_stripped(self):
        kept, dropped = filter_ioc_list([_ioc("evil.com.", "Domain")])
        assert len(kept) == 1
        assert kept[0]["value"] == "evil.com"

    def test_ipv6_trailing_colons_not_mangled(self):
        # 压缩 IPv6 以 "::" 结尾：_normalize_value 不应误剥冒号导致类型判定失败
        for v in ("2001:db8::", "fe80::", "2606:4700:4700::"):
            assert classify_ioc_value(_normalize_value(v)) == "IP"
        # 非保留段（不在白名单）的尾部 :: IPv6 应保留
        kept, dropped = filter_ioc_list([_ioc("2606:4700:4700::", "IP")])
        assert len(kept) == 1
        assert dropped["invalid_type"] == []


class TestWhitelistFilter:
    def test_private_ip_filtered(self):
        kept, dropped = filter_ioc_list([_ioc("192.168.1.100", "IP")])
        assert kept == []
        assert len(dropped["whitelisted"]) == 1

    def test_public_dns_filtered(self):
        kept, dropped = filter_ioc_list([_ioc("8.8.8.8", "IP")])
        assert kept == []
        assert len(dropped["whitelisted"]) == 1

    def test_cloud_domain_filtered(self):
        kept, dropped = filter_ioc_list([
            _ioc("cloudflare.com", "Domain"),
            _ioc("sub.cloudflare.com", "Domain"),
            _ioc("https://cloudflare.com/path?x=1", "URL"),
        ])
        assert kept == []
        assert len(dropped["whitelisted"]) == 3

    def test_email_domain_filtered(self):
        kept, dropped = filter_ioc_list([_ioc("phishing@google.com", "Email")])
        assert kept == []
        assert len(dropped["whitelisted"]) == 1

    def test_malicious_kept(self):
        kept, dropped = filter_ioc_list([
            _ioc("evil.com", "Domain"),
            _ioc("200.100.50.25", "IP"),
        ])
        assert len(kept) == 2
        assert dropped["whitelisted"] == []


class TestNode:
    def test_filters_actor_details(self):
        state = {
            "actor_details": [
                {
                    "actor_id": "a1",
                    "name": "A1",
                    "iocs": [
                        _ioc("evil.com", "Domain"),
                        _ioc("a.exe", "File"),
                        _ioc("8.8.8.8", "IP"),
                    ],
                    "tools": [],
                }
            ]
        }
        out = ioc_filter_node(state)
        details = out["actor_details"]
        assert len(details[0]["iocs"]) == 1
        assert details[0]["iocs"][0]["value"] == "evil.com"
        assert "ioc_filter" in out["execution_log"][0]

    def test_no_details_skips(self):
        out = ioc_filter_node({"actor_details": []})
        assert "跳过" in out["execution_log"][0]
