# -*- coding: utf-8 -*-
"""内置白名单 —— 默认不会被过滤的常见安全字符串"""

import re

# ── IP 白名单（仅保留绝对无意义的协议地址） ──

IP_WHITELIST_PATTERNS = [
    # 0.0.0.0（绑定所有接口）
    re.compile(r"0\.0\.0\.0"),
    # 全 255 广播地址
    re.compile(r"255\.255\.255\.255"),
]

# ── 域名白名单 ──

DOMAIN_WHITELIST = [
    "localhost",
    "localhost.localdomain",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.local",
]

# ── Hostname 白名单 ──

HOSTNAME_WHITELIST = [
    "localhost",
]

# ── 已知公开端口范围（不单独作为敏感信息） ──

COMMON_PORTS = {22, 80, 443, 8080, 8443, 3000, 5000, 8000, 9090}


# ── 白名单检查函数 ──

def is_whitelisted_ip(ip: str) -> bool:
    """检查 IP 是否在内置协议地址白名单中（0.0.0.0、255.255.255.255）。"""
    for pattern in IP_WHITELIST_PATTERNS:
        if pattern.fullmatch(ip):
            return True
    return False


def is_whitelisted_domain(domain: str) -> bool:
    """检查域名是否在白名单中。"""
    return domain.lower() in DOMAIN_WHITELIST


def is_whitelisted_hostname(hostname: str) -> bool:
    """检查主机名是否在白名单中。"""
    return hostname.lower() in HOSTNAME_WHITELIST
