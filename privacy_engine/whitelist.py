# -*- coding: utf-8 -*-
"""Built-in whitelist — safe strings that should never be filtered"""

import re

# ── IP whitelist (protocol-reserved addresses only) ──

IP_WHITELIST_PATTERNS = [
    # 0.0.0.0 (bind all interfaces)
    re.compile(r"0\.0\.0\.0"),
    # 255.255.255.255 (broadcast)
    re.compile(r"255\.255\.255\.255"),
]

# ── Domain whitelist ──

DOMAIN_WHITELIST = [
    "localhost",
    "localhost.localdomain",
    "example.com",
    "example.org",
    "example.net",
    "test.com",
    "test.local",
]

# ── Hostname whitelist ──

HOSTNAME_WHITELIST = [
    "localhost",
]

# ── Common public port numbers (not sensitive on their own) ──

COMMON_PORTS = {22, 80, 443, 8080, 8443, 3000, 5000, 8000, 9090}


# ── Whitelist check functions ──

def is_whitelisted_ip(ip: str) -> bool:
    """Check if IP is in the built-in protocol-address whitelist (0.0.0.0, 255.255.255.255)."""
    for pattern in IP_WHITELIST_PATTERNS:
        if pattern.fullmatch(ip):
            return True
    return False


def is_whitelisted_domain(domain: str) -> bool:
    """Check if domain is in the whitelist."""
    return domain.lower() in DOMAIN_WHITELIST


def is_whitelisted_hostname(hostname: str) -> bool:
    """Check if hostname is in the whitelist."""
    return hostname.lower() in HOSTNAME_WHITELIST
