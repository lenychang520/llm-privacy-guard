# -*- coding: utf-8 -*-
"""配置加载 —— 从 config.yaml 读取用户自定义规则和参数"""

import os
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


# ── 默认配置 ──

DEFAULT_CONFIG = {
    "preprocess": {
        "strip_zw_chars": True,    # 移除零宽字符 (\\u200b, \\u200c, 等)
        "url_decode": True,        # URL 解码 (%3A → :)
        "html_unescape": True,     # HTML 实体解码 (&#64; → @)
    },
    "entropy": {
        "enabled": True,          # 是否启用熵检测
        "threshold": 5.0,         # 熵阈值
        "min_length": 12,         # 最小检测长度（降为 12，覆盖短 token）
        "mode": "auto",           # "auto"（自动替换，默认）或 "review"（仅标记）
    },
    "rules": {
        # 内置规则开关，默认全部开启
        "ipv4": True,
        "ipv4_hex": True,
        "ipv6": True,
        "ipv6_hyphen": True,
        "uuid": True,
        "uuid_hex": True,
        "email": True,
        "phone_cn": True,
        "phone_cn_sep": True,
        "phone_intl": True,
        "id_card_cn": True,
        "id_card_cn_sep": True,
        "ssn_us": True,
        "api_key_prefix": True,
        "aws_access_key": True,
        "ssh_private_key": True,
        "ssh_public_key": True,
        "sha_hash": True,
        "github_token": True,
        "jwt": True,
        "jwt_multiline": True,
        "db_connection_string": True,
        "db_cli": True,
        "credit_card": True,
        "credential_value": True,
        "url_query_credential": True,
        "credential_inline": True,
    },
    "custom_rules": [
        # 用户可以在这里添加自定义正则规则
        # - name: "my_domain"
        #   pattern: "my-company\\.com"
        #   placeholder: "[MY_DOMAIN]"
    ],
    "placeholders": {
        # 覆盖默认占位符
        # ipv4: "[HIDDEN_IP]"
    },
    "whitelist": {
        "ips": [],      # 额外的 IP 白名单
        "domains": [],  # 额外的域名白名单
        "strings": [],  # 完全匹配的白名单字符串
    },
}


def find_config_file() -> Path | None:
    """查找 config.yaml。

    按以下顺序搜索：
    1. 当前工作目录
    2. 插件所在目录的上级（llm_filter/）
    3. ~/.llm-privacy-guard/
    """
    candidates = [
        Path.cwd() / "config.yaml",
        Path(__file__).resolve().parent.parent / "config.yaml",
        Path.home() / ".llm-privacy-guard" / "config.yaml",
    ]

    for p in candidates:
        if p.exists():
            return p
    return None


def load_config() -> dict:
    """加载配置，合并默认值与用户配置。"""
    import yaml

    config = dict(DEFAULT_CONFIG)

    # 深度复制嵌套 dict，避免引用污染
    for key in ("preprocess", "entropy", "rules", "placeholders", "whitelist"):
        if key in config and isinstance(config[key], dict):
            config[key] = dict(config[key])

    config_path = find_config_file()
    if config_path is None:
        logger.info("未找到 config.yaml，使用默认配置")
        return config

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            user_config = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning(f"加载 config.yaml 失败: {e}，使用默认配置")
        return config

    # 深度合并（仅两层——preprocess、entropy、rules、placeholders、whitelist）
    for section in ("preprocess", "entropy", "rules", "placeholders", "whitelist"):
        if section in user_config:
            if isinstance(config.get(section), dict) and isinstance(user_config[section], dict):
                config[section].update(user_config[section])
            else:
                config[section] = user_config[section]

    # 自定义规则直接追加
    if "custom_rules" in user_config and isinstance(user_config["custom_rules"], list):
        config["custom_rules"] = user_config["custom_rules"]

    return config
