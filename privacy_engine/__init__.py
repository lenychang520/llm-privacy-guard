# -*- coding: utf-8 -*-
"""LLM Privacy Guard — 核心引擎

用法:
    from privacy_engine import filter_text, scan_text, add_rule

    safe = filter_text("ssh root@192.168.1.1")
    # → "ssh root@[IP]"

    matches = scan_text("key=sk-abc123")
    # → [Match(type="API_KEY", value="sk-abc123", ...)]

    add_rule("my_company", r"company-\\d{6}", "[COMPANY_ID]")
"""

from .detector import PrivacyDetector

# 单例
_detector: PrivacyDetector | None = None


def _get_detector() -> PrivacyDetector:
    global _detector
    if _detector is None:
        _detector = PrivacyDetector()
    return _detector


def filter_text(
    text: str,
    rules: list[str] | None = None,
    placeholder: str | None = None,
) -> str:
    """过滤文本，用类型占位符替换敏感信息。

    Args:
        text: 原始文本
        rules: 启用的规则名列表。None 表示全部启用。
        placeholder: 自定义全局占位符。None 表示使用各规则默认占位符。

    Returns:
        脱敏后的文本
    """
    return _get_detector().filter(text, rules=rules, placeholder=placeholder)


def scan_text(text: str) -> list[dict]:
    """扫描文本，返回所有检测到的敏感信息（不修改原文本）。

    Returns:
        匹配列表，每项包含 type, value, start, end, placeholder
    """
    return _get_detector().scan(text)


def add_rule(name: str, pattern: str, placeholder: str = "[REDACTED]"):
    """运行时注册一条自定义规则。

    Args:
        name: 规则名（唯一标识）
        pattern: 正则表达式字符串
        placeholder: 替换后的占位符
    """
    _get_detector().add_rule(name, pattern, placeholder)


def reload_config():
    """重新加载 config.yaml 并重置检测器。"""
    global _detector
    _detector = PrivacyDetector()


# 导出版本
__version__ = "0.2.0"
__all__ = ["filter_text", "scan_text", "add_rule", "reload_config"]
