# -*- coding: utf-8 -*-
"""隐私检测器 —— 组合正则检测 + 熵检测，提供 filter / scan 接口"""

import re
import logging
import unicodedata
import html
import urllib.parse
from dataclasses import dataclass, field
from collections import OrderedDict

from .patterns import BUILTIN_RULES, Rule as PatternRule
from .entropy import find_high_entropy, EntropyMatch
from .whitelist import (
    is_whitelisted_ip,
    is_whitelisted_domain,
    is_whitelisted_hostname,
)
from .config import load_config

logger = logging.getLogger(__name__)


@dataclass
class Match:
    """一条检测匹配"""

    type: str           # 规则名，如 "ipv4", "entropy"
    value: str          # 原始值
    start: int          # 起始位置
    end: int            # 结束位置
    placeholder: str    # 替换占位符
    entropy: float = 0.0    # 仅熵检测时有值
    priority: int = 0       # 规则优先级
    confidence: str = "high"  # "high" | "low"（信用卡 Luhn 失败时用）


def _luhn_check(card_number: str) -> bool:
    """Luhn 算法校验信用卡号是否合法。"""
    digits = [int(ch) for ch in card_number if ch.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for i, d in enumerate(digits):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


def _normalize(text: str) -> str:
    """Unicode NFKC 归一化（防御性内联）。"""
    return unicodedata.normalize("NFKC", text)


# 零宽字符集合（\u200b 零宽空格, \u200c 零宽非连接符, etc.）
_ZERO_WIDTH_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u00ad\u2060\u2061"
    r"\u2062\u2063\u2064\u2066\u2067\u2068\u2069\ufe00-\ufe0f]"
)


def _preprocess(text: str, config: dict) -> str:
    """预处理管道：在正则匹配前清洗文本。

    顺序：1) NFKC 归一化 → 2) 零宽字符移除 → 3) URL 解码 → 4) HTML 解码
    """
    pp = config.get("preprocess", {})
    # NFKC 归一化（始终执行）
    text = _normalize(text)
    # 零宽字符移除
    if pp.get("strip_zw_chars", True):
        text = _ZERO_WIDTH_CHARS.sub("", text)
    # URL 解码
    if pp.get("url_decode", True):
        text = _safe_url_decode(text)
    # HTML 实体解码
    if pp.get("html_unescape", True):
        text = _safe_html_unescape(text)
    return text


def _safe_url_decode(text: str) -> str:
    """安全 URL 解码，失败时返回原文。"""
    try:
        # 限制重复解码次数，防止无限循环
        for _ in range(3):
            decoded = urllib.parse.unquote(text, errors="strict")
            if decoded == text:
                break
            text = decoded
    except Exception:
        pass
    return text


def _safe_html_unescape(text: str) -> str:
    """安全 HTML 解码，失败时返回原文。"""
    try:
        return html.unescape(text)
    except Exception:
        return text


class PrivacyDetector:
    """隐私检测器 —— 单例，内部维护所有规则。"""

    def __init__(self, config: dict | None = None):
        self._config = config or load_config()

        # 编译内置规则 (OrderedDict 保证优先级顺序)
        self._rules: OrderedDict[str, re.Pattern] = OrderedDict()
        self._placeholders: dict[str, str] = {}
        self._priorities: dict[str, int] = {}

        # 白名单
        self._whitelist_ips: set[str] = set()
        self._whitelist_domains: set[str] = set()
        self._whitelist_strings: set[str] = set()

        self._custom_rules: list[dict] = []
        self._custom_compiled: list[tuple[str, re.Pattern, str, int]] = []

        self._load_rules()

    # ── 内部方法 ──

    def _load_rules(self):
        """从配置加载所有规则。"""
        rules_config = self._config.get("rules", {})
        placeholders_config = self._config.get("placeholders", {})

        # 内置规则（按 BUILTIN_RULES 的顺序加载，保持优先级）
        for rule in BUILTIN_RULES:
            if rules_config.get(rule.name, True):
                self._rules[rule.name] = re.compile(rule.pattern)
                self._placeholders[rule.name] = placeholders_config.get(
                    rule.name, rule.placeholder
                )
                self._priorities[rule.name] = rule.priority

        # 白名单
        wl = self._config.get("whitelist", {})
        self._whitelist_ips = set(wl.get("ips", []))
        self._whitelist_domains = set(wl.get("domains", []))
        self._whitelist_strings = set(wl.get("strings", []))

        # 自定义规则
        for cr in self._config.get("custom_rules", []):
            name = cr.get("name", "")
            pattern = cr.get("pattern", "")
            placeholder = cr.get("placeholder", "[REDACTED]")
            priority = cr.get("priority", 50)
            if name and pattern:
                self._custom_compiled.append(
                    (name, re.compile(pattern), placeholder, priority)
                )
            else:
                logger.warning(f"跳过无效自定义规则: {cr}")

    def _is_whitelisted(self, rule_name: str, value: str) -> bool:
        """检查匹配值是否在白名单中。"""
        # 完全匹配白名单
        if value in self._whitelist_strings:
            return True
        # IP 白名单：内置协议地址 + 用户配置
        if rule_name in ("ipv4", "ipv6", "ipv4_hex", "ipv6_hyphen"):
            if is_whitelisted_ip(value):
                return True
            if value in self._whitelist_ips:
                return True
        # 域名白名单：内置 + 用户配置
        if rule_name == "email":
            domain_part = value.rsplit("@", 1)[-1] if "@" in value else ""
            if is_whitelisted_domain(domain_part):
                return True
            if domain_part in self._whitelist_domains:
                return True
        return False

    # ── 正则匹配提取 ──

    def _find_regex_matches(
        self,
        text: str,
        rules: list[str] | None = None,
        placeholder: str | None = None,
    ) -> list[Match]:
        """扫描文本，返回所有正则规则匹配到的 Match 列表。"""
        matches: list[Match] = []

        # 内置规则（按加载顺序）
        for name, pat in self._rules.items():
            if rules is not None and name not in rules:
                continue
            priority = self._priorities.get(name, 0)
            for m in pat.finditer(text):
                value = m.group(0)
                if self._is_whitelisted(name, value):
                    continue
                # 信用卡：Luhn 失败时仍保留匹配，但降低置信度
                confidence = "high"
                if name == "credit_card":
                    if not _luhn_check(value):
                        confidence = "low"
                matches.append(
                    Match(
                        type=name,
                        value=value,
                        start=m.start(),
                        end=m.end(),
                        placeholder=placeholder or self._placeholders.get(
                            name, "[REDACTED]"
                        ),
                        priority=priority,
                        confidence=confidence,
                    )
                )

        # 自定义规则
        for name, pat, ph, priority in self._custom_compiled:
            if rules is not None and name not in rules:
                continue
            for m in pat.finditer(text):
                value = m.group(0)
                if self._is_whitelisted(name, value):
                    continue
                matches.append(
                    Match(
                        type=name,
                        value=value,
                        start=m.start(),
                        end=m.end(),
                        placeholder=placeholder or ph,
                        priority=priority,
                        confidence="high",
                    )
                )

        return matches

    # ── 重叠去重 ──

    def _deduplicate_matches(self, matches: list[Match]) -> list[Match]:
        """按优先级和长度去重，解决规则间重叠匹配问题。

        规则：
        1. 先按优先级排序（数字越小优先级越高）
        2. 重叠时：保留优先级更高的；同优先级保留更长的
        3. 完全包含时始终保留更大的覆盖范围（避免信息泄漏）
        """
        if not matches:
            return []

        # 按 start 升序，同起点按优先级升序（越小越优先），再按长度降序
        sorted_matches = sorted(
            matches,
            key=lambda m: (m.start, m.priority, -(m.end - m.start)),
        )

        deduped: list[Match] = []
        for m in sorted_matches:
            if not deduped:
                deduped.append(m)
                continue

            last = deduped[-1]
            # 无重叠：直接加入
            if m.start >= last.end:
                deduped.append(m)
                continue

            # 完全包含在 last 内部 → 始终丢弃当前
            # （无论优先级高低，last 已覆盖当前全部区域，
            #   替换为更小匹配会导致 last 未覆盖部分泄漏）
            if m.end <= last.end:
                continue

            # 部分重叠：当前延伸到 last 之外
            if m.priority < last.priority:
                # 当前优先级更高 → 替换 last
                deduped[-1] = m
            elif m.priority == last.priority:
                # 同优先级 → 保留更长的
                if m.end > last.end:
                    deduped[-1] = m
            # else: 当前优先级更低 → 丢弃当前

        return deduped

    # ── 公开 API ──

    def filter(
        self,
        text: str,
        rules: list[str] | None = None,
        placeholder: str | None = None,
    ) -> str:
        """过滤文本，替换敏感信息为占位符。

        Args:
            text: 原始文本（应已做 NFKC 归一化）
            rules: 启用的规则名列表。None = 全部。
            placeholder: 全局占位符。None = 各规则默认。

        Returns:
            脱敏文本
        """
        if not text:
            return text

        # 预处理管道（NFKC + 零宽字符 + URL解码 + HTML解码）
        text = _preprocess(text, self._config)

        # 1. 正则匹配
        regex_matches = self._find_regex_matches(text, rules, placeholder)

        # 2. 熵检测（默认 auto 模式 — 自动替换）
        entropy_matches: list[Match] = []
        entropy_config = self._config.get("entropy", {})
        ent_enabled = entropy_config.get("enabled", True)
        ent_mode = entropy_config.get("mode", "auto")
        ent_threshold = entropy_config.get("threshold", 5.0)
        ent_min_len = entropy_config.get("min_length", 12)

        if ent_enabled and ent_mode == "auto":
            ent_matches = find_high_entropy(
                text,
                threshold=ent_threshold,
                min_length=ent_min_len,
            )
            # 排除已被正则覆盖的区域
            covered_regions: list[tuple[int, int]] = [
                (m.start, m.end) for m in regex_matches
            ]
            for em in ent_matches:
                # 检查是否与已有正则匹配重叠
                overlap = False
                for start, end in covered_regions:
                    if not (em.end <= start or em.start >= end):
                        overlap = True
                        break
                if not overlap:
                    entropy_matches.append(
                        Match(
                            type="entropy",
                            value=em.value,
                            start=em.start,
                            end=em.end,
                            placeholder="[HIGH_ENTROPY]",
                            entropy=em.entropy,
                            priority=100,
                            confidence="high",
                        )
                    )

        # 3. 合并 & 去重
        all_matches = regex_matches + entropy_matches
        deduped = self._deduplicate_matches(all_matches)

        # 4. 从右到左替换（避免索引漂移），跳过低置信度匹配
        result = text
        for m in sorted(deduped, key=lambda x: x.start, reverse=True):
            if m.confidence == "low":
                continue
            result = result[: m.start] + m.placeholder + result[m.end :]

        return result

    def scan(self, text: str) -> list[dict]:
        """扫描文本，返回所有检测到的敏感信息（不修改原文本）。

        Returns:
            匹配列表，每项包含 type, value, start, end, placeholder
        """
        if not text:
            return []

        # 预处理管道（NFKC + 零宽字符 + URL解码 + HTML解码）
        text = _preprocess(text, self._config)

        # 正则匹配
        regex_matches = self._find_regex_matches(text)

        # 熵检测
        entropy_matches: list[Match] = []
        entropy_config = self._config.get("entropy", {})
        ent_enabled = entropy_config.get("enabled", True)
        ent_threshold = entropy_config.get("threshold", 5.0)
        ent_min_len = entropy_config.get("min_length", 12)

        if ent_enabled:
            ent_matches = find_high_entropy(
                text,
                threshold=ent_threshold,
                min_length=ent_min_len,
            )
            covered_regions: list[tuple[int, int]] = [
                (m.start, m.end) for m in regex_matches
            ]
            for em in ent_matches:
                overlap = False
                for start, end in covered_regions:
                    if not (em.end <= start or em.start >= end):
                        overlap = True
                        break
                if not overlap:
                    entropy_matches.append(
                        Match(
                            type="entropy",
                            value=em.value,
                            start=em.start,
                            end=em.end,
                            placeholder="[HIGH_ENTROPY]",
                            entropy=em.entropy,
                            priority=100,
                            confidence="high",
                        )
                    )

        all_matches = regex_matches + entropy_matches
        deduped = self._deduplicate_matches(all_matches)

        return [
            {
                "type": m.type,
                "value": m.value,
                "start": m.start,
                "end": m.end,
                "placeholder": m.placeholder,
                "entropy": m.entropy,
                "confidence": m.confidence,
            }
            for m in deduped
        ]

    def add_rule(self, name: str, pattern: str, placeholder: str = "[REDACTED]"):
        """运行时注册一条自定义规则。"""
        try:
            compiled = re.compile(pattern)
        except re.error as e:
            raise ValueError(f"无效的正则表达式: {pattern}") from e
        self._custom_compiled.append((name, compiled, placeholder, 50))
        logger.info(f"已注册自定义规则: {name}")
