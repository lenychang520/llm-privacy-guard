# -*- coding: utf-8 -*-
"""高熵字符串检测 —— 识别无格式但可能是密钥的随机字符串"""

import math
import re
from dataclasses import dataclass, field


@dataclass
class EntropyMatch:
    """熵检测匹配结果"""

    value: str
    start: int
    end: int
    entropy: float
    length: int


# ── 可配置参数 ──

# 熵阈值：超过此值认为可能是随机字符串
# 经验值：正常英文 ~3.5-4.5 bits/char，base64 编码 ~6 bits/char
# 真正的随机密钥通常 > 5.0
DEFAULT_ENTROPY_THRESHOLD = 5.0

# 最小长度：随机 token 去掉 padding 经常是 12-22 字符
DEFAULT_MIN_LENGTH = 12

# 最大采样长度（避免对极长字符串做全量熵计算）
MAX_SAMPLE_LENGTH = 1024


def _shannon_entropy(data: str) -> float:
    """计算字符串的香农熵（bit per char）。

    熵值越高，字符分布越均匀，越像随机数据。
    """
    from collections import Counter

    if not data:
        return 0.0

    total = len(data)
    counter = Counter(data)

    entropy = 0.0
    for count in counter.values():
        p = count / total
        entropy -= p * math.log2(p)

    return entropy


# ── 需要被排除的常见非敏感高熵字符串模式 ──

NON_SECRET_PATTERNS = [
    # base64 数据（data:image/...）
    re.compile(r"data:[^;]+;base64,", re.IGNORECASE),
]


def _may_be_secret(value: str) -> bool:
    """排除明显不是敏感内容的高熵字符串。

    宽松策略：只有当中文/日文/韩文汉字或假名大量出现时才拒绝。
    单个标点符号（全角或半角）不阻止检测。
    """
    if not value:
        return False

    # 全是同一个字符
    if len(set(value)) == 1:
        return False

    # 包含换行 / 制表符 → 不太可能是紧凑密钥
    if re.search(r"[\n\r\t]", value):
        return False

    # 已经在排除列表中的（如 data URI）
    for pat in NON_SECRET_PATTERNS:
        if pat.search(value):
            return False

    # CJK 文字字符（非标点）太多 → 自然语言，不是密钥
    # Unicode 范围：CJK 统一汉字 + 日文假名 + 韩文
    cjk_alpha = re.findall(
        r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]",
        value,
    )
    if len(cjk_alpha) > len(value) * 0.3:
        return False

    # 空格太多 → 可能是自然语言
    spaces = value.count(" ") + value.count("\u3000")  # 半角 + 全角空格
    if spaces > len(value) * 0.25:
        return False

    return True


def find_high_entropy(
    text: str,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list[EntropyMatch]:
    """在文本中查找高熵子串。

    策略：用滑动窗口扫描，然后合并相邻的匹配。
    """
    if len(text) < min_length:
        return []

    matches: list[EntropyMatch] = []
    sample = text[:MAX_SAMPLE_LENGTH]

    # 滑动窗口步长
    step = max(1, min_length // 3)

    pos = 0
    while pos + min_length <= len(sample):
        window = sample[pos : pos + min_length]
        entropy = _shannon_entropy(window)

        if entropy >= threshold:
            # 向右扩展：如果加一个字符熵不降，就扩展
            extended_end = pos + min_length
            while extended_end < len(sample):
                test_window = sample[pos : extended_end + 1]
                if _shannon_entropy(test_window) >= threshold:
                    extended_end += 1
                else:
                    break

            value = sample[pos:extended_end]
            if _may_be_secret(value):
                matches.append(
                    EntropyMatch(
                        value=value,
                        start=pos,
                        end=extended_end,
                        entropy=entropy,
                        length=len(value),
                    )
                )
            pos = extended_end
        else:
            pos += step

    # 去重重叠匹配（保留更长的）
    deduped: list[EntropyMatch] = []
    for m in sorted(matches, key=lambda x: (x.start, -x.length)):
        if deduped and m.start < deduped[-1].end:
            if m.length > deduped[-1].length:
                deduped[-1] = m
        else:
            deduped.append(m)

    return deduped
