# -*- coding: utf-8 -*-
"""High-entropy string detection — identifies unstructured strings that may be keys/tokens"""

import math
import re
from dataclasses import dataclass, field


@dataclass
class EntropyMatch:
    """Entropy detection match result"""

    value: str
    start: int
    end: int
    entropy: float
    length: int


# ── Configurable parameters ──

# Entropy threshold: values above this are considered potentially random.
# Empirical values: normal English ~3.5-4.5 bits/char, base64 ~6 bits/char.
# Truly random keys typically exceed 5.0.
DEFAULT_ENTROPY_THRESHOLD = 5.0

# Minimum length: random tokens (sans padding) are often 12-22 chars
DEFAULT_MIN_LENGTH = 12

# Max sample length (avoid full-entropy calc on extremely long strings)
MAX_SAMPLE_LENGTH = 1024


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string (bits per char).

    Higher entropy = more uniform character distribution = more likely random.
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


# ── Patterns to exclude from high-entropy detection ──

NON_SECRET_PATTERNS = [
    # base64 data URIs (data:image/...)
    re.compile(r"data:[^;]+;base64,", re.IGNORECASE),
]


def _may_be_secret(value: str) -> bool:
    """Exclude high-entropy strings that are clearly not secrets.

    Lenient strategy: only reject when CJK characters or kana
    appear in large numbers. Single punctuation marks (fullwidth
    or halfwidth) do NOT block detection.
    """
    if not value:
        return False

    # All same character
    if len(set(value)) == 1:
        return False

    # Contains newlines / tabs → unlikely to be a compact key
    if re.search(r"[\n\r\t]", value):
        return False

    # Already in the exclusion list (e.g. data URIs)
    for pat in NON_SECRET_PATTERNS:
        if pat.search(value):
            return False

    # Too many CJK alphabetic characters (not punctuation) → natural language, not a key
    # Unicode ranges: CJK Unified Ideographs + Japanese Kana + Korean
    cjk_alpha = re.findall(
        r"[\u4e00-\u9fff\u3040-\u309f\u30a0-\u30ff\uac00-\ud7af]",
        value,
    )
    if len(cjk_alpha) > len(value) * 0.3:
        return False

    # Too many spaces → likely natural language
    spaces = value.count(" ") + value.count("\u3000")  # halfwidth + fullwidth
    if spaces > len(value) * 0.25:
        return False

    return True


def find_high_entropy(
    text: str,
    threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    min_length: int = DEFAULT_MIN_LENGTH,
) -> list[EntropyMatch]:
    """Find high-entropy substrings in text.

    Strategy: sliding window scan, then merge adjacent matches.
    """
    if len(text) < min_length:
        return []

    matches: list[EntropyMatch] = []
    sample = text[:MAX_SAMPLE_LENGTH]

    # Sliding window step size
    step = max(1, min_length // 3)

    pos = 0
    while pos + min_length <= len(sample):
        window = sample[pos : pos + min_length]
        entropy = _shannon_entropy(window)

        if entropy >= threshold:
            # Extend right: keep going if adding a character doesn't drop entropy
            extended_end = pos + min_length
            while extended_end < len(sample):
                test_window = sample[pos : extended_end + 1]
                if _shannon_entropy(test_window) >= threshold:
                    extended_end += 1
                else:
                    break

            value = sample[pos:extended_end]
            if _may_be_secret(value):
                # Recalculate entropy on the extended value for accuracy
                full_entropy = _shannon_entropy(value)
                matches.append(
                    EntropyMatch(
                        value=value,
                        start=pos,
                        end=extended_end,
                        entropy=full_entropy,
                        length=len(value),
                    )
                )
            pos = extended_end
        else:
            pos += step

    # Deduplicate overlapping matches (keep the longer one)
    deduped: list[EntropyMatch] = []
    for m in sorted(matches, key=lambda x: (x.start, -x.length)):
        if deduped and m.start < deduped[-1].end:
            if m.length > deduped[-1].length:
                deduped[-1] = m
        else:
            deduped.append(m)

    return deduped
