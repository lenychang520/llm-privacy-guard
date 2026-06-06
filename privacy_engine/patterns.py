# -*- coding: utf-8 -*-
"""Built-in rules — regex patterns for all structured sensitive information"""

from dataclasses import dataclass
from typing import Pattern as RePattern
import re


@dataclass(frozen=True)
class Rule:
    """A detection rule"""

    name: str           # Unique identifier, e.g. "ipv4"
    pattern: str        # Regex pattern (will be compiled)
    placeholder: str    # Replacement placeholder, e.g. "[IP]"
    priority: int = 0   # Priority — lower = matched first


# ── Built-in rules ──────────────────────────────────────

BUILTIN_RULES = [
    # ── Network identity ──
    Rule(
        name="ipv4",
        pattern=r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])",
        placeholder="[IP]",
        priority=0,
    ),
    # ── Hex IPv4 ──
    Rule(
        name="ipv4_hex",
        pattern=r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{8}(?![0-9a-fA-F])",
        placeholder="[IP]",
        priority=2,
    ),
    Rule(
        name="ipv6",
        # Core IPv6 pattern: compressed formats match full addresses first to avoid truncation
        pattern=(
            r"\[?"
            r"(?:"
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"       # Full 8 hextets
            r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|"   # Trailing :: (prefer longer)
            r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"    # Leading :: compressed
            r"(?:[0-9a-fA-F]{1,4}:){1,7}:"                       # Ends with :: (last resort)
            r")"
            r"\]?"
        ),
        placeholder="[IP]",
        priority=1,  # Slightly lower than IPv4 so IPv4 matches first in mixed addresses
    ),

    # ── IPv6 hyphen format (FE80-0000-...) ──
    Rule(
        name="ipv6_hyphen",
        pattern=r"(?<![0-9a-fA-F-])[0-9a-fA-F]{4}(?:-[0-9a-fA-F]{4}){7}(?![0-9a-fA-F-])",
        placeholder="[IP]",
        priority=2,
    ),

    # ── UUID (with hyphens) ──
    Rule(
        name="uuid",
        pattern=r"(?<![\da-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{12}(?![\da-fA-F-])",
        placeholder="[UUID]",
    ),

    # ── UUID without hyphens (32-char hex) ──
    Rule(
        name="uuid_hex",
        pattern=r"(?<![\da-fA-F])[0-9a-fA-F]{32}(?![\da-fA-F])",
        placeholder="[UUID]",
        priority=2,  # Lower than email to avoid false positives on domain hex fragments
    ),

    # ── Email ──
    Rule(
        name="email",
        pattern=r"(?<![a-zA-Z0-9.%+-])[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}"
                r"(?![a-zA-Z0-9.%+-])",
        placeholder="[EMAIL]",
    ),

    # ── Phone (China mainland, incl. parenthesis/hyphen variants) ──
    Rule(
        name="phone_cn",
        pattern=r"(?<!\d)1[3-9]\d{9}(?!\d)",
        placeholder="[PHONE]",
    ),
    Rule(
        name="phone_cn_sep",
        pattern=r"(?<!\d)\(?1[3-9]\d\)?[\s.\-]?\d{4}[\s.\-]?\d{4}(?!\d)",
        placeholder="[PHONE]",
        priority=3,
    ),

    # ── Phone (international) ──
    Rule(
        name="phone_intl",
        pattern=r"(?<!\d)\+[1-9]\d{0,2}[\s.\-]?(?:\d[\s.\-]?){5,14}\d(?!\d)",
        placeholder="[PHONE]",
    ),

    # ── ID Card (China mainland) ──
    Rule(
        name="id_card_cn",
        pattern=r"(?<![\dXx])[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
                r"(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])",
        placeholder="[ID_CARD]",
    ),
    # ── ID Card (hyphen-separated) ──
    Rule(
        name="id_card_cn_sep",
        pattern=r"(?<![\dXx])[1-9]\d{5}[\-\s]?(?:19|20)\d{2}[\-\s]?"
                r"(?:0[1-9]|1[0-2])[\-\s]?(?:0[1-9]|[12]\d|3[01])[\-\s]?"
                r"\d{3}[\-\s]?[\dXx](?![\dXx])",
        placeholder="[ID_CARD]",
        priority=4,
    ),

    # ── US SSN ──
    Rule(
        name="ssn_us",
        pattern=r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
        placeholder="[SSN]",
    ),

    # ── API Key (OpenAI sk-/pk-, Anthropic sk-ant-, case-insensitive,
    #    supports multi-hyphen formats sk-live-/sk-test-/sk-proj-/sk-ant-) ──
    Rule(
        name="api_key_prefix",
        pattern=r"(?:(?i:sk|pk)-(?:[A-Za-z0-9]-?){14,}|"
                r"(?i:Bearer)\s+[A-Za-z0-9_\-\.]{10,})",
        placeholder="[API_KEY]",
    ),

    # ── AWS Key (case-insensitive) ──
    Rule(
        name="aws_access_key",
        pattern=r"(?<![A-Za-z0-9])(?i:AKIA)[0-9A-Za-z]{16}(?![A-Za-z0-9])",
        placeholder="[AWS_KEY]",
    ),

    # ── SSH private key header (incl. PKCS#8 generic format without algorithm prefix) ──
    Rule(
        name="ssh_private_key",
        pattern=r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----",
        placeholder="[SSH_KEY]",
    ),

    # ── SSH public key (ssh-rsa / ssh-ed25519 / ecdsa-sha2-... etc.) ──
    Rule(
        name="ssh_public_key",
        pattern=r"(?i)ssh-(?:rsa|ed25519|dss|"
                r"ecdsa-sha2-nistp(?:256|384|521))\s+"
                r"AAAA[A-Za-z0-9+/=]{20,}",
        placeholder="[SSH_KEY]",
        priority=3,
    ),

    # ── 64-char hex hash (SHA256 etc.) ──
    Rule(
        name="sha_hash",
        pattern=r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])",
        placeholder="[HASH]",
        priority=6,
    ),

    # ── GitHub Token (incl. fine-grained PAT prefix github_pat_) ──
    Rule(
        name="github_token",
        pattern=r"(?<![a-zA-Z0-9_])"
                r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,}"
                r"(?![a-zA-Z0-9_])",
        placeholder="[GITHUB_TOKEN]",
    ),

    # ── JWT Token (standard 3-segment + newline-separated variant) ──
    Rule(
        name="jwt",
        pattern=r"(?<![a-zA-Z0-9_\-])eyJ[A-Za-z0-9_-]{10,}\."
                r"[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
                r"(?![a-zA-Z0-9_\-])",
        placeholder="[JWT]",
    ),
    Rule(
        name="jwt_multiline",
        pattern=r"(?<![a-zA-Z0-9_\-])eyJ[A-Za-z0-9_-]{10,}\s*\.\s*\n?\s*"
                r"[A-Za-z0-9_-]{4,}\s*\.\s*\n?\s*"
                r"[A-Za-z0-9_-]{4,}(?![a-zA-Z0-9_\-])",
        placeholder="[JWT]",
        priority=5,
    ),

    # ── Database connection strings (URI + dialect-driver variants) ──
    Rule(
        name="db_connection_string",
        pattern=r"(?:mysql|postgres|postgresql|mongodb|redis|sqlite|oracle|mssql)"
                r"(?:\+[a-zA-Z]\w*)?"
                r"://[^\s]+",
        placeholder="[DB_URL]",
    ),

    # ── CLI-form database connections (psql / mysql / mongo / pg_dump etc.) ──
    Rule(
        name="db_cli",
        pattern=r"(?:psql|mysql|mongo(?:sh)?|redis-cli|sqlite3|sqlcmd|"
                r"pg_dump|pg_dumpall)\s+"
                r"(?:-[a-zA-Z]+\s+\S+\s*)+",
        placeholder="[DB_CMD]",
        priority=5,
    ),

    # ── Credential assignment (inline and line-start, covers plural forms) ──
    # keyword must not be followed directly by a lowercase letter (excludes passwordless, secretly, etc.)
    Rule(
        name="credential_value",
        pattern=(
            r'(?im)^\s*\w*(?:(?<=[_\s])|(?<=^))'
            r'(?i:password|secret|credential|token|api[_\s]?keys?)'
            r'(?=[_\s:=]|[A-Z0-9])\w*'
            r'\s*[:=]\s*'
            r'\S{4,}'
        ),
        placeholder="[CREDENTIAL]",
        priority=10,
    ),

    # ── URL query-string credentials (?user= / ?pass= / &token= etc.) ──
    Rule(
        name="url_query_credential",
        pattern=r"(?i)[?&]\s*(?:"
                r"user(?:name)?|pass(?:word)?|secret|token|key|auth"
                r")\s*=\s*[^&\s]{4,}",
        placeholder="[CREDENTIAL]",
        priority=4,
    ),

    # ── Inline credential detection (no line-start anchor: catches comments/heredoc/logs/CLI) ──
    #    Supports prefixed keywords: DB_PASS, MYSQL_ROOT_PASSWORD, REDIS_AUTH_TOKEN, etc.
    #    Note: does NOT match bare auth/key to avoid false positives on auth_type=basic / primary_key=id
    Rule(
        name="credential_inline",
        pattern=r"(?i)(?<![a-zA-Z0-9])(?:[a-z_]+_)?"
                r"(?:password|passwd|pwd|pass(?:word)?|secret|token|credential|"
                r"auth(?:orization|entication|(?:[_\s](?:token|key|code|secret)))|"
                r"(?:(?:encrypt(?:ion)?|sign(?:ing)?|decrypt(?:ion)?|api|master|"
                r"license|admin)[_\s]?key))s?"
                r"\s*[:=]\s*\S{4,}",
        placeholder="[CREDENTIAL]",
        priority=5,
    ),

    # ── Credit card (format match; Luhn check used in detector as confidence signal) ──
    Rule(
        name="credit_card",
        pattern=r"(?<![\d\-])(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|"
                r"6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
                r"(?![\d\-])",
        placeholder="[CARD]",
    ),
]
