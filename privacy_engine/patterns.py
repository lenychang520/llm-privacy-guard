# -*- coding: utf-8 -*-
"""内置规则库 —— 所有有格式的敏感信息正则模式"""

from dataclasses import dataclass
from typing import Pattern as RePattern
import re


@dataclass(frozen=True)
class Rule:
    """一条检测规则"""

    name: str           # 唯一标识，如 "ipv4"
    pattern: str        # 正则表达式（会被编译）
    placeholder: str    # 替换占位符，如 "[IP]"
    priority: int = 0   # 优先级，越小越先匹配


# ── 内置规则列表 ──────────────────────────────────────────

BUILTIN_RULES = [
    # ── 网络身份 ──
    Rule(
        name="ipv4",
        pattern=r"(?<![\d.])(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}"
                r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)(?![\d.])",
        placeholder="[IP]",
        priority=0,
    ),
    # ── 十六进制 IPv4 ──
    Rule(
        name="ipv4_hex",
        pattern=r"(?<![0-9a-fA-Fx])0x[0-9a-fA-F]{8}(?![0-9a-fA-F])",
        placeholder="[IP]",
        priority=2,
    ),
    Rule(
        name="ipv6",
        # 核心 IPv6 模式：压缩格式优先匹配完整地址，避免被截断
        pattern=(
            r"\[?"
            r"(?:"
            r"(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|"       # 完整 8 段
            r"::(?:[0-9a-fA-F]{1,4}:){0,5}[0-9a-fA-F]{1,4}|"   # 尾部 :: 压缩（优先匹配）
            r"(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|"    # 头部 :: 压缩
            r"(?:[0-9a-fA-F]{1,4}:){1,7}:"                       # 以 :: 结尾（最后匹配）
            r")"
            r"\]?"
        ),
        placeholder="[IP]",
        priority=1,  # 比 IPv4 略低，让 IPv4 先匹配混合地址中的 IPv4 部分
    ),

    # ── IPv6 连字符格式（FE80-0000-...） ──
    Rule(
        name="ipv6_hyphen",
        pattern=r"(?<![0-9a-fA-F-])[0-9a-fA-F]{4}(?:-[0-9a-fA-F]{4}){7}(?![0-9a-fA-F-])",
        placeholder="[IP]",
        priority=2,
    ),

    # ── UUID（带横杠） ──
    Rule(
        name="uuid",
        pattern=r"(?<![\da-fA-F-])[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                r"[0-9a-fA-F]{12}(?![\da-fA-F-])",
        placeholder="[UUID]",
    ),

    # ── UUID 无连字符 32 位 hex ──
    Rule(
        name="uuid_hex",
        pattern=r"(?<![\da-fA-F])[0-9a-fA-F]{32}(?![\da-fA-F])",
        placeholder="[UUID]",
        priority=2,  # 比 email 低，避免误杀域名中的 32 位 hex 片段
    ),

    # ── 邮箱 ──
    Rule(
        name="email",
        pattern=r"(?<![a-zA-Z0-9.%+-])[\w.%+-]+@[\w.-]+\.[A-Za-z]{2,}"
                r"(?![a-zA-Z0-9.%+-])",
        placeholder="[EMAIL]",
    ),

    # ── 手机号（中国大陆，含括号/连字符变体） ──
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

    # ── 国际手机号 ──
    Rule(
        name="phone_intl",
        pattern=r"(?<!\d)\+[1-9]\d{0,2}[\s.\-]?(?:\d[\s.\-]?){5,14}\d(?!\d)",
        placeholder="[PHONE]",
    ),

    # ── 身份证号（中国大陆） ──
    Rule(
        name="id_card_cn",
        pattern=r"(?<![\dXx])[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])"
                r"(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx](?![\dXx])",
        placeholder="[ID_CARD]",
    ),
    # ── 身份证号（连字符分隔） ──
    Rule(
        name="id_card_cn_sep",
        pattern=r"(?<![\dXx])[1-9]\d{5}[\-\s]?(?:19|20)\d{2}[\-\s]?"
                r"(?:0[1-9]|1[0-2])[\-\s]?(?:0[1-9]|[12]\d|3[01])[\-\s]?"
                r"\d{3}[\-\s]?[\dXx](?![\dXx])",
        placeholder="[ID_CARD]",
        priority=4,
    ),

    # ── 美国 SSN ──
    Rule(
        name="ssn_us",
        pattern=r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)",
        placeholder="[SSN]",
    ),

    # ── API Key（OpenAI sk-/pk-，Anthropic sk-ant-，大小写不敏感，
    #    支持多连字符格式 sk-live-/sk-test-/sk-proj-/sk-ant-） ──
    Rule(
        name="api_key_prefix",
        pattern=r"(?:(?i:sk|pk)-(?:[A-Za-z0-9]-?){14,}|"
                r"(?i:Bearer)\s+[A-Za-z0-9_\-\.]{10,})",
        placeholder="[API_KEY]",
    ),

    # ── AWS Key（大小写不敏感） ──
    Rule(
        name="aws_access_key",
        pattern=r"(?<![A-Za-z0-9])(?i:AKIA)[0-9A-Za-z]{16}(?![A-Za-z0-9])",
        placeholder="[AWS_KEY]",
    ),

    # ── SSH 私钥头（含无算法前缀的 PKCS#8 通用格式） ──
    Rule(
        name="ssh_private_key",
        pattern=r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PRIVATE)\s+KEY-----",
        placeholder="[SSH_KEY]",
    ),

    # ── SSH 公钥（ssh-rsa / ssh-ed25519 / ecdsa-sha2-... 等） ──
    Rule(
        name="ssh_public_key",
        pattern=r"(?i)ssh-(?:rsa|ed25519|dss|"
                r"ecdsa-sha2-nistp(?:256|384|521))\s+"
                r"AAAA[A-Za-z0-9+/=]{20,}",
        placeholder="[SSH_KEY]",
        priority=3,
    ),

    # ── 64 位十六进制哈希（SHA256 等） ──
    Rule(
        name="sha_hash",
        pattern=r"(?<![a-fA-F0-9])[a-fA-F0-9]{64}(?![a-fA-F0-9])",
        placeholder="[HASH]",
        priority=6,
    ),

    # ── GitHub Token（含 fine-grained PAT 的 github_pat_ 前缀） ──
    Rule(
        name="github_token",
        pattern=r"(?<![a-zA-Z0-9_])"
                r"(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{22,}"
                r"(?![a-zA-Z0-9_])",
        placeholder="[GITHUB_TOKEN]",
    ),

    # ── JWT Token（标准三段 + 换行分隔变体） ──
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

    # ── 数据库连接字符串（覆盖 URI + dialect driver 变体） ──
    Rule(
        name="db_connection_string",
        pattern=r"(?:mysql|postgres|postgresql|mongodb|redis|sqlite|oracle|mssql)"
                r"(?:\+[a-zA-Z]\w*)?"
                r"://[^\s]+",
        placeholder="[DB_URL]",
    ),

    # ── 命令行形式的数据库连接（psql / mysql / mongo / pg_dump 等） ──
    Rule(
        name="db_cli",
        pattern=r"(?:psql|mysql|mongo(?:sh)?|redis-cli|sqlite3|sqlcmd|"
                r"pg_dump|pg_dumpall)\s+"
                r"(?:-[a-zA-Z]+\s+\S+\s*)+",
        placeholder="[DB_CMD]",
        priority=5,
    ),

    # ── 凭证赋值（支持行内和行首，覆盖复数形式） ──
    # keyword 后不允许直接接小写字母（排除 passwordless、secretly 等）
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

    # ── URL Query String 凭证（?user= / ?pass= / &token= 等） ──
    Rule(
        name="url_query_credential",
        pattern=r"(?i)[?&]\s*(?:"
                r"user(?:name)?|pass(?:word)?|secret|token|key|auth"
                r")\s*=\s*[^&\s]{4,}",
        placeholder="[CREDENTIAL]",
        priority=4,
    ),

    # ── 行内凭证检测（无行首锚定，捕获注释/heredoc/日志/CLI 中的凭证） ──
    #    支持带前缀的关键词：DB_PASS, MYSQL_ROOT_PASSWORD, REDIS_AUTH_TOKEN 等
    #    注意：不包含裸 auth/key，避免误杀 auth_type=basic / primary_key=id
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

    # ── 信用卡号（格式匹配，Luhn 校验在 detector 中作为置信度信号） ──
    Rule(
        name="credit_card",
        pattern=r"(?<![\d\-])(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|"
                r"6(?:011|5\d{2}))[-\s]?\d{4}[-\s]?\d{4}[-\s]?\d{4}"
                r"(?![\d\-])",
        placeholder="[CARD]",
    ),
]
