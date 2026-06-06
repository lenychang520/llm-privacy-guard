# -*- coding: utf-8 -*-
"""核心引擎功能测试 + 对抗回归测试"""

import sys
sys.path.insert(0, ".")

from privacy_engine import filter_text, scan_text, add_rule

passed = 0
failed = 0


def check(label, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  [PASS] {label}")
    else:
        failed += 1
        print(f"  [FAIL] {label}  {detail}")


# ══════════════════════════════════════════════════════
# 正向功能测试
# ══════════════════════════════════════════════════════

print("=" * 60)
print("PART 1: 正向功能测试")
print("=" * 60)

# 1 — IPv4
result = filter_text("ssh root@[REDACTED_IP] ufw status")
check("IPv4 公网", "[IP]" in result and "[REDACTED_IP]" not in result, result)

# 2 — UUID 带横杠
result = filter_text("UUID: 4e0a1c0d-3342-4d5b-8785-6618aff9b102")
check("UUID 带横杠", "[UUID]" in result and "4e0a1c0d" not in result, result)

# 3 — API Key
result = filter_text("Authorization: Bearer sk-abc123def45678901234567890")
check("API Key", "[API_KEY]" in result and "sk-abc123" not in result, result)

# 4 — 私有 IP 现在也过滤
result = filter_text("ping 127.0.0.1 && ping 192.168.1.1 && ping 10.0.0.1")
check("私有 IP 过滤", all(x not in result for x in ["127.0.0.1", "192.168.1.1", "10.0.0.1"]), result)

# 5 — 协议地址 0.0.0.0 依然保留
result = filter_text("bind 0.0.0.0:8080")
check("0.0.0.0 白名单", "0.0.0.0" in result, result)

# 6 — scan
matches = scan_text("IP: [REDACTED_IP], UUID: abcd1234-5678-abcd-1234-5678abcdef01, key=sk-test12345678901234567890")
check("scan 检测", len(matches) >= 3, f"got {len(matches)}")

# 7 — add_rule
add_rule("test_project", r"PROJ-\d{6}", "[PROJECT]")
result = filter_text("部署 PROJ-123456 到服务器")
check("自定义规则", "[PROJECT]" in result, result)

# 8 — 邮箱
result = filter_text("联系 admin@company.com")
check("邮箱", "[EMAIL]" in result, result)

# 9 — 中国大陆手机号
result = filter_text("电话: 13812345678")
check("手机号 CN", "[PHONE]" in result, result)

# 10 — 中国大陆身份证
result = filter_text("身份证: 110101199001011234")
check("身份证 CN", "[ID_CARD]" in result, result)

# 11 — 所有规则默认可加载
from privacy_engine import PrivacyDetector
d = PrivacyDetector()
check(f"规则加载 ({len(d._rules)} 条)", len(d._rules) >= 18, f"got {len(d._rules)}")

# ══════════════════════════════════════════════════════
# 对抗回归测试（应已修复的）
# ══════════════════════════════════════════════════════

print()
print("=" * 60)
print("PART 2: 对抗回归测试（应已修复）")
print("=" * 60)

# Unicode 归一化 — 全角手机号
result = filter_text("电话: １３９１２３４５６７８")
check("全角数字 → 手机号", "[PHONE]" in result, result)

# Unicode 归一化 — 全角信用卡（Luhn 失败 → filter 不替换，scan 仍可检出）
result = filter_text("卡号 ４３９２ ５７９９ １２３４ ５６７８")
check("全角数字 → 信用卡", "[CARD]" not in result, "NFKC 归一化生效但 Luhn 不通过，不应替换")
# 确认 scan 能检出（低置信度）
m = scan_text("卡号 ４３９２ ５７９９ １２３４ ５６７８")
check("全角数字 → 信用卡 scan 可检出", any(x["type"] == "credit_card" and x["confidence"] == "low" for x in m), f"matched: {[x['type'] for x in m]}")

# AWS Key 大小写不敏感
result = filter_text("抢注 akiaqt4v25abcd6efghj 测试")
check("AWS Key 小写", "[AWS_KEY]" in result, result)

# GitHub fine-grained PAT
result = filter_text("token 是 github_pat_11A22B33C44D55E66F77G88H99I00J11K22L33")
check("GitHub PAT 新前缀", "[GITHUB_TOKEN]" in result, result)

# SSH PRIVATE KEY 通用格式
result = filter_text("-----BEGIN PRIVATE KEY-----\nMIIEvg...\n-----END PRIVATE KEY-----")
check("SSH PKCS#8 通用", "[SSH_KEY]" in result, result)

# UUID 32 位 hex 无横杠
result = filter_text("trace id: 550e8400e29b41d4a716446655440000")
check("UUID 无横杠", "[UUID]" in result, result)

# DB 连接 dialect driver
result = filter_text("连接 postgresql+psycopg2://admin:pass@db.example.com:5432/prod")
check("DB 连接 dialect driver", "[DB_URL]" in result, result)

# DB 命令行格式
result = filter_text("psql -h pg-server.internal -U readonly -d prod -p 5432")
check("DB CLI 命令行", "[DB_CMD]" in result, result)

# 信用卡 Luhn 失败 → filter 不替换，scan 低置信度仍可检出
result = filter_text("卡号 4392 5799 1234 5678")
check("信用卡 Luhn 不替换", "[CARD]" not in result, "Luhn 失败不应替换")
m = scan_text("卡号 4392 5799 1234 5678")
check("信用卡 Luhn scan 可检出", any(x["type"] == "credit_card" for x in m), f"matched: {[x['type'] for x in m]}")

# IPv6 连字符格式
result = filter_text("连接 FE80-0000-0000-0000-0202-B3FF-FE1E-8329 失败")
check("IPv6 连字符格式", "[IP]" in result, result)

# IPv6 方括号 + 压缩格式 → 不应有残骸
result = filter_text("endpoint [2001:db8::1] port 443 timeout")
check("IPv6 方括号无残骸", "[IP]" in result and "1]" not in result, result)

# IPv6 混合 IPv4
result = filter_text("地址 ::ffff:192.0.2.1 格式")
check("IPv6 混合 IPv4", "[IP]" in result and "0.2.1" not in result, result)

# 十六进制 IPv4
result = filter_text("地址 0xC0A80101 对应")
check("IPv4 十六进制", "[IP]" in result, result)

# JWT 跨行格式（已加 jwt_multiline 规则）
result = filter_text("eyJhbGciOiJIUzI1NiJ9\n.\nQzJ9\n.\nSflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c")
check("JWT 跨行格式", "[JWT]" in result, result)

# 手机号含括号
result = filter_text("电话 (135)1234-5678")
check("手机号含括号", "[PHONE]" in result, result)

# 身份证含连字符
result = filter_text("号码 110101-19900101-1234 确认")
check("身份证含连字符", "[ID_CARD]" in result, result)

# ══════════════════════════════════════════════════════
# 已知限制（明确不会修）
# ══════════════════════════════════════════════════════

print()
print("=" * 60)
print("PART 3: 已知限制（预期漏网）")
print("=" * 60)

# 确认预期漏网的不是 false negative
result = filter_text("192[.]168[.]1[.]150")
check("[.] 混淆 → 预期漏网", "192" in result or "168" in result, "混淆绕过属于正则范式极限")

result = filter_text("zhangjie at company")
check("at 替代 @ → 预期漏网", "zhangjie" in result, "自然语言混淆")

result = filter_text("127 . 0 . 0 . 1")
check("IP 空格 → 预期漏网", "127" in result, "空格分隔混淆")

# ══════════════════════════════════════════════════════

print()
print("=" * 60)
print(f"RESULT: {passed} passed, {failed} failed, {passed+failed} total")
print("=" * 60)

if failed > 0:
    sys.exit(1)
