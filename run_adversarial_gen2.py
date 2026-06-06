# -*- coding: utf-8 -*-
"""对抗测试第2代 — 全新生成的绕过样本，不重复36条静态用例"""

import sys
sys.path.insert(0, ".")

from privacy_engine import filter_text, scan_text

fresh_cases = [
    # ── 零宽字符插入 ──
    "服务器地址是 192\u200b.168\u200b.1\u200b.1 你能ping通吗",
    "token=sk\u200b-proj\u200b-abc123def456 这个key过期了没",

    # ── 同形字攻击（西里尔字母 а/е/о 替换拉丁 a/e/o） ──
    "ssh admin@192.168.1.1 密码是 s\u0435cr\u0435t_p\u0430ss",

    # ── URL 编码的敏感数据 ──
    "请求参数里有个 redirect_uri=https%3A%2F%2Fadmin%3Apass123%4010.0.0.1%3A8080",
    "刚才看到的连接字符串是 mysql%3A%2F%2Froot%3Ahunter2%40192.168.1.100%3A3306%2Fprod",

    # ── Markdown 代码块内嵌敏感信息 ──
    "```yaml\nproduction:\n  host: 203.0.113.42\n  token: ghp_xJ3kL9mN2pQ5rS8tV1wY4zA7bC0dE3fG6h\n```",

    # ── 多行赋值中的敏感值 ──
    "DATABASE_URL = (\n"
    "    'postgresql://prod_admin:S3cur3!Pass@db-primary.internal.io:5432/main'\n"
    ")",

    # ── 环境变量引用风格 ──
    "把 ${AWS_ACCESS_KEY_ID} 设成 AKIAIOSFODNN7EXAMPLE 再用 ${AWS_SECRET_ACCESS_KEY} 签名",

    # ── HTML entities 混淆 ──
    "注册邮箱是 admin&#64;internal&#46;corp&#46;com 但收不到验证码",

    # ── JSON 转义字符串中的敏感数据 ──
    '{"error": "连接 \\"mysql://user:p@ssw0rd@10.20.30.40:3306/db\\" 超时"}',

    # ── IPv4 点分十进制变体（前导零） ──
    "防火墙规则里有一条 192.168.001.001 的入站策略该不该删",

    # ── 键盘布局错位（qwerty→dvorak 或常见手误） ──
    "vi ~/.ssh/authorized_keys 添加了 ssh-rsa AAAAB3NzaC1yc2E... 这个公钥是谁的",

    # ── 注释掉的敏感配置 ──
    "// const API_SECRET = 'sk-live-9a8b7c6d5e4f3a2b1c0d9e8f'; // 已废弃，待删除",

    # ── Bash heredoc 中的凭证 ──
    "cat <<EOF > .env\nDB_PASS=Pr0ducti0n#2024!\nREDIS_AUTH=redis-secret-token-here\nEOF",

    # ── Python f-string 内嵌 ──
    "conn = f'mysql://{os.environ[\"DB_USER\"]}:{os.environ[\"DB_PASS\"]}@{os.environ[\"DB_HOST\"]}'",

    # ── 日志格式中的敏感数据 ──
    "[2024-06-06 10:23:45] ERROR connection refused for user=admin pass=CorrectHorseBatteryStaple host=db-master.prod.internal",

    # ── 电话号码用文字数字混合 ──
    "紧急联系电话 一三九一二三四五六七八 或者直接打 138-1234-5678-910",

    # ── 信用卡号分段标注 BIN ──
    "BIN 是 4532 01，后面补了 11 位数字 51123456789 组成的完整卡号是 45320151123456789",

    # ── AES key 在自然语言中 ──
    "加密用的密钥我存成文件了，内容是 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",

    # ── Docker run 命令含凭证 ──
    "docker run -e MYSQL_ROOT_PASSWORD=my-secret-pw -e API_KEY=sk-ant-api03-xxxxx -p 3306:3306 mysql:8",

    # ── K8s secret 明文 ──
    "apiVersion: v1\nkind: Secret\nmetadata:\n  name: db-credentials\ndata:\n  username: YWRtaW4=\n  password: cGFzc3dvcmQxMjM=",

    # ── 反向混淆——在敏感模式中插入安全词 ──
    "临时IP是192.example.168.com.1.1 这样子不会被防火墙告警吧",

    # ── ROT13 编码 ──
    "密钥是 fx-fgernz-ncv-xrl-ebg13-rapbqrq 记得先用ROT13解码再用",

    # ── Base58 编码（类似比特币地址） ──
    "测试用钱包地址 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 里面有点测试币",

    # ── 身份证号用汉字读法 ──
    "身份证号我念给你听：一一零一零一一九九零零一零一一二三四",

    # ── 密码在 SQL INSERT 语句中 ──
    "INSERT INTO users (email, password_hash) VALUES ('admin@corp.com', '5f4dcc3b5aa765d61d8327deb882cf99')",

    # ── Terraform 变量含凭证 ──
    'variable "db_password" { default = "T3rr4f0rm!S3cur3" }',

    # ── 端口号藏在URL路径里伪装 ──
    "访问 http://internal-api/connect?target=db-primary&port=5432&user=readonly&pass=guest2024",

    # ── cron 表达式中的敏感路径 ──
    "0 2 * * * /usr/bin/pg_dump -h db.internal -U backup -w -f /backup/daily.sql # 密码在 ~/.pgpass",

    # ── 混合全半角零宽 ──
    "key=sk-\u200bｐｒｏｊ\u200b-ａｂｃ１２３ｄｅｆ４５６ 这样能绕过日志过滤",
]

print("=" * 70)
print("LLM Privacy Guard — Gen2 Fresh Adversarial Test")
print("=" * 70)
print()

def _safe(s, n=100):
    return s[:n].encode("gbk", errors="replace").decode("gbk")

caught = 0
leaked = 0
leaks = []

for i, case in enumerate(fresh_cases, 1):
    matches = scan_text(case)
    filtered = filter_text(case)

    if matches:
        caught += 1
        types = ", ".join(m["type"] for m in matches)
        print(f"[OK #{i}] 已捕获 ({types})")
        print(f"  原文: {_safe(case)}...")
        print(f"  过滤: {_safe(filtered)}...")
    else:
        leaked += 1
        leaks.append((i, case))
        print(f"[!! #{i}] 漏网!")
        print(f"  原文: {_safe(case, 120)}...")
    print()

print("=" * 70)
print(f"Result: {caught} caught / {leaked} leaked / {len(fresh_cases)} total")
if leaked:
    print(f"Leak rate: {leaked / len(fresh_cases) * 100:.1f}%")
    print()
    print("--- Leaked Cases ---")
    for idx, text in leaks:
        print(f"  #{idx}: {_safe(text, 150)}")
print("=" * 70)
