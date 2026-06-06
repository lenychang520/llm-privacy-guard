import sys; sys.path.insert(0, ".")
from privacy_engine import scan_text, filter_text

cases = [
    ("#3 UUID花括号",
     "生产环境的配置文件里，那个旧的 uuid 被改成了大写的 GUID 格式，"
     "类似 {F81D4FAE-7DEC-47D0-A4E6-3D4B45C64B15}，"
     "导致后台服务解析报错了，你看看要不要回滚？"),
    ("#12 postgresql+psycopg2",
     "新来的实习生在本地调试，一直连不上公网集群，我看他代码里的连接字符串直接写成了 "
     "postgresql+psycopg2://admin:password123@db.example.com:5432/prod，"
     "咱们网关根本没开这个协议的直连。"),
    ("#16 IPv6方括号",
     "k8s 报错信息贴在这里了：Network unreachable: kubernetes endpoint "
     "[2001:db8::1] port 443 timeout。感觉是容器里的 CoreDNS 解析行为不太对劲。"),
    ("#24 GitHub Token大写key",
     '{\n  "github_config": {\n    "auth_method": "oauth2",\n'
     '    "GHP_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz12345678901234"\n  }\n}'),
    ("#27 信用卡空格",
     "刚才在支付页面输入信用卡号，如果不小心在每四位之间加了空格，"
     "比如像 4392 5799 1234 5678 这样，前端直接提示卡号位数不对，这体验有点糟糕。"),
    ("#30 IPv6混合IPv4",
     "从老服务器迁移过来的数据中，包含了一些历史遗留的兼容地址，"
     "比如 ::ffff:192.0.2.1 这种混合格式，咱们的新网关好像无法正确转发这部分流量。"),
    ("#35 BEARER大写",
     "// HTTP Authorization header configuration for legacy components\n"
     "// Case-insensitive validation check bypass test\n"
     'xhr.setRequestHeader("Authorization", "BEARER sk-abcdefghijklmnopqrstuvwxyz123456");'),
]

for label, text in cases:
    matches = scan_text(text)
    filtered = filter_text(text)
    types = ", ".join(m["type"] for m in matches)
    print(f"=== {label} ===")
    print(f"  Matched: {types}")
    for m in matches:
        print(f"    -> {m['type']}: {m['value'][:50]}  =>  {m['placeholder']}")
    print(f"  Original : {text.strip()}")
    print(f"  Filtered : {filtered.strip()}")
    print()
