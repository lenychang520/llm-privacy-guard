# -*- coding: utf-8 -*-
"""对抗测试：跑一遍全部 AI 生成的样本，找出漏网之鱼"""

import sys
sys.path.insert(0, ".")

from privacy_engine import filter_text, scan_text

test_cases = [
    # 1 — IPv4 [.] 绕过
    '老大，我把内网的临时数据库代理配置发你，地址是 192[.]168[.]1[.]150，你用 3306 连进去看看是不是数据同步卡住了。',
    # 2 — IPv6 混合格式
    '刚刚抓包看了一下请求，对方网关返回的错误日志里写着 Connecting to FE80-0000-0000-0000-0202-B3FF-FE1E-8329 failed，感觉是 IPv6 的路由策略配错了。',
    # 3 — UUID GUID 花括号
    '生产环境的配置文件里，那个旧的 uuid 被改成了大写的 GUID 格式，类似 {F81D4FAE-7DEC-47D0-A4E6-3D4B45C64B15}，导致后台服务解析报错了，你看看要不要回滚？',
    # 4 — 邮箱 [at] 绕过
    '急找财务张姐！发票抬头有误，退信提示找不到地址。谁有她最新的内网工作邮箱？我试了 zhangjie at company 投递不成功，帮我问问是不是换别名了。',
    # 5 — 手机号全角数字
    '通知：刚才前台收到一个顺丰快递，收件人电话写的是 １３９１２３４５６７８，名字模糊不清，请技术部的同学过去认领一下。',
    # 6 — 身份证连字符分段
    '刚刚去政务系统查了一下，填表说明里写着如果身份证号带 X，可以试试用连字符把生日隔开输入，比如像 110101-19900101-1234 这样提交，你试过了吗？',
    # 7 — API Key s-k 分段
    '# deploy_config.yml\napp:\n  env: production\n  auth:\n    provider: openai\n    secret_type: short_lived\n    s-k: 4pX9zW2mQ7vB1kL5n_custom_short',
    # 8 — AWS Key 小写
    '研发群里谁把测试环境的 AK 顺手粘出来了，虽然是小写的 akiaqt4v25abcd6efghj，但安全合规团队在全员通报了，当事人赶紧去把权限撤销掉！',
    # 9 — SSH 私钥无算法前缀
    '# TODO: Jenkins pipeline migration script\n# Kept standard header but stripped the actual bit strength prefix to check parser behavior\necho "-----BEGIN PRIVATE KEY-----" >> ./tmp_key\necho "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3yV..." >> ./tmp_key\necho "-----END PRIVATE KEY-----" >> ./tmp_key',
    # 10 — GitHub Token 新格式 github_pat_
    '换了细粒度权限之后，新的线上发布脚本需要更新。我看文档上写着现在的 token 格式变了，前缀是 github_pat_11A22B33C44D55E66F77G88H99I00J11K22L33 这种，别再用以前的旧格式了。',
    # 11 — JWT 换行+点号
    '前端拿到的 Session 数据格式好奇怪，虽然有三个部分，但中间是用换行符加点号拼起来的：eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n.\neyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ\n.\nsignature，这还能正常解码吗？',
    # 12 — DB postgresql+psycopg2
    '新来的实习生在本地调试，一直连不上公网集群，我看他代码里的连接字符串直接写成了 postgresql+psycopg2://admin:password123@db.example.com:5432/prod，咱们网关根本没开这个协议的直连。',
    # 13 — 信用卡全角数字+空格
    '客服部反馈有个 VIP 客户反映线上支付失败，卡号格式好像带了全角数字 ４３９２ ５７９９ １２３４ ５６７８，后台日志直接报格式非法，开发看一下是不是校验正则太死板了。',
    # 14 — 高熵：拼接后 <16 + 中文标点
    '# 临时生成的本地加盐混淆变量，长度限制在15位以内以防溢出\nsalt_var1 = "x7R!m9$pQ2#bW4v"\nsalt_var2 = "k9*zL2@nP5%qX7t"\nfinal_key = salt_var1 + salt_var2',
    # 15 — IPv4 十六进制
    '打扰了，有谁能帮我查一下生产集群的公网出口吗？刚刚用十六进制工具算了一下，对应的数字地址大概是 0xC0A80101，急着配置外部 API 的白名单。',
    # 16 — IPv6 方括号
    'k8s 报错信息贴在这里了：Network unreachable: kubernetes endpoint [2001:db8::1] port 443 timeout。感觉是容器里的 CoreDNS 解析行为不太对劲。',
    # 17 — UUID 无连字符 32 位 hex
    '那个离线任务的追踪 ID 别用常规的连字符了，直接传一整串 32 位的十六进制字符串 550e8400e29b41d4a716446655440000 过去，下游系统才能正常识别。',
    # 18 — 邮箱 中文用户名 + [at]
    '紧急求助，谁能联系上对接方那边的架构师？他的邮箱好像是 运维小张[at]ext-domain.com，我发了几封商务邮件全被退回了，有电话的私聊我一个。',
    # 19 — 手机号 +86 空格
    '麻烦让值班运维看一下，今天值班留的紧急联系人电话 +86 186 9876 5432 格式好像在通知系统里报错了，是不是空格导致系统没识别出来？',
    # 20 — 身份证全角数字
    '系统报输入非法，可能是因为我把身份证号里的全角数字直接复制进去了：３２０１０６１９８５０４１２ X，有哪位老师能帮忙在数据库后台手动修正一下吗？',
    # 21 — API Key 大写 API-KEY 短 token
    'export API_CREDENTIALS_V2="API-KEY_V2_4pX9zW2mQ7vB1kL" # 采用短字节策略，避免日志组件在审计时触发长字符串警告',
    # 22 — AWS Key 分段
    '安全审计报告里说，在一段老的部署脚本里发现了 AWS_ACCESS_KEY_ID=AKIA 后面拼接临时变量的写法，虽然拆成了两段，但还是建议重构掉。',
    # 23 — SSH 私钥路径 + base64
    '别直接在群里发私钥文件，如果不方便传跳板机，就用 Base64 把整个文本编码一遍，或者直接告诉我你在 ~/.ssh/id_ed25519 下面用的是哪个别名就行。',
    # 24 — GitHub Token 大写前缀
    '{\n  "github_config": {\n    "auth_method": "oauth2",\n    "GHP_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz12345678901234"\n  }\n}',
    # 25 — JWT 只有两段
    '移动端反馈说在某些旧版本系统上，拿到的 JWT 只有两段，格式是 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VySWQiOiIxMjM0NTY3ODkwIn0=，没有最后的签名部分，导致鉴权直接挂了。',
    # 26 — DB psql 命令行
    '别用那种标准的 URL 格式了，直接用原生的命令行参数连：psql -h pg-server.internal -U readonly_user -d business_db -p 5432，这样更方便写进文档里。',
    # 27 — 信用卡 空格
    '刚才在支付页面输入信用卡号，如果不小心在每四位之间加了空格，比如像 4392 5799 1234 5678 这样，前端直接提示卡号位数不对，这体验有点糟糕。',
    # 28 — 高熵 中文逗号
    '为了防止混淆，我们在随机生成的初始化凭证中间故意插入了一个中文逗号：k7$m9_Pq2！bW4vX8z，这样既能提高熵值，又方便人工肉眼辨识。',
    # 29 — IPv4 空格
    '运维组的兄弟，今天更新了主机的 hosts 文件，把本地的回环路由写成了 127 . 0 . 0 . 1，导致很多本地代理服务都断摆了，赶快上去批量修复一下。',
    # 30 — IPv6 ::ffff:ipv4
    '从老服务器迁移过来的数据中，包含了一些历史遗留的兼容地址，比如 ::ffff:192.0.2.1 这种混合格式，咱们的新网关好像无法正确转发这部分流量。',
    # 31 — UUID base64
    '在做 API 迁移的时候，发现有个请求参数直接传了 Base64 编码后的数据：VTUwZTg0MDBlMjliNDFkNGE3MTY0NDY2NTU0NDAwMDA=，解码出来居然是一个没有连字符的原始 UUID。',
    # 32 — 邮箱 无 TLD
    '找人启事：哪位大佬认识 用户@internal-cluster 这个内网信箱的主人？他刚才提交了一个占用大量内存的死循环脚本，现在整个开发环境都卡死了。',
    # 33 — 手机号 全角括号
    '刚刚看了一下系统的报错信息，有个用户的联系方式填的是 （135）1234-5678，括号是全角的，导致短信接口直接返回了手机号格式不正确的错误代码。',
    # 34 — 身份证 自然语言
    '在进行旧系统数据归档时，发现有一些早期手工录入的记录，身份证字段直接写成了 \'某省某市1980年05月12日出生的某人\'，这种非结构化文本该怎么清洗？',
    # 35 — API Key BEARER 大写
    '// HTTP Authorization header configuration for legacy components\n// Case-insensitive validation check bypass test\nxhr.setRequestHeader("Authorization", "BEARER sk-abcdefghijklmnopqrstuvwxyz123456");',
    # 36 — 高熵 <16 截断
    '这串高熵密匙在同步的时候被截断了，现在只剩下最后的 15 个字符 9$pQ2#bW4vX8z*k，大家帮我想想办法，看能不能从之前的备份日志里恢复前半部分。',
]

print("=" * 70)
print("LLM Privacy Guard Adversarial Test Report")
print("=" * 70)
print()

caught = 0
leaked = 0
leaks = []

for i, case in enumerate(test_cases, 1):
    matches = scan_text(case)
    filtered = filter_text(case)
    
    if matches:
        caught += 1
        types = ", ".join(m["type"] for m in matches)
        print(f"[OK #{i}] 已捕获 ({types})")
        print(f"  原文: {case[:80]}...")
        print(f"  过滤: {filtered[:80]}...")
    else:
        leaked += 1
        leaks.append((i, case))
        print(f"[!! #{i}] 漏网!")
        print(f"  原文: {case[:100]}...")
    print()

print("=" * 70)
print(f"Result: {caught} caught / {leaked} leaked / {len(test_cases)} total")
if leaked:
    print(f"Leak rate: {leaked / len(test_cases) * 100:.1f}%")
    print()
    print("--- Leaked Cases ---")
    for idx, text in leaks:
        print(f"  #{idx}: {text[:120]}")
print("=" * 70)
