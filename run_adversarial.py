# -*- coding: utf-8 -*-
"""Adversarial test suite — run through all AI-generated samples, find leaks"""

import sys
sys.path.insert(0, ".")

from privacy_engine import filter_text, scan_text

test_cases = [
    # 1 — IPv4 [.] bypass
    'Hey, I\'m sending you the internal DB proxy config — address is 192[.]168[.]1[.]150, use port 3306 to check if data sync is stuck.',

    # 2 — IPv6 hyphen format
    'Just checked the packet capture — the gateway returned an error log showing Connecting to FE80-0000-0000-0000-0202-B3FF-FE1E-8329 failed, looks like the IPv6 routing policy is misconfigured.',

    # 3 — UUID GUID curly braces
    'In the production config, the old UUID was changed to an uppercase GUID format like {F81D4FAE-7DEC-47D0-A4E6-3D4B45C64B15}, which caused the backend service parsing to fail. Should we roll back?',

    # 4 — Email [at] bypass
    'Urgently need Finance Zhang! The invoice header is wrong and the bounce says address not found. Anyone have her latest internal email? I tried zhangjie at company and it didn\'t deliver — can someone ask if her alias changed?',

    # 5 — Phone fullwidth digits (NFKC test: CJK)
    'Notice: The front desk just received a SF Express package. The recipient phone is written as １３９１２３４５６７８. Name is illegible — tech team please come claim it.',

    # 6 — ID card hyphen-separated
    'Just checked the government system — the form instructions say if the ID number has an X, try separating the birthday with hyphens, like 110101-19900101-1234. Have you tried submitting that way?',

    # 7 — API Key s-k segmented
    '# deploy_config.yml\napp:\n  env: production\n  auth:\n    provider: openai\n    secret_type: short_lived\n    s-k: 4pX9zW2mQ7vB1kL5n_custom_short',

    # 8 — AWS Key lowercase
    'Who pasted the test environment AK in the dev group chat? Even though it\'s lowercase akiaqt4v25abcd6efghj, the security compliance team is sending out company-wide notices — whoever did it, go revoke those credentials ASAP!',

    # 9 — SSH private key without algorithm prefix
    '# TODO: Jenkins pipeline migration script\n# Kept standard header but stripped the actual bit strength prefix to check parser behavior\necho "-----BEGIN PRIVATE KEY-----" >> ./tmp_key\necho "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC3yV..." >> ./tmp_key\necho "-----END PRIVATE KEY-----" >> ./tmp_key',

    # 10 — GitHub Token new format github_pat_
    'After switching to fine-grained permissions, the new release script needs updating. The docs say the token format has changed, prefix is github_pat_11A22B33C44D55E66F77G88H99I00J11K22L33 — don\'t use the old format anymore.',

    # 11 — JWT newline + dot separator
    'The session data from the frontend looks weird. Even though it has three parts, they\'re separated by newlines with dots:\neyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\n.\neyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ\n.\nsignature — can this still decode properly?',

    # 12 — DB postgresql+psycopg2
    'The new intern can\'t connect to the public cluster from local. I saw the connection string hardcoded in their code as postgresql+psycopg2://admin:password123@db.example.com:5432/prod — our gateway doesn\'t even support direct connections for this protocol.',

    # 13 — Credit card fullwidth digits + spaces (NFKC test: CJK)
    'Customer support says a VIP customer reported a payment failure. The card number format seems to have fullwidth digits ４３９２ ５７９９ １２３４ ５６７８, and the backend logs just report invalid format — devs should check if the validation regex is too rigid.',

    # 14 — High-entropy: short concatenated strings + CJK punctuation
    '# Temp locally-generated salted obfuscation vars, limited to <16 chars to prevent overflow\nsalt_var1 = "x7R!m9$pQ2#bW4v"\nsalt_var2 = "k9*zL2@nP5%qX7t"\nfinal_key = salt_var1 + salt_var2',

    # 15 — IPv4 hex
    'Excuse me, can anyone look up the production cluster\'s public egress IP? I used a hex tool and the numeric address is roughly 0xC0A80101 — need it ASAP to configure the external API whitelist.',

    # 16 — IPv6 brackets
    'The k8s error is pasted here: Network unreachable: kubernetes endpoint [2001:db8::1] port 443 timeout. Feels like the CoreDNS in the container isn\'t resolving correctly.',

    # 17 — UUID 32-char hex without hyphens
    'For that offline task, don\'t use the regular hyphenated format for the trace ID — just pass the full 32-char hex string 550e8400e29b41d4a716446655440000 directly so the downstream system can recognize it properly.',

    # 18 — Email: Chinese username + [at]
    'Urgent help — can anyone reach the architect on the partner side? Their email seems to be ops-zhang[at]ext-domain.com — I\'ve sent several business emails and they all bounced. Anyone have a phone number? DM me.',

    # 19 — Phone +86 with spaces
    'Can the on-call ops please check — the emergency contact number left for today is +86 186 9876 5432 and the format seems to be erroring in the notification system. Are the spaces causing the system to not recognize it?',

    # 20 — ID card fullwidth digits (NFKC test: CJK)
    'System says input is invalid — probably because I copied the ID card number with fullwidth digits: ３２０１０６１９８５０４１２ X. Can any teacher help manually fix it in the database backend?',

    # 21 — API Key uppercase API-KEY short token
    'export API_CREDENTIALS_V2="API-KEY_V2_4pX9zW2mQ7vB1kL" # Using short-byte strategy to avoid triggering long-string warnings in the audit log component',

    # 22 — AWS Key split across two segments
    'The security audit report says an old deployment script has AWS_ACCESS_KEY_ID=AKIA followed by a temp variable concatenation — even though it\'s split into two segments, they still recommend refactoring it.',

    # 23 — SSH key path + base64 mention
    'Don\'t post private key files directly in the group chat. If it\'s inconvenient to use the jump host, just base64-encode the whole text, or tell me which alias you\'re using under ~/.ssh/id_ed25519.',

    # 24 — GitHub Token uppercase key
    '{\n  "github_config": {\n    "auth_method": "oauth2",\n    "GHP_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz12345678901234"\n  }\n}',

    # 25 — JWT only two segments
    'This JWT seems truncated — only has the header and payload parts: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbkBleGFtcGxlLmNvbSIsInJvbGUiOiJhZG1pbiJ9 — is the signature just empty or is the backend not verifying?',

    # 26 — DB: MySQL CLI format
    'This SQL dump script I found on the server: mysql -h db-prod-1.internal.io -u analytics_ro -pS3cur3R3ad0nly -D analytics_prod < /tmp/export.sql — is this still in use?',

    # 27 — Credit card with spaces
    'On the payment page just now, if I accidentally added spaces between every four digits — like 4392 5799 1234 5678 — the frontend just says "incorrect digit count". That UX is pretty bad.',

    # 28 — IPv6 with trailing double-colon (just ::)
    'The local test environment is having all kinds of IPv6 binding issues. Running ip -6 addr show, the loopback shows ::1, which shouldn\'t cause route conflicts towards the internet, right?',

    # 29 — IPv6 uppercase with compression
    'I found this address in the DNS zone file that looks suspicious, written as 2001:0DB8:0000:0000:0000:FF00:0042:8329 — looks like the full expanded format. Should we clean up the record?',

    # 30 — IPv6 mixed IPv4
    'The data migrated from the old server contains some historical compatibility addresses like ::ffff:192.0.2.1 — our new gateway seems unable to correctly forward this traffic.',

    # 31 — IPv4 with leading zeros
    'The firewall rule has an inbound policy for 192.168.001.001 — should we delete this rule?',

    # 32 — Credential assignment in comment
    '// const DATABASE_PASSWORD = "C0mpl3x!P@ss#2024"; // deprecated, pending removal',

    # 33 — Inline credential in heredoc
    'cat <<EOF > .env\n  APP_SECRET=s3cr3t-k3y-f0r-jwt\n  DB_PASSWORD=prod-db-p@ss\nEOF',

    # 34 — URL-encoded IPv4
    'The request params have redirect_uri=https%3A%2F%2Fadmin%3Apass123%40192.168.1.100%3A8080 — is this old config still active?',

    # 35 — BEARER uppercase
    '// HTTP Authorization header configuration for legacy components\n// Case-insensitive validation check bypass test\nxhr.setRequestHeader("Authorization", "BEARER sk-abcdefghijklmnopqrstuvwxyz123456");',

    # 36 — SSH public key in authorized_keys format
    'I added this to ~/.ssh/authorized_keys: ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC8... user@host — is this key registered correctly?',
]

print("=" * 70)
print("LLM Privacy Guard — Adversarial Test Report")
print("=" * 70)
print()

caught = 0
leaked = 0
leaks = []

def _safe(s, n=100):
    return s[:n].encode("gbk", errors="replace").decode("gbk")

for i, case in enumerate(test_cases, 1):
    matches = scan_text(case)
    filtered = filter_text(case)

    if matches:
        caught += 1
        types = ", ".join(m["type"] for m in matches)
        print(f"[OK #{i}] Caught ({types})")
        print(f"  Raw     : {_safe(case, 80)}...")
        print(f"  Filtered: {_safe(filtered, 80)}...")
    else:
        leaked += 1
        leaks.append((i, case))
        print(f"[!! #{i}] LEAKED!")
        print(f"  Raw: {_safe(case, 120)}...")
    print()

print("=" * 70)
print(f"Result: {caught} caught / {leaked} leaked / {len(test_cases)} total")
if leaked:
    print(f"Leak rate: {leaked / len(test_cases) * 100:.1f}%")
    print()
    print("--- Leaked Cases ---")
    for idx, text in leaks:
        print(f"  #{idx}: {_safe(text, 150)}")
print("=" * 70)
