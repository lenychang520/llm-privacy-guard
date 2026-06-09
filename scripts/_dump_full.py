"""Dump every potentially sensitive data point from all git history"""
import subprocess, re, sys

commits = subprocess.check_output(
    ["git", "log", "--all", "--oneline"], text=True, encoding="utf-8", errors="replace"
).strip().split("\n")

categories = {
    "UUID":         r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}',
    "IPv4":         r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
    "API_KEY":      r'sk-[a-zA-Z0-9_-]{10,}',
    "GITHUB_PAT":   r'gh[pousr]_[a-zA-Z0-9]{30,}|github_pat_[a-zA-Z0-9_]{30,}',
    "AWS_ACCESS":   r'AKIA[A-Z0-9]{16}',
    "AWS_SECRET":   r'(?<=AWS_SECRET|secret_key|SecretAccessKey)[=: ]+?([A-Za-z0-9/+]{30,})',
    "CREDIT_CARD":  r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    "SSH_KEY_BODY": r'AAAA[A-Za-z0-9+/=]{50,}',
    "SSH_PRIV_KEY": r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
    "JWT":          r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}',
    "EMAIL":        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "PHONE_CN":     r'1[3-9]\d{9}',
    "ID_CARD_CN":   r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
    "DB_URL":       r'(?:postgresql|mysql|mongodb|redis|sqlite)://[^\s<>"\']{10,}',
    "BASE64_LONG":  r'(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?',
}

print("=" * 70)
print("  FULL DATA AUDIT — ALL COMMITS")
print("=" * 70)

for cat, pattern in categories.items():
    findings = set()
    for line in commits:
        commit_hash = line.split()[0]
        try:
            diff = subprocess.check_output(
                ["git", "show", commit_hash], text=True, encoding="utf-8",
                errors="replace", stderr=subprocess.DEVNULL
            )
        except:
            continue
        for m in re.finditer(pattern, diff, re.IGNORECASE):
            val = m.group()
            findings.add((commit_hash[:7], val))
    
    if findings:
        print(f"\n{'─'*70}")
        print(f"  [{cat}] — {len(findings)} unique value(s)")
        print(f"{'─'*70}")
        for ch, val in sorted(findings, key=lambda x: x[1]):
            print(f"  {ch}  {val}")

# Also show all file names that exist in any commit
print(f"\n{'─'*70}")
print(f"  [FILES]")
print(f"{'─'*70}")
files = subprocess.check_output(
    ["git", "ls-tree", "-r", "--name-only", "HEAD"], text=True, encoding="utf-8", errors="replace"
)
for f in sorted(files.strip().split("\n")):
    print(f"  {f}")
