"""Dump remaining categories"""
import subprocess, re

commits = subprocess.check_output(
    ["git", "log", "--all", "--oneline"], text=True, encoding="utf-8", errors="replace"
).strip().split("\n")

categories = {
    "CREDIT_CARD":  r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
    "SSH_KEY_BODY": r'AAAA[A-Za-z0-9+/=]{50,}',
    "SSH_PRIV_KEY": r'-----BEGIN [A-Z ]+ PRIVATE KEY-----',
    "JWT":          r'eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}',
    "EMAIL":        r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}',
    "PHONE_CN":     r'1[3-9]\d{9}',
    "ID_CARD_CN":   r'\b[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b',
    "DB_URL":       r'(?:postgresql|mysql|mongodb|redis|sqlite)://[^\s<>"\']{10,}',
    "BASE64_40":    r'(?<!\w)[A-Za-z0-9+/=]{40,}(?!\w)',
}

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
        for m in re.finditer(pattern, diff):
            val = m.group()
            # skip git hashes and commit IDs
            if re.match(r'^[0-9a-f]{40}$', val):
                continue
            findings.add((commit_hash[:7], val[:100]))
    
    if findings:
        print(f"\n{'─'*70}")
        print(f"  [{cat}] — {len(findings)} unique")
        print(f"{'─'*70}")
        for ch, val in sorted(findings, key=lambda x: x[1]):
            print(f"  {ch}  {val}")
