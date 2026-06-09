"""Full audit — list ALL potentially sensitive strings, no filtering by 'looks fake'"""
import re, subprocess

commits = subprocess.check_output(
    ["git", "log", "--all", "--oneline"], text=True, encoding="utf-8", errors="replace"
).strip().split("\n")

all_found = {}

for line in commits:
    commit_hash = line.split()[0]
    diff = subprocess.check_output(
        ["git", "show", commit_hash, "--patch"], text=True, encoding="utf-8", errors="replace",
        stderr=subprocess.DEVNULL
    )
    
    patterns = [
        ("UUID", r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I),
        ("IP", r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', 0),
        ("API_KEY", r'sk-[a-zA-Z0-9_-]{16,}', 0),
        ("GITHUB_TOKEN", r'gh[pousr]_[a-zA-Z0-9]{30,}', 0),
        ("AWS_KEY", r'AKIA[A-Z0-9]{16}', 0),
        ("CREDIT_CARD", r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b', 0),
        ("SSH_KEY", r'ssh-(?:rsa|dss|ed25519|ecdsa)\s+[A-Za-z0-9+/=]{100,}', 0),
    ]
    
    for ptype, pattern, flags in patterns:
        for m in re.finditer(pattern, diff, flags):
            val = m.group()
            key = (ptype, commit_hash, val)
            if key not in all_found:
                all_found[key] = commit_hash[:7]

# Print all, sorted by type then value
by_type = {}
for (ptype, ch, val), short_hash in all_found.items():
    by_type.setdefault(ptype, []).append((short_hash, val))

for ptype in ["UUID", "IP", "API_KEY", "GITHUB_TOKEN", "AWS_KEY", "CREDIT_CARD", "SSH_KEY"]:
    if ptype not in by_type:
        continue
    print(f"\n{'='*60}")
    print(f"  {ptype}  ({len(by_type[ptype])} found)")
    print(f"{'='*60}")
    seen = set()
    for short_hash, val in sorted(by_type[ptype], key=lambda x: x[1]):
        if val in seen:
            continue
        seen.add(val)
        print(f"  [{short_hash}]  {val}")
