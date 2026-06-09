"""Dump ALL test data / example strings from every commit, no filtering"""
import subprocess, re

commits = subprocess.check_output(
    ["git", "log", "--all", "--oneline"], text=True, encoding="utf-8", errors="replace"
).strip().split("\n")

# Collect every quoted string from every commit
all_strings = []

for line in commits:
    commit_hash = line.split()[0]
    diff = subprocess.check_output(
        ["git", "show", commit_hash], text=True, encoding="utf-8", errors="replace",
        stderr=subprocess.DEVNULL
    )
    
    # Extract all quoted strings (single and double)
    for m in re.finditer(r'''["']([^"']{6,})["']''', diff):
        s = m.group(1)
        # Skip obvious code
        if s.startswith(".") or s.startswith("/") or s.startswith("\\"):
            continue
        if s.startswith("git ") or s.startswith("cd "):
            continue
        if s in ("true", "false", "none", "null", "info", "error", "warning"):
            continue
        all_strings.append((commit_hash[:7], s))

# Deduplicate
seen = set()
unique = []
for ch, s in all_strings:
    if s not in seen:
        seen.add(s)
        unique.append((ch, s))

print(f"=== ALL UNIQUE STRING LITERALS (6+ chars) ACROSS {len(commits)} COMMITS ===\n")
for ch, s in sorted(unique, key=lambda x: x[1]):
    # Highlight suspicious ones
    marker = ""
    if re.search(r'[0-9a-f]{8}-[0-9a-f]{4}', s, re.I):
        marker = " [UUID]"
    elif re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', s):
        marker = " [IP]"
    elif re.search(r'sk-', s):
        marker = " [API_KEY]"
    elif re.search(r'ghp_|github_pat_', s):
        marker = " [TOKEN]"
    elif re.search(r'AKIA', s):
        marker = " [AWS]"
    elif re.search(r'\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}', s):
        marker = " [CARD]"
    elif re.search(r'(password|passwd|secret|token).{3,}', s, re.I):
        marker = " [CRED]"
    
    print(f"  [{ch}]{marker} {s[:120]}")
