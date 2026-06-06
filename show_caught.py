import sys; sys.path.insert(0, ".")
from privacy_engine import scan_text, filter_text

cases = [
    ("#3 UUID curly braces",
     "In the production config, the old UUID was changed to an uppercase GUID format "
     "like {F81D4FAE-7DEC-47D0-A4E6-3D4B45C64B15}, "
     "which caused the backend service parsing to fail. Should we roll back?"),
    ("#12 postgresql+psycopg2",
     "The new intern can't connect to the public cluster from local. I saw the connection string "
     "hardcoded as postgresql+psycopg2://admin:password123@db.example.com:5432/prod — "
     "our gateway doesn't even support direct connections for this protocol."),
    ("#16 IPv6 brackets",
     "k8s error pasted here: Network unreachable: kubernetes endpoint "
     "[2001:db8::1] port 443 timeout. Feels like the container's CoreDNS isn't resolving correctly."),
    ("#24 GitHub Token uppercase key",
     '{\n  "github_config": {\n    "auth_method": "oauth2",\n'
     '    "GHP_TOKEN": "ghp_abcdefghijklmnopqrstuvwxyz12345678901234"\n  }\n}'),
    ("#27 Credit card spaces",
     "On the payment page, if I accidentally added spaces between every four digits "
     "like 4392 5799 1234 5678 — the frontend just says 'incorrect digit count'. That UX is pretty bad."),
    ("#30 IPv6 mixed IPv4",
     "Data migrated from the old server contains some historical compatibility addresses "
     "like ::ffff:192.0.2.1 — our new gateway seems unable to correctly forward this traffic."),
    ("#35 BEARER uppercase",
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
