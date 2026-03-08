#!/usr/bin/env python3
"""
JSXRay — Python Deep Analysis Module
Entropy analysis, deobfuscation, advanced pattern matching.
Author: Hari Kamma | https://github.com/harikamma/JSXRay
"""

import re, sys, os, json, math, base64, argparse
from collections import Counter
from pathlib import Path

# ── Colors ──
R='\033[1;31m'; G='\033[1;32m'; Y='\033[1;33m'
C='\033[1;36m'; M='\033[1;35m'; W='\033[1;37m'; D='\033[2m'; N='\033[0m'

# ──────────────────────────────────────────────
# ENTROPY
# ──────────────────────────────────────────────
def entropy(s: str) -> float:
    if not s: return 0
    c = Counter(s); n = len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def high_entropy_strings(content: str, min_len=20, threshold=4.5) -> list:
    results = []
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{' + str(min_len) + r',})["\']', content):
        s = m.group(1)
        e = entropy(s)
        if e >= threshold:
            results.append({"value": s, "entropy": round(e, 3), "pos": m.start(), "len": len(s)})
    return results

# ──────────────────────────────────────────────
# OBFUSCATION DETECTION
# ──────────────────────────────────────────────
def detect_obfuscation(content: str) -> dict:
    checks = {
        "eval_call":       bool(re.search(r'\beval\s*\(', content)),
        "atob_call":       bool(re.search(r'\batob\s*\(', content)),
        "fromCharCode":    bool(re.search(r'fromCharCode', content)),
        "hex_literals":    bool(re.search(r'\\x[0-9a-fA-F]{2}', content)),
        "unicode_escapes": bool(re.search(r'\\u[0-9a-fA-F]{4}', content)),
        "p.a.c.k.e.r":    bool(re.search(r"eval\(function\(p,a,c,k,e", content)),
        "obfusc_vars":     bool(re.search(r'\b_0x[0-9a-f]+\b', content)),
        "jsfuck":          bool(re.search(r'(\[\]\+\[\]|\!\[\])', content)),
    }
    score = sum(checks.values())
    checks["score"] = score
    checks["likely_obfuscated"] = score >= 2
    return checks

# ──────────────────────────────────────────────
# DEOBFUSCATION
# ──────────────────────────────────────────────
def decode_atob(content: str) -> list:
    out = []
    for m in re.finditer(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)', content):
        try:
            decoded = base64.b64decode(m.group(1) + "==").decode("utf-8", errors="replace")
            if len(decoded) > 5:
                out.append({"encoded": m.group(1)[:60], "decoded": decoded[:200]})
        except Exception:
            pass
    return out

def decode_fromcharcode(content: str) -> list:
    """Decode String.fromCharCode(...) sequences."""
    out = []
    for m in re.finditer(r'fromCharCode\(([0-9,\s]+)\)', content):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(',') if x.strip().isdigit()]
            decoded = ''.join(chr(n) for n in nums if 32 <= n < 128)
            if len(decoded) > 6:
                out.append({"raw": m.group(0)[:60], "decoded": decoded})
        except Exception:
            pass
    return out

def decode_hex_strings(content: str) -> list:
    out = []
    for m in re.finditer(r'["\']((?:\\x[0-9a-fA-F]{2}){6,})["\']', content):
        try:
            decoded = bytes.fromhex(re.sub(r'\\x', '', m.group(1))).decode("utf-8", errors="replace")
            if len(decoded) > 4:
                out.append({"hex": m.group(1)[:60], "decoded": decoded})
        except Exception:
            pass
    return out

# ──────────────────────────────────────────────
# IMAGE URL PARAM CHECK
# ──────────────────────────────────────────────
def check_image_url_params(url: str) -> list:
    out = []
    SENSITIVE = {'key','token','auth','secret','api','access_token','bearer','password','apikey'}
    if '?' in url:
        for part in url.split('?',1)[1].split('&'):
            if '=' in part:
                k, v = part.split('=', 1)
                if k.lower() in SENSITIVE and len(v) > 5:
                    out.append({"param": k, "value": v, "url": url})
    return out

# ──────────────────────────────────────────────
# SECRET PATTERNS
# ──────────────────────────────────────────────
PATTERNS = {
    "AWS_Key":        r'AKIA[0-9A-Z]{16}',
    "GCP_Key":        r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase_Key":   r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',
    "JWT":            r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',
    "Stripe_Live":    r'sk_live_[0-9a-zA-Z]{24}',
    "Stripe_Test":    r'sk_test_[0-9a-zA-Z]{24}',
    "GitHub_PAT":     r'gh[pousr]_[0-9A-Za-z]{36}',
    "GitLab_PAT":     r'glpat-[0-9a-zA-Z\-]{20}',
    "Slack_Token":    r'xox[baprs]-[0-9a-zA-Z\-]+',
    "Slack_Webhook":  r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/[a-zA-Z0-9_]+',
    "SendGrid":       r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',
    "Telegram_Bot":   r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',
    "MongoDB":        r'mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s]+',
    "PostgreSQL":     r'postgres(?:ql)?://[^:]+:[^@]+@[^\s]+',
    "MySQL":          r'mysql://[^:]+:[^@]+@[^\s]+',
    "Private_Key":    r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "ETH_Key":        r'(?i)(?:private.?key).{0,20}["\'][0-9a-fA-F]{64}["\']',
    "Generic_Secret": r'(?i)(?:secret|api_?key|token|password)["\s:=]{1,10}["\'][A-Za-z0-9_\-]{16,}["\']',
    "Shopify":        r'shpat_[a-fA-F0-9]{32}',
    "Razorpay":       r'rzp_(?:live|test)_[A-Za-z0-9]{14}',
}

def scan_patterns(content: str) -> list:
    out = []
    for name, regex in PATTERNS.items():
        for m in re.finditer(regex, content):
            out.append({"type": name, "value": m.group(0)[:200], "pos": m.start()})
    return out

# ──────────────────────────────────────────────
# COMMENT ANALYSIS
# ──────────────────────────────────────────────
COMMENT_TRIGGERS = re.compile(
    r'(?i)(password|secret|key|token|api|credential|todo.*(remove|delete|fix|hack)|bypass|debug)',
    re.IGNORECASE
)
def sensitive_comments(content: str) -> list:
    out = []
    for m in re.finditer(r'//(.+)', content):
        c = m.group(1).strip()
        if COMMENT_TRIGGERS.search(c):
            line = content[:m.start()].count('\n') + 1
            out.append({"type": "single_line", "content": c[:200], "line": line})
    for m in re.finditer(r'/\*(.*?)\*/', content, re.DOTALL):
        c = m.group(1).strip()
        if COMMENT_TRIGGERS.search(c):
            line = content[:m.start()].count('\n') + 1
            out.append({"type": "multi_line", "content": c[:300], "line": line})
    return out

# ──────────────────────────────────────────────
# MAIN ANALYSIS
# ──────────────────────────────────────────────
def analyze(filepath: str, verbose: bool = False) -> dict:
    try:
        content = Path(filepath).read_text(errors='replace')
    except Exception as e:
        return {"file": filepath, "error": str(e)}

    print(f"\n{C}[*]{N} {W}{filepath}{N} ({len(content):,} bytes)")

    result = {
        "file": filepath,
        "size": len(content),
        "obfuscation": {},
        "high_entropy_strings": [],
        "pattern_matches": [],
        "atob_decoded": [],
        "fromcharcode_decoded": [],
        "hex_decoded": [],
        "sensitive_comments": [],
        "image_url_secrets": []
    }

    # Obfuscation
    obf = detect_obfuscation(content)
    result["obfuscation"] = obf
    if obf["likely_obfuscated"]:
        print(f"  {Y}[OBFUSC]{N} Score {obf['score']}/8 — indicators: " +
              ", ".join(k for k,v in obf.items() if v is True))

    # Entropy
    eh = high_entropy_strings(content)
    result["high_entropy_strings"] = eh
    if eh:
        print(f"  {M}[ENTROPY]{N} {len(eh)} high-entropy strings")
        for h in eh[:5]:
            print(f"    {D}[{h['entropy']}]{N} {h['value'][:80]}")

    # Patterns
    pm = scan_patterns(content)
    result["pattern_matches"] = pm
    if pm:
        print(f"  {R}[PATTERNS]{N} {len(pm)} secret patterns matched")
        for p in pm:
            print(f"    {R}[!]{N} {Y}{p['type']}{N} → {G}{p['value'][:80]}{N}")

    # Deobfuscation
    atob = decode_atob(content)
    result["atob_decoded"] = atob
    if atob:
        print(f"  {C}[ATOB]{N} {len(atob)} base64 decoded")
        for a in atob:
            print(f"    → {a['decoded'][:80]}")

    fcc = decode_fromcharcode(content)
    result["fromcharcode_decoded"] = fcc
    if fcc:
        print(f"  {C}[FROMCHARCODE]{N} {len(fcc)} decoded sequences")
        for f in fcc:
            print(f"    → {f['decoded'][:80]}")

    hex_d = decode_hex_strings(content)
    result["hex_decoded"] = hex_d
    if hex_d:
        print(f"  {C}[HEX-STRINGS]{N} {len(hex_d)} decoded")
        for h in hex_d:
            print(f"    → {h['decoded'][:80]}")

    # Comments
    cmts = sensitive_comments(content)
    result["sensitive_comments"] = cmts
    if cmts:
        print(f"  {Y}[COMMENTS]{N} {len(cmts)} sensitive comments")
        for c in cmts[:3]:
            print(f"    L{c['line']}: {D}{c['content'][:100]}{N}")

    # Image URL params
    img_urls = re.findall(
        r'https?://[^\s"\']+\.(?:png|jpg|jpeg|gif|webp|svg|ico)(?:\?[^\s"\']*)?',
        content, re.IGNORECASE
    )
    for iu in img_urls:
        sec = check_image_url_params(iu)
        if sec:
            result["image_url_secrets"].extend(sec)
            for s in sec:
                print(f"  {R}[IMG-URL]{N} Secret param in image URL: {Y}{s['param']}={s['value']}{N}")
                print(f"    URL: {D}{iu[:100]}{N}")

    return result

# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="JSXRay Python Analyzer — Entropy, Deobfuscation, Deep Pattern Scan",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  python3 jsxray_analyze.py app.js
  python3 jsxray_analyze.py ./jsxray_output/js_files/
  python3 jsxray_analyze.py main.js chunk.js vendor.js -o results.json
  python3 jsxray_analyze.py ./js/ --entropy-threshold 4.2 --min-len 16
        """
    )
    parser.add_argument("targets", nargs="+", help="JS files or directories to analyze")
    parser.add_argument("-o", "--output", default="jsxray_python_results.json",
                        help="Output JSON file (default: jsxray_python_results.json)")
    parser.add_argument("--entropy-threshold", type=float, default=4.5,
                        help="Entropy threshold for high-entropy strings (default: 4.5)")
    parser.add_argument("--min-len", type=int, default=20,
                        help="Minimum string length for entropy analysis (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()

    print(f"{C}")
    print("  ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗")
    print("  ██║╚════██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝")
    print("  ██║    ██╔╝ ╚███╔╝ ██████╔╝███████║ ╚████╔╝ ")
    print("  ██║   ██╔╝  ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝  ")
    print("  ██║   ██║  ██╔╝ ██╗██║  ██║██║  ██║   ██║   ")
    print("  ╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝  ")
    print(f"{N}  {D}Python Deep Analyzer | By Hari Kamma{N}\n")

    # Collect files
    files = []
    for target in args.targets:
        p = Path(target)
        if p.is_file():
            files.append(str(p))
        elif p.is_dir():
            for ext in ("*.js", "*.ts", "*.jsx", "*.tsx", "*.json", "*.mjs"):
                files.extend(str(f) for f in p.rglob(ext))
        else:
            print(f"{Y}[!] Not found: {target}{N}")

    if not files:
        print(f"{R}[!] No files to analyze.{N}")
        sys.exit(1)

    print(f"{C}[*]{N} Analyzing {W}{len(files)}{N} files...\n")

    all_results = []
    for f in files:
        r = analyze(f, args.verbose)
        all_results.append(r)

    # Save
    out_path = args.output
    with open(out_path, 'w') as f:
        json.dump(all_results, f, indent=2)

    # Summary
    total_secrets  = sum(len(r.get("pattern_matches", [])) for r in all_results)
    total_entropy  = sum(len(r.get("high_entropy_strings", [])) for r in all_results)
    total_deobf    = sum(
        len(r.get("atob_decoded",[])) + len(r.get("fromcharcode_decoded",[])) + len(r.get("hex_decoded",[]))
        for r in all_results
    )
    total_comments = sum(len(r.get("sensitive_comments",[])) for r in all_results)
    total_imgs     = sum(len(r.get("image_url_secrets",[])) for r in all_results)
    obfusc_files   = sum(1 for r in all_results if r.get("obfuscation",{}).get("likely_obfuscated"))

    print(f"\n{C}{'═'*52}{N}")
    print(f"{W}{C}  JSXRay Python Analysis Summary{N}")
    print(f"{C}{'═'*52}{N}")
    print(f"  Files Analyzed         : {W}{len(files)}{N}")
    print(f"  Obfuscated Files       : {Y}{obfusc_files}{N}")
    print(f"  Pattern Matches        : {R}{total_secrets}{N}")
    print(f"  High-Entropy Strings   : {M}{total_entropy}{N}")
    print(f"  Deobfuscated Values    : {C}{total_deobf}{N}")
    print(f"  Sensitive Comments     : {Y}{total_comments}{N}")
    print(f"  Image URL Secrets      : {R}{total_imgs}{N}")
    print(f"  Output                 : {G}{out_path}{N}")
    print(f"{C}{'═'*52}{N}\n")
    print(f"{D}  ⚠  Authorized use only. — Hari Kamma{N}\n")

if __name__ == "__main__":
    main()
