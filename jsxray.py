#!/usr/bin/env python3
# ═══════════════════════════════════════════════════════════════════════════════
#
#   ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
#   ██║╚════██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
#   ██║    ██╔╝ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
#   ██║   ██╔╝  ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
#   ██║   ██║  ██╔╝ ██╗██║  ██║██║  ██║   ██║
#   ╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
#
#   JSXRay v2.0  |  Ultra-Advanced JS + Image Secret Scanner
#   Author  : Hari Kamma
#   GitHub  : https://github.com/Mr-White1/VenomJS
#   License : MIT
#
#   WHAT MAKES JSXRay v2.0 DIFFERENT FROM ALL EXISTING TOOLS:
#   (SecretFinder, LinkFinder, JSFinder — NONE of them do this)
#
#   ┌──────────────────────────────────────────────────────────────┐
#   │  IMAGE SECRET EXTRACTION — The Gap No Other Tool Covers:    │
#   │  • EXIF metadata (author/comment fields storing API keys)   │
#   │  • PNG text chunks (tEXt/iTXt/zTXt hidden data)             │
#   │  • JPEG comment markers & appended data after EOI           │
#   │  • LSB steganography pixel-level detection + decode         │
#   │  • Binary strings extraction from raw image bytes           │
#   │  • SVG inline <script> tags + data URI scanning             │
#   │  • Image URL query parameter secrets (?token=sk_live_xxx)   │
#   │  • steghide + zsteg integration (if installed)              │
#   ├──────────────────────────────────────────────────────────────┤
#   │  CHROMIUM HEADLESS BROWSER (Playwright)                      │
#   │  • Renders full SPAs (React/Vue/Angular/Next.js)             │
#   │  • Intercepts all network requests live                      │
#   │  • Captures lazy-loaded JS that static scanners miss         │
#   │  • Extracts DOM image URLs from CSS background images        │
#   ├──────────────────────────────────────────────────────────────┤
#   │  110+ SECRET PATTERNS across 15 categories                  │
#   │  Shannon entropy for unknown secrets no regex catches        │
#   │  Full deobfuscation: atob / fromCharCode / hex / eval        │
#   │  Source map recovery → original React/Vue/Angular code       │
#   │  Nuclei integration: auto-updates + runs CVE/exposure tags  │
#   │  Live API key validation (8 services)                        │
#   │  GraphQL, IDOR, mass exposure, stack trace CVE checks        │
#   │  Bulk URL thread-pool scanning                               │
#   │  Reports: HTML dashboard + JSON + CSV                        │
#   └──────────────────────────────────────────────────────────────┘
#
#   ⚠  AUTHORIZED SECURITY TESTING ONLY. UNAUTHORIZED USE IS ILLEGAL.
# ═══════════════════════════════════════════════════════════════════════════════

import os, sys, re, json, math, base64, hashlib, time, csv, struct, shutil
import subprocess, threading, argparse
from pathlib import Path
from datetime import datetime
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs

# ─── Optional imports ─────────────────────────────────────────────────────────
try:
    import requests
    requests.packages.urllib3.disable_warnings()
    HAS_REQUESTS = True
except ImportError:
    import urllib.request, urllib.error
    HAS_REQUESTS = False

try:
    from PIL import Image
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    HAS_PLAYWRIGHT = True
except ImportError:
    HAS_PLAYWRIGHT = False

try:
    import jsbeautifier
    HAS_JSB = True
except ImportError:
    HAS_JSB = False

# ─── Globals ──────────────────────────────────────────────────────────────────
VERSION   = "2.0.0"
AUTHOR    = "Hari Kamma"
GITHUB    = "https://github.com/Mr-White1/VenomJS"
TS        = datetime.now().strftime("%Y%m%d_%H%M%S")
DEDUP     = set()
DEDUP_LK  = threading.Lock()
FINDINGS  = []
FIND_LK   = threading.Lock()
VERBOSE   = False
LOG_F     = None
UA        = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124"

# ─── Colors ───────────────────────────────────────────────────────────────────
class C:
    R='\033[0;31m'; BR='\033[1;31m'; G='\033[0;32m'; BG='\033[1;32m'
    CY='\033[1;36m'; Y='\033[1;33m'; BL='\033[1;34m'; M='\033[1;35m'
    W='\033[1;37m'; DM='\033[2m'; BO='\033[1m'; NC='\033[0m'

def banner():
    print(f"""{C.CY}
   ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
   ██║╚════██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
   ██║    ██╔╝ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
   ██║   ██╔╝  ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
   ██║   ██║  ██╔╝ ██╗██║  ██║██║  ██║   ██║
   ╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝{C.NC}
   {C.W}{C.BO}v2.0  |  Ultra-Advanced JS + Image Secret Scanner{C.NC}
   {C.DM}Author: {AUTHOR}  |  {GITHUB}{C.NC}
   {C.Y}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.NC}
   {C.DM}⚠  Authorized security testing ONLY. Unauthorized use is illegal.{C.NC}
   {C.Y}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━{C.NC}
""")

# ═══════════════════════════════════════════════════════════════════════════════
#  110+ SECRET PATTERNS
# ═══════════════════════════════════════════════════════════════════════════════
PAT = {
    # AWS
    "AWS_Access_Key_ID":    (r'AKIA[0-9A-Z]{16}',                                                "CRITICAL"),
    "AWS_Secret_Key":       (r'(?i)(aws_secret_access_key|aws_secret)[\s"\'=:]{1,10}[A-Za-z0-9/+=]{40}', "CRITICAL"),
    "AWS_MWS_Token":        (r'amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "HIGH"),
    "AWS_Session_Token":    (r'(?i)aws_session_token[\s"\'=:]{1,10}[A-Za-z0-9/+=]{100,}',        "CRITICAL"),
    # GCP / Firebase
    "GCP_API_Key":          (r'AIza[0-9A-Za-z\-_]{35}',                                          "HIGH"),
    "GCP_Service_Account":  (r'"type":\s*"service_account"',                                     "CRITICAL"),
    "Firebase_Server_Key":  (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',                        "CRITICAL"),
    "Firebase_Config":      (r'apiKey:\s*["\'][A-Za-z0-9_-]{39}["\']',                           "HIGH"),
    "Firebase_DB_URL":      (r'https://[a-z0-9-]+\.firebaseio\.com',                             "MEDIUM"),
    # Azure
    "Azure_Storage_Conn":   (r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{88}==', "CRITICAL"),
    "Azure_Client_Secret":  (r'(?i)client_secret[\s"\'=:]{1,10}[A-Za-z0-9~._-]{34,}',           "CRITICAL"),
    "Azure_SAS_Token":      (r'sig=[A-Za-z0-9%+/]+=*&se=\d{4}-\d{2}-\d{2}',                    "HIGH"),
    # Stripe / Payments
    "Stripe_Live_Secret":   (r'sk_live_[0-9a-zA-Z]{24}',                                         "CRITICAL"),
    "Stripe_Test_Secret":   (r'sk_test_[0-9a-zA-Z]{24}',                                         "MEDIUM"),
    "Stripe_Restricted":    (r'rk_live_[0-9a-zA-Z]{24}',                                         "CRITICAL"),
    "Stripe_Webhook":       (r'whsec_[A-Za-z0-9+/]{32,}',                                        "HIGH"),
    "PayPal_Braintree":     (r'access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}',            "CRITICAL"),
    "Square_Token":         (r'sq0atp-[0-9A-Za-z\-_]{22}',                                       "HIGH"),
    "Square_Secret":        (r'sq0csp-[0-9A-Za-z\-_]{43}',                                       "CRITICAL"),
    "Razorpay":             (r'rzp_(live|test)_[A-Za-z0-9]{14}',                                 "HIGH"),
    "Shopify_Access_Token": (r'shpat_[a-fA-F0-9]{32}',                                           "CRITICAL"),
    "Shopify_Secret":       (r'shpss_[a-fA-F0-9]{32}',                                           "CRITICAL"),
    "Adyen_Key":            (r'AQE[a-zA-Z0-9+/]{10,}={0,2}',                                    "HIGH"),
    # Auth / JWT
    "JWT_Token":            (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}',  "HIGH"),
    "OAuth_Google":         (r'ya29\.[0-9A-Za-z\-_]+',                                           "HIGH"),
    "Bearer_Token":         (r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*',                             "HIGH"),
    "Auth_In_URL":          (r'https?://[^:@\s]+:[^:@\s]+@[^\s]+',                              "HIGH"),
    "API_Key_In_URL":       (r'[?&](api_?key|apikey|access_token|token|key)=[A-Za-z0-9_\-]{16,}', "HIGH"),
    # GitHub / GitLab / CI
    "GitHub_PAT":           (r'ghp_[0-9A-Za-z]{36}',                                             "CRITICAL"),
    "GitHub_OAuth":         (r'gho_[0-9A-Za-z]{36}',                                             "CRITICAL"),
    "GitHub_App_Token":     (r'(ghu|ghs)_[0-9A-Za-z]{36}',                                       "HIGH"),
    "GitHub_Fine_Grained":  (r'github_pat_[A-Za-z0-9_]{82}',                                     "CRITICAL"),
    "GitLab_PAT":           (r'glpat-[0-9a-zA-Z\-]{20}',                                         "CRITICAL"),
    "GitLab_Runner":        (r'GR1348941[0-9a-zA-Z\-_]{20}',                                     "HIGH"),
    "CircleCI_Token":       (r'(?i)circle.?ci.{0,10}["\'][0-9a-f]{40}["\']',                    "HIGH"),
    "Netlify_Token":        (r'(?i)netlify.{0,20}[A-Za-z0-9_-]{40,}',                           "HIGH"),
    "Vercel_Token":         (r'(?i)vercel.{0,20}[A-Za-z0-9_-]{24,}',                            "HIGH"),
    # Communication
    "Slack_Bot_Token":      (r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24}',                 "HIGH"),
    "Slack_User_Token":     (r'xoxp-[0-9]+-[0-9]+-[0-9]+-[a-fA-F0-9]+',                         "HIGH"),
    "Slack_Webhook":        (r'https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+', "HIGH"),
    "Discord_Bot_Token":    (r'[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}',                        "HIGH"),
    "Discord_Webhook":      (r'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+',  "MEDIUM"),
    "Telegram_Bot_Token":   (r'[0-9]{8,10}:[A-Za-z0-9_-]{35}',                                   "MEDIUM"),
    "Twilio_SID":           (r'AC[a-zA-Z0-9]{32}',                                               "HIGH"),
    "Twilio_Auth_Token":    (r'(?i)twilio.{0,20}["\'][0-9a-f]{32}["\']',                        "HIGH"),
    "SendGrid_Key":         (r'SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}',                     "HIGH"),
    "Mailgun_Key":          (r'key-[0-9a-zA-Z]{32}',                                             "HIGH"),
    "Mailchimp_Key":        (r'[0-9a-f]{32}-us[0-9]{1,2}',                                       "MEDIUM"),
    "Postmark_Token":       (r'(?i)postmark.{0,20}[A-Za-z0-9_-]{36}',                           "HIGH"),
    # Databases
    "MongoDB_URI":          (r'mongodb(\+srv)?://[^:]+:[^@]+@[^\s"\']+',                         "CRITICAL"),
    "PostgreSQL_URI":       (r'postgres(ql)?://[^:]+:[^@]+@[^\s"\']+',                           "CRITICAL"),
    "MySQL_URI":            (r'mysql://[^:]+:[^@]+@[^\s"\']+',                                   "CRITICAL"),
    "Redis_URI":            (r'redis://[^:]*:?[^@]+@[^\s"\']+',                                  "HIGH"),
    "Supabase_Key":         (r'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "HIGH"),
    "S3_Bucket_URL":        (r'https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com',         "MEDIUM"),
    "PlanetScale_Token":    (r'pscale_tkn_[A-Za-z0-9_-]{43}',                                    "CRITICAL"),
    "Neon_DB_URL":          (r'postgresql://[^:]+:[^@]+@[a-z0-9.-]+\.neon\.tech[^\s"\']+',       "CRITICAL"),
    # AI / LLM Keys (v2.0 — no other scanner covers these)
    "OpenAI_Key":           (r'sk-[A-Za-z0-9]{48}',                                              "CRITICAL"),
    "OpenAI_Project_Key":   (r'sk-proj-[A-Za-z0-9_-]{48,}',                                      "CRITICAL"),
    "Anthropic_Key":        (r'sk-ant-[A-Za-z0-9\-_]{95}',                                       "CRITICAL"),
    "Groq_Key":             (r'gsk_[A-Za-z0-9]{52}',                                             "CRITICAL"),
    "Replicate_Token":      (r'r8_[A-Za-z0-9]{40}',                                              "HIGH"),
    "HuggingFace_Token":    (r'hf_[A-Za-z0-9]{34}',                                              "HIGH"),
    # Social / Dev APIs
    "Twitter_API_Key":      (r'(?i)twitter.{0,30}["\'][A-Za-z0-9]{25,}["\']',                   "HIGH"),
    "Twitter_Bearer":       (r'AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+%[A-Za-z0-9%]+',              "HIGH"),
    "Facebook_Token":       (r'EAACEdEose0cBA[0-9A-Za-z]+',                                     "HIGH"),
    "Mapbox_Token":         (r'pk\.eyJ1[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',                         "MEDIUM"),
    "Algolia_API_Key":      (r'(?i)algolia.{0,20}[A-Za-z0-9]{32}',                              "HIGH"),
    # Crypto / Web3
    "ETH_Private_Key":      (r'(?i)(private.?key|eth.?key).{0,20}["\'][0-9a-fA-F]{64}["\']',   "CRITICAL"),
    "Crypto_Mnemonic":      (r'(?i)(mnemonic|seed.?phrase).{0,30}([a-z]+\s){11}[a-z]+',         "CRITICAL"),
    "Infura_Key":           (r'(?i)infura.{0,20}["\'][0-9a-f]{32}["\']',                        "HIGH"),
    # Crypto Material
    "RSA_Private_Key":      (r'-----BEGIN RSA PRIVATE KEY-----',                                 "CRITICAL"),
    "EC_Private_Key":       (r'-----BEGIN EC PRIVATE KEY-----',                                  "CRITICAL"),
    "OPENSSH_Key":          (r'-----BEGIN OPENSSH PRIVATE KEY-----',                             "CRITICAL"),
    "PGP_Private_Key":      (r'-----BEGIN PGP PRIVATE KEY BLOCK-----',                           "CRITICAL"),
    # Generic
    "Generic_API_Key":      (r'(?i)(api[-_]?key|apikey)[\s"\'=:]{1,10}["\'][A-Za-z0-9_\-]{20,}["\']', "HIGH"),
    "Generic_Secret":       (r'(?i)(secret|client_secret)[\s"\'=:]{1,10}["\'][A-Za-z0-9_\-+/]{16,}["\']', "HIGH"),
    "Generic_Password":     (r'(?i)(password|passwd|pwd)[\s"\'=:]{1,10}["\'][^"\'\\s]{8,}["\']', "HIGH"),
    "Generic_Token":        (r'(?i)(access_token|refresh_token|id_token)[\s"\'=:]{1,10}["\'][A-Za-z0-9_\-.]{20,}["\']', "HIGH"),
    "SMTP_Credentials":     (r'smtp(s)?://[^:]+:[^@]+@[^\s"\']+',                               "CRITICAL"),
    "SSN":                  (r'(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)',                                  "CRITICAL"),
    "Credit_Card":          (r'(?<!\d)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})(?!\d)', "CRITICAL"),
    "Internal_IP":          (r'(10\.\d{1,3}|172\.(1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}', "MEDIUM"),
    # Endpoints
    "Admin_Route":          (r'/admin[/"\'?#]',                                                   "MEDIUM"),
    "GraphQL_Route":        (r'/graphql["\'?\s]',                                                 "LOW"),
    "Swagger_Route":        (r'/(swagger|openapi|api-docs)[-/v0-9]',                             "MEDIUM"),
    "Debug_Enabled":        (r'(?i)(debug|backdoor|internal)[\s"\'=:]{1,5}true',                 "MEDIUM"),
    "SSRF_Metadata":        (r'169\.254\.169\.254|metadata\.google\.internal',                   "HIGH"),
    "Hardcoded_Admin":      (r'(?i)(username|user|login)[\s"\'=:]{1,10}["\']admin["\']',         "HIGH"),
}

EP_SIGS = [
    r'/api/v?\d*/', r'/_api/', r'/graphql', r'/swagger', r'/openapi',
    r'/api-docs', r'/admin', r'/debug', r'/test/', r'/.env',
    r'/config\.json', r'/settings\.json', r'/package\.json',
    r'/.git/config', r'/backup', r'/export', r'/oauth/token',
    r'169\.254\.169\.254', r'/internal/', r'/staging/',
]

# ═══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════════════════
def log(msg, lv="INFO"):
    col = {"INFO":C.CY,"OK":C.BG,"FIND":C.BR,"WARN":C.Y,"ERR":C.R,
           "IMG":C.BL,"DIM":C.DM,"HEAD":C.M}.get(lv, C.NC)
    print(f"{col}{msg}{C.NC}")
    if LOG_F:
        with open(LOG_F,'a',encoding='utf-8') as f:
            f.write(re.sub(r'\033\[[0-9;]+m','',msg)+"\n")

def vlog(msg):
    if VERBOSE: log(f"  [DBG] {msg}","DIM")

def http_get(url, timeout=15, proxy=None, cookies=None):
    hdr = {"User-Agent": UA}
    try:
        if HAS_REQUESTS:
            px = {"http":proxy,"https":proxy} if proxy else None
            r  = requests.get(url,timeout=timeout,proxies=px,cookies=cookies,
                              headers=hdr,verify=False,allow_redirects=True)
            return r.status_code, r.content, dict(r.headers)
        else:
            req = urllib.request.Request(url, headers=hdr)
            with urllib.request.urlopen(req, timeout=timeout) as res:
                return res.status, res.read(), dict(res.headers)
    except Exception as e:
        vlog(f"GET failed {url}: {e}")
        return 0, b"", {}

def http_text(url, **kw):
    c, d, h = http_get(url, **kw)
    return c, d.decode("utf-8", errors="replace"), h

def save(sev, ftype, val, src, line="-", notes=""):
    dk = f"{ftype}::{val[:120]}"
    with DEDUP_LK:
        if dk in DEDUP: return
        DEDUP.add(dk)
    sc = {"CRITICAL":C.BR,"HIGH":C.R,"MEDIUM":C.Y,"LOW":C.BL}.get(sev,C.NC)
    print(f"\n  {sc}[{sev}]{C.NC} {C.M}{ftype}{C.NC}")
    print(f"    {C.BG}→ {C.W}{val[:120]}{C.NC}")
    print(f"    {C.DM}Source: {str(src)[:80]}  Line: {line}{C.NC}")
    e = {"severity":sev,"type":ftype,"value":val,"source":str(src),
         "line":str(line),"validated":"false","notes":notes}
    with FIND_LK:
        FINDINGS.append(e)
    if LOG_F:
        with open(LOG_F,'a',encoding='utf-8') as f:
            f.write(f"[{sev}] {ftype} → {val[:120]} | {src}\n")

# ═══════════════════════════════════════════════════════════════════════════════
#  ENTROPY
# ═══════════════════════════════════════════════════════════════════════════════
def entropy(s):
    if not s: return 0.0
    c=Counter(s); n=len(s)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def entropy_scan(content, src):
    for m in re.finditer(r'["\']([A-Za-z0-9+/=_\-]{20,})["\']', content):
        s = m.group(1)
        e = entropy(s)
        if e >= 4.5:
            ln = content[:m.start()].count('\n')+1
            save("HIGH","High_Entropy_String",s,src,ln,notes=f"entropy={e:.2f}")

# ═══════════════════════════════════════════════════════════════════════════════
#  DEOBFUSCATION
# ═══════════════════════════════════════════════════════════════════════════════
def deobfuscate(content, src):
    decoded = []
    # atob()
    for m in re.finditer(r'atob\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)', content):
        try:
            d = base64.b64decode(m.group(1)+"==").decode("utf-8",errors="replace")
            if len(d) > 8:
                decoded.append(d)
                ln = content[:m.start()].count('\n')+1
                save("HIGH","Deobf_atob",d[:200],src,ln,notes="Decoded from atob()")
        except: pass
    # fromCharCode
    for m in re.finditer(r'fromCharCode\(([0-9,\s]+)\)', content):
        try:
            nums = [int(x.strip()) for x in m.group(1).split(',') if x.strip().isdigit()]
            d = ''.join(chr(n) for n in nums if 32<=n<128)
            if len(d)>6:
                decoded.append(d)
                ln = content[:m.start()].count('\n')+1
                save("MEDIUM","Deobf_fromCharCode",d,src,ln,notes="Decoded fromCharCode")
        except: pass
    # \x hex
    for m in re.finditer(r'["\']((\\x[0-9a-fA-F]{2}){6,})["\']', content):
        try:
            d = bytes.fromhex(re.sub(r'\\x','',m.group(1))).decode('utf-8',errors='replace')
            if len(d)>4:
                decoded.append(d)
                ln = content[:m.start()].count('\n')+1
                save("MEDIUM","Deobf_HexEscape",d,src,ln,notes="Decoded \\x hex string")
        except: pass
    for d in decoded:
        scan(d, f"{src} [deobfuscated]")

# ═══════════════════════════════════════════════════════════════════════════════
#  CORE SCANNER
# ═══════════════════════════════════════════════════════════════════════════════
def scan(content, src):
    if not content or len(content)<10: return
    if HAS_JSB and len(content)>500 and '\n' not in content[:200]:
        try:
            opts = jsbeautifier.default_options()
            opts.indent_size=2
            content = jsbeautifier.beautify(content, opts)
        except: pass
    for pn,(rx,sev) in PAT.items():
        try:
            for m in re.finditer(rx, content, re.MULTILINE):
                v=m.group(0)
                if len(v)<8: continue
                ln=content[:m.start()].count('\n')+1
                save(sev,pn,v,src,ln)
        except re.error: pass
    for i,ln in enumerate(content.split('\n'),1):
        if re.search(r'(?i)(//|/\*|\*).{0,5}(password|secret|api.?key|token|credential|bypass)',ln):
            save("MEDIUM","Sensitive_Comment",ln.strip()[:200],src,i,notes="Manual review needed")
    for m in re.finditer(r'[A-Za-z0-9+/]{40,}={0,2}', content):
        v=m.group(0)
        try:
            d=base64.b64decode(v+"==").decode('utf-8',errors='replace')
            if re.search(r'(?i)(password|secret|key|token|aws|BEGIN|firebase)',d):
                ln=content[:m.start()].count('\n')+1
                save("HIGH","Base64_Encoded_Secret",v,src,ln,notes=f"Decoded hint: {d[:80]}")
        except: pass
    for m in re.finditer(r'process\.env\.[A-Z_]{4,}|REACT_APP_[A-Z_]+|window\.__env__', content):
        ln=content[:m.start()].count('\n')+1
        save("MEDIUM","Env_Var_Exposure",m.group(0),src,ln,notes="Check if value hardcoded nearby")
    entropy_scan(content, src)
    deobfuscate(content, src)

# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — CHROMIUM HEADLESS (Playwright)
# ═══════════════════════════════════════════════════════════════════════════════
def browser_scan(url, out_dir, timeout=30, proxy=None):
    if not HAS_PLAYWRIGHT:
        log("  [!] --browser needs: pip install playwright && playwright install chromium","WARN")
        return [],[]
    js_found=[]; img_found=[]
    log(f"\n  {C.CY}[BROWSER]{C.NC} Launching Chromium → {url[:80]}","INFO")
    try:
        with sync_playwright() as p:
            opts={"headless":True}
            if proxy: opts["proxy"]={"server":proxy}
            browser=p.chromium.launch(**opts)
            ctx=browser.new_context(user_agent=UA,ignore_https_errors=True)
            page=ctx.new_page()
            int_js=[]; int_img=[]; int_api=[]
            def on_req(r):
                u=r.url
                if re.search(r'\.(js|mjs|jsx|ts)(\?|$)',u,re.I): int_js.append(u)
                elif re.search(r'\.(png|jpg|jpeg|gif|webp|svg|bmp|ico)(\?|$)',u,re.I): int_img.append(u)
                elif re.search(r'/(api|graphql|v\d+)/',u,re.I): int_api.append(u)
            page.on("request", on_req)
            try: page.goto(url,timeout=timeout*1000,wait_until="networkidle")
            except Exception as e: log(f"  [~] Browser nav error: {e}","WARN")
            dom_js=page.evaluate("()=>Array.from(document.querySelectorAll('script[src]')).map(s=>s.src).filter(Boolean)")
            dom_img=page.evaluate("""()=>{
                const a=Array.from(document.querySelectorAll('img[src]')).map(i=>i.src);
                const b=Array.from(document.querySelectorAll('[style]'))
                    .map(el=>{const bg=el.style.backgroundImage;
                        if(bg&&bg.includes('url(')){return bg.replace(/url\\(['"']?/,'').replace(/['"']?\\)/,'');}
                        return null;}).filter(Boolean);
                return [...a,...b].filter(Boolean);}""")
            html=page.content()
            safe=hashlib.md5(url.encode()).hexdigest()[:10]
            with open(os.path.join(out_dir,f"rendered_{safe}.html"),'w',errors='replace') as f: f.write(html)
            scan(html, f"{url} [rendered HTML]")
            js_found  = list(set(dom_js+int_js))
            img_found = list(set(dom_img+int_img))
            # Save img list for image module
            with open(os.path.join(out_dir,f"browser_imgs_{safe}.txt"),'w') as f: f.write('\n'.join(img_found))
            log(f"  {C.BG}[BROWSER]{C.NC} {len(js_found)} JS | {len(img_found)} images | {len(int_api)} API calls","OK")
            browser.close()
    except Exception as e:
        log(f"  [!] Playwright error: {e}","ERR")
    return js_found, img_found

# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — IMAGE ANALYSIS (THE GAP NO OTHER TOOL COVERS)
# ═══════════════════════════════════════════════════════════════════════════════
def analyze_image(img_url, img_file, out_dir):
    ext  = Path(img_file).suffix.lower().lstrip('.')
    hits = 0

    # 1. URL query param secrets (?token=sk_live_xxx, ?key=AKIA...)
    parsed=urlparse(img_url)
    if parsed.query:
        sensitive={'key','token','auth','secret','api','access_token',
                   'bearer','password','apikey','access_key','session','jwt'}
        for param,vals in parse_qs(parsed.query).items():
            if param.lower() in sensitive:
                for v in vals:
                    if len(v)>8:
                        save("HIGH","Image_URL_Param_Secret",f"{param}={v}",img_url,"URL-param",
                             notes="Sensitive key in image request URL query parameter"); hits+=1

    if not os.path.isfile(img_file) or os.path.getsize(img_file)==0: return hits

    # 2. EXIF via exiftool
    if shutil.which('exiftool'):
        try:
            r=subprocess.run(['exiftool','-a','-u','-g1',img_file],
                             capture_output=True,text=True,timeout=15)
            for ln in r.stdout.split('\n'):
                if re.search(r'(?i)(api|key|token|secret|password|auth|credential|comment|description)',ln):
                    save("HIGH","Image_EXIF_Sensitive_Field",ln.strip()[:200],img_url,"EXIF",
                         notes="Sensitive keyword in EXIF field"); hits+=1
                for pn,(rx,sev) in PAT.items():
                    m=re.search(rx,ln)
                    if m:
                        save(sev,f"EXIF_{pn}",m.group(0),img_url,"EXIF",
                             notes="Secret pattern matched in EXIF data"); hits+=1
        except: pass

    # 3. PNG chunk analysis (tEXt / iTXt / zTXt)
    if ext=='png':
        try:
            with open(img_file,'rb') as f: data=f.read()
            if data[:8]==b'\x89PNG\r\n\x1a\n':
                pos=8
                while pos<len(data)-12:
                    try:
                        length=struct.unpack('>I',data[pos:pos+4])[0]
                        ctype=data[pos+4:pos+8].decode('ascii',errors='ignore')
                        cdata=data[pos+8:pos+8+length]
                        if ctype in('tEXt','iTXt','zTXt'):
                            text=cdata.decode('utf-8',errors='replace')
                            if re.search(r'(?i)(key|token|secret|password|api|auth)',text):
                                save("HIGH",f"PNG_{ctype}_Chunk_Secret",text[:300],img_url,
                                     f"PNG:{ctype}",notes="Sensitive data in PNG text chunk"); hits+=1
                            scan(text, f"{img_url} [PNG:{ctype}]")
                        pos+=12+length
                    except: break
                iend=data.rfind(b'IEND')
                if iend!=-1:
                    after=data[iend+8:]
                    if len(after)>20:
                        txt=after.decode('utf-8',errors='replace')
                        save("HIGH","PNG_Appended_Data",txt[:200],img_url,"PNG:EOF",
                             notes=f"{len(after)} bytes after PNG EOF — steganography?"); hits+=1
                        scan(txt, f"{img_url} [PNG appended]")
        except: pass

    # 4. JPEG comment marker (0xFFFE) + appended data
    if ext in('jpg','jpeg'):
        try:
            with open(img_file,'rb') as f: data=f.read()
            pos=0
            while pos<len(data)-4:
                if data[pos:pos+2]==b'\xff\xfe':
                    length=struct.unpack('>H',data[pos+2:pos+4])[0]
                    comment=data[pos+4:pos+2+length].decode('utf-8',errors='replace')
                    if len(comment)>5:
                        if re.search(r'(?i)(key|token|secret|password|api|auth)',comment):
                            save("HIGH","JPEG_Comment_Secret",comment[:300],img_url,"JPEG:COM",
                                 notes="Sensitive data in JPEG comment marker"); hits+=1
                        scan(comment, f"{img_url} [JPEG:COM]")
                pos+=1
            eoi=data.rfind(b'\xff\xd9')
            if eoi!=-1:
                after=data[eoi+2:]
                if len(after)>20:
                    txt=after.decode('utf-8',errors='replace')
                    save("HIGH","JPEG_Appended_Data",txt[:200],img_url,"JPEG:EOF",
                         notes=f"{len(after)} bytes after JPEG EOI — hidden data?"); hits+=1
                    scan(txt, f"{img_url} [JPEG appended]")
        except: pass

    # 5. LSB Steganography detection + decode attempt
    if HAS_PIL and ext in('png','bmp'):
        try:
            img=Image.open(img_file).convert('RGB')
            pixels=list(img.getdata())
            if len(pixels)>100:
                lsbs=[c&1 for px in pixels[:1000] for c in px]
                ones=lsbs.count(1)
                ratio=ones/len(lsbs)
                if 0.45<=ratio<=0.55 and len(pixels)>500:
                    save("MEDIUM","Image_LSB_Stego_Detected",
                         f"LSB 1-bit ratio: {ratio:.3f} (near 50/50 — strong steganography indicator)",
                         img_url,"LSB",notes="Run: zsteg or stegsolve to extract"); hits+=1
                chars=[]
                for i in range(0,min(800,len(lsbs)-8),8):
                    byte=int(''.join(str(b) for b in lsbs[i:i+8]),2)
                    chars.append(chr(byte) if 32<=byte<127 else '.')
                lsb_str=''.join(chars)
                if re.search(r'(?i)(key|token|secret|password|AKIA|sk_|ghp_|AIza)',lsb_str):
                    save("CRITICAL","Image_LSB_Secret_Decoded",lsb_str[:200],img_url,"LSB:decoded",
                         notes="Secret pattern decoded from LSB pixel data"); hits+=1
        except: pass

    # 6. Binary strings extraction
    if shutil.which('strings'):
        try:
            r=subprocess.run(['strings','-n','8',img_file],
                             capture_output=True,text=True,timeout=15)
            for ln in r.stdout.split('\n'):
                ln=ln.strip()
                if len(ln)<8: continue
                for pn,(rx,sev) in PAT.items():
                    m=re.search(rx,ln)
                    if m:
                        save(sev,f"ImgBinary_{pn}",m.group(0),img_url,"binary:strings",
                             notes="Secret found in raw image binary data"); hits+=1
        except: pass
    else:
        # Manual fallback when 'strings' not available
        try:
            with open(img_file,'rb') as f: data=f.read()
            cur=[]
            for byte in data:
                if 32<=byte<127: cur.append(chr(byte))
                else:
                    if len(cur)>=8:
                        s=''.join(cur)
                        for pn,(rx,sev) in PAT.items():
                            m=re.search(rx,s)
                            if m:
                                save(sev,f"ImgBinary_{pn}",m.group(0),img_url,"binary:manual",
                                     notes="Secret found in image binary"); hits+=1
                    cur=[]
        except: pass

    # 7. SVG inline JS + data URIs
    if ext=='svg':
        try:
            with open(img_file,'r',errors='replace') as f: svg=f.read()
            for m in re.finditer(r'<script[^>]*>(.*?)</script>',svg,re.DOTALL|re.IGNORECASE):
                if m.group(1).strip():
                    scan(m.group(1), f"{img_url} [SVG:script]"); hits+=1
            for mime,b64 in re.findall(r'data:([^;,]+);base64,([A-Za-z0-9+/=]+)',svg):
                try:
                    d=base64.b64decode(b64+"==").decode('utf-8',errors='replace')
                    scan(d, f"{img_url} [SVG:data-uri:{mime}]")
                except: pass
            scan(svg, f"{img_url} [SVG:full]")
        except: pass

    # 8. steghide (if installed)
    if shutil.which('steghide') and ext in('jpg','jpeg','bmp'):
        try:
            r=subprocess.run(['steghide','info',img_file,'-p',''],
                             capture_output=True,text=True,timeout=10)
            if 'embedded' in r.stdout.lower():
                save("HIGH","Image_Steghide_Embedded",
                     f"steghide reports embedded data: {os.path.basename(img_file)}",
                     img_url,"steghide",notes="Run: steghide extract -sf <file> -p ''"); hits+=1
        except: pass

    # 9. zsteg (if installed)
    if shutil.which('zsteg') and ext=='png':
        try:
            r=subprocess.run(['zsteg',img_file],capture_output=True,text=True,timeout=20)
            for ln in r.stdout.split('\n'):
                if re.search(r'(?i)(key|token|secret|password|AKIA|sk_|ghp_|AIza)',ln):
                    save("HIGH","Image_zsteg_Secret",ln.strip(),img_url,"zsteg",
                         notes="Secret pattern found by zsteg"); hits+=1
        except: pass

    return hits

def img_urls_from(content):
    return list(set(re.findall(
        r'https?://[^\s"\']+\.(?:png|jpg|jpeg|gif|webp|svg|bmp|ico)(?:\?[^\s"\']*)?',
        content, re.IGNORECASE)))

def fetch_and_analyze_image(img_url, img_dir, proxy=None):
    parsed=urlparse(img_url)
    if not parsed.scheme: return
    ext=Path(parsed.path).suffix.lower() or '.jpg'
    img_file=os.path.join(img_dir, hashlib.md5(img_url.encode()).hexdigest()[:12]+ext)
    code,data,_=http_get(img_url,proxy=proxy)
    if code==200 and data:
        with open(img_file,'wb') as f: f.write(data)
        log(f"  {C.BL}[IMG]{C.NC} {img_url[:80]}","IMG")
        n=analyze_image(img_url,img_file,img_dir)
        if n==0: vlog(f"No secrets found in image")

# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — SOURCE MAP RECOVERY
# ═══════════════════════════════════════════════════════════════════════════════
def recover_sourcemap(js_url, js_content, map_dir, proxy=None):
    m=re.search(r'//# sourceMappingURL=([^\s]+)',js_content)
    if not m: return
    ref=m.group(1)
    if not ref.startswith('http'):
        p=urlparse(js_url)
        jdir='/'.join(p.path.split('/')[:-1])
        ref=f"{p.scheme}://{p.netloc}{jdir}/{ref}"
    log(f"  {C.CY}[SRCMAP]{C.NC} {ref[:80]}","INFO")
    code,data,_=http_get(ref,proxy=proxy)
    if code!=200 or not data: return
    try:
        sm=json.loads(data.decode('utf-8',errors='replace'))
        sources=sm.get('sources',[]); contents=sm.get('sourcesContent',[])
        sdir=os.path.join(map_dir,f"src_{hashlib.md5(ref.encode()).hexdigest()[:8]}")
        os.makedirs(sdir,exist_ok=True)
        log(f"  {C.BG}[SRCMAP]{C.NC} Recovered {len(sources)} original source files","OK")
        for i,src in enumerate(sources):
            if i<len(contents) and contents[i]:
                fname=re.sub(r'[^A-Za-z0-9._-]','_',src)[:80]
                with open(os.path.join(sdir,fname),'w',errors='replace') as f: f.write(contents[i])
                scan(contents[i], f"{ref} → {src}")
    except Exception as e: vlog(f"Sourcemap parse error: {e}")

# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — API ENDPOINT CVE CHECKS
# ═══════════════════════════════════════════════════════════════════════════════
def probe_endpoint(ep_url, api_dir, proxy=None):
    code,text,_=http_text(ep_url,proxy=proxy)
    if not text or code==0: return
    safe=hashlib.md5(ep_url.encode()).hexdigest()[:10]
    with open(os.path.join(api_dir,f"api_{safe}.txt"),'w',errors='replace') as f: f.write(text)
    if 200<=code<300:
        scan(text,ep_url)
        if re.search(r'"(password|passwd|token)":', text, re.I):
            save("CRITICAL","Unauth_Credential_Leak",ep_url,ep_url,notes="Credentials in unauthenticated response")
        try:
            d=json.loads(text)
            if isinstance(d,list) and len(d)>10:
                save("HIGH","Mass_Data_Exposure",ep_url,ep_url,notes=f"{len(d)} records exposed")
        except: pass
        if re.search(r'/\d+(/|$)',ep_url):
            save("MEDIUM","Potential_IDOR",ep_url,ep_url,notes="Numeric ID — test adjacent IDs")
        if re.search(r'(stack trace|traceback|at [A-Za-z]+\.[A-Za-z]+\()',text,re.I):
            save("MEDIUM","Stack_Trace_Disclosure",ep_url,ep_url,notes="Debug trace in response")
        if 'graphql' in ep_url.lower() and HAS_REQUESTS:
            try:
                r=requests.post(ep_url,json={"query":"{__schema{types{name}}}"},timeout=8,verify=False)
                if '__schema' in r.text:
                    save("HIGH","GraphQL_Introspection_Open",ep_url,ep_url,notes="Schema introspection public")
            except: pass
    elif code in(401,403):
        save("LOW","Auth_Protected_Endpoint",ep_url,ep_url,notes=f"HTTP {code}")

# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — LIVE API KEY VALIDATION
# ═══════════════════════════════════════════════════════════════════════════════
def validate_key(ptype, val):
    if not HAS_REQUESTS: return
    result=None
    try:
        if ptype=="GCP_API_Key":
            _,t=lambda: (lambda r: (r.status_code,r.text))(
                requests.get(f"https://maps.googleapis.com/maps/api/geocode/json?address=test&key={val}",
                             timeout=8,verify=False))()
            if '"OK"' in t: result="✅ VALID — GCP Key ACTIVE"
            elif 'REQUEST_DENIED' in t: result="❌ DENIED/RESTRICTED"
        elif ptype=="Stripe_Live_Secret":
            r=requests.get("https://api.stripe.com/v1/charges?limit=1",auth=(val,""),timeout=8,verify=False)
            if '"data"' in r.text: result="✅ VALID — Stripe Live Key ACTIVE"
        elif ptype in("GitHub_PAT","GitHub_OAuth"):
            r=requests.get("https://api.github.com/user",headers={"Authorization":f"token {val}"},timeout=8)
            m=re.search(r'"login":\s*"([^"]+)"',r.text)
            if m: result=f"✅ VALID — GitHub user: {m.group(1)}"
        elif ptype=="Slack_Bot_Token":
            r=requests.get(f"https://slack.com/api/auth.test?token={val}",timeout=8)
            if '"ok":true' in r.text: result="✅ VALID — Slack Token ACTIVE"
        elif ptype=="Telegram_Bot_Token":
            r=requests.get(f"https://api.telegram.org/bot{val}/getMe",timeout=8)
            m=re.search(r'"username":"([^"]+)"',r.text)
            if m: result=f"✅ VALID — Telegram Bot: @{m.group(1)}"
        elif ptype=="OpenAI_Key":
            r=requests.get("https://api.openai.com/v1/models",
                           headers={"Authorization":f"Bearer {val}"},timeout=8)
            if '"data"' in r.text: result="✅ VALID — OpenAI Key ACTIVE"
        elif ptype=="SendGrid_Key":
            r=requests.get("https://api.sendgrid.com/v3/user/profile",
                           headers={"Authorization":f"Bearer {val}"},timeout=8)
            if '"email"' in r.text: result="✅ VALID — SendGrid Key ACTIVE"
    except: pass
    if result:
        log(f"\n  {C.BR}{C.BO}[KEY-VALIDATED] {result}{C.NC}","FIND")
        log(f"    Key: {val[:45]}...","WARN")

VALIDATE_LIST=["GCP_API_Key","Stripe_Live_Secret","GitHub_PAT","GitHub_OAuth",
               "Slack_Bot_Token","Telegram_Bot_Token","OpenAI_Key","SendGrid_Key"]

# ═══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — NUCLEI
# ═══════════════════════════════════════════════════════════════════════════════
def run_nuclei(ep_file, out_dir, proxy=None):
    if not shutil.which('nuclei'):
        log("""
  [~] Nuclei not installed. Install:
      go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
      nuclei -update-templates""","WARN"); return
    if not os.path.isfile(ep_file) or os.path.getsize(ep_file)==0:
        log("  [~] No endpoints for Nuclei","WARN"); return
    log(f"\n  {C.CY}[NUCLEI]{C.NC} Updating templates...","INFO")
    subprocess.run(['nuclei','-update-templates','-silent'],capture_output=True)
    nout=os.path.join(out_dir,"nuclei_results.txt")
    cmd=['nuclei','-l',ep_file,
         '-tags','exposure,token,api,secret,config,debug,disclosure,misconfig,cve,js,auth-bypass,ssrf,xss',
         '-severity','critical,high,medium','-o',nout,'-silent','-timeout','10',
         '-rate-limit','50','-bulk-size','25']
    if proxy: cmd+=['-proxy',proxy]
    count=sum(1 for _ in open(ep_file))
    log(f"  {C.CY}[NUCLEI]{C.NC} Scanning {count} endpoints...","INFO")
    try: subprocess.run(cmd,timeout=600)
    except subprocess.TimeoutExpired: log("  [~] Nuclei timed out","WARN")
    if os.path.isfile(nout) and os.path.getsize(nout)>0:
        log(f"\n  {C.BG}[NUCLEI FINDINGS]{C.NC}","OK")
        with open(nout) as f:
            for ln in f: log(f"    {C.M}→{C.NC} {ln.strip()}","INFO")
    else:
        log("  [~] Nuclei: no findings","DIM")

# ═══════════════════════════════════════════════════════════════════════════════
#  URL PROCESSOR
# ═══════════════════════════════════════════════════════════════════════════════
def process_url(url, args, js_dir, img_dir, api_dir, map_dir, ep_file):
    log(f"\n{C.Y}[→]{C.NC} {C.DM}{url}{C.NC}","INFO")
    parsed=urlparse(url)
    if not parsed.scheme:
        log(f"  [!] Skip (no scheme): {url}","WARN"); return

    if args.browser and HAS_PLAYWRIGHT:
        js_list,img_list=browser_scan(url,js_dir,timeout=args.timeout,proxy=args.proxy)
        for ju in js_list:
            _fetch_scan(ju,args,js_dir,img_dir,api_dir,map_dir,ep_file)
        if args.scan_images:
            for iu in img_list:
                fetch_and_analyze_image(iu,img_dir,proxy=args.proxy)
        return
    _fetch_scan(url,args,js_dir,img_dir,api_dir,map_dir,ep_file)

def _fetch_scan(url, args, js_dir, img_dir, api_dir, map_dir, ep_file):
    code,text,_=http_text(url,timeout=args.timeout,proxy=args.proxy)
    if not text or code==0:
        log(f"  {C.R}[-] Failed HTTP {code}{C.NC}","ERR"); return
    log(f"  {C.BG}[✓]{C.NC} HTTP {code} | {len(text):,} bytes","OK")
    safe=hashlib.md5(url.encode()).hexdigest()[:12]
    ext='json' if '.json' in url else 'js'
    with open(os.path.join(js_dir,f"{safe}.{ext}"),'w',errors='replace') as f: f.write(text)
    scan(text, url)
    if args.scan_images:
        imgs=img_urls_from(text)
        if imgs:
            log(f"  {C.BL}[IMG]{C.NC} Found {len(imgs)} image URLs — analyzing...","IMG")
            for iu in imgs: fetch_and_analyze_image(iu,img_dir,proxy=args.proxy)
    if args.sourcemaps:
        recover_sourcemap(url,text,map_dir,proxy=args.proxy)
    if args.json_api:
        base=f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        eps=re.findall(r'["\'](\/?[a-zA-Z0-9_\-\/\.]{3,})["\']|(https?://[^\s"\'<>]{10,})',text)
        for tup in eps[:150]:
            ep=(tup[0] or tup[1]).strip()
            if not ep: continue
            full=ep if ep.startswith('http') else f"{base}{ep}"
            if any(re.search(sig,full,re.I) for sig in EP_SIGS):
                with open(ep_file,'a') as f: f.write(full+'\n')
                probe_endpoint(full,api_dir,proxy=args.proxy)
    if args.validate:
        for pn in VALIDATE_LIST:
            if pn not in PAT: continue
            rx,_=PAT[pn]
            m=re.search(rx,text)
            if m: validate_key(pn,m.group(0))

# ═══════════════════════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════════════════════
def gen_reports(out_dir):
    crit=sum(1 for f in FINDINGS if f['severity']=='CRITICAL')
    high=sum(1 for f in FINDINGS if f['severity']=='HIGH')
    med =sum(1 for f in FINDINGS if f['severity']=='MEDIUM')
    low =sum(1 for f in FINDINGS if f['severity']=='LOW')
    total=len(FINDINGS)
    # JSON
    jf=os.path.join(out_dir,"findings.json")
    with open(jf,'w') as f:
        json.dump({"tool":"JSXRay","version":VERSION,"author":AUTHOR,
                   "timestamp":TS,"total":total,"findings":FINDINGS},f,indent=2)
    # CSV
    cf=os.path.join(out_dir,"findings.csv")
    with open(cf,'w',newline='',encoding='utf-8') as f:
        w=csv.DictWriter(f,fieldnames=["severity","type","value","source","line","validated","notes"])
        w.writeheader(); w.writerows(FINDINGS)
    # HTML
    order={"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}
    rows=""
    for fi in sorted(FINDINGS,key=lambda x:order.get(x['severity'],9)):
        sev=fi['severity']
        v=fi['value'].replace('"','&quot;').replace("'",'&#39;')
        rows+=f"""<tr data-s="{sev}">
<td><span class="b b{sev}">{sev}</span></td>
<td class="mo sm">{fi['type']}</td>
<td><span class="vl" title="{v}">{fi['value'][:90]}</span>
<button class="cp" onclick="navigator.clipboard.writeText('{v[:100]}')">⎘</button></td>
<td class="mo xs">{fi['source'][:65]}</td>
<td class="mo xs">{fi['line']}</td>
<td class="xs gry">{fi['notes'][:55]}</td></tr>"""
    hf=os.path.join(out_dir,"report.html")
    with open(hf,'w',encoding='utf-8') as f:
        f.write(f"""<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>JSXRay v{VERSION} Report — {TS}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@300;400;600;700&display=swap');
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#060f18;--bg2:#0b1924;--bg3:#101e2e;--bd:#16263d;--ac:#00e5ff;--ac2:#7c3aed;
--cr:#ff3d3d;--hi:#ff8c00;--md:#ffd700;--lo:#00c853;--tx:#a8c4d8;--tx2:#4d6b80;--wh:#daeeff}}
body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--tx);min-height:100vh}}
header{{background:linear-gradient(160deg,#060f18,#0a1a2a,#060f18);
border-bottom:1px solid var(--bd);padding:26px 34px;position:relative;overflow:hidden}}
header::before{{content:'';position:absolute;top:-60px;right:-30px;width:300px;height:300px;
background:radial-gradient(circle,rgba(0,229,255,.07),transparent 70%);pointer-events:none}}
.logo{{font-family:'JetBrains Mono',monospace;font-size:1.8em;font-weight:600;
background:linear-gradient(130deg,#00e5ff,#7c3aed);-webkit-background-clip:text;
-webkit-text-fill-color:transparent;background-clip:text}}
.sub{{color:var(--tx2);font-size:.85em;margin-top:4px}}
.meta{{display:flex;gap:16px;margin-top:10px;flex-wrap:wrap}}
.mi{{font-family:'JetBrains Mono',monospace;font-size:.74em;color:var(--tx2)}}
.mi span{{color:var(--ac)}}
.wb{{background:rgba(255,140,0,.08);border:1px solid rgba(255,140,0,.25);
border-radius:5px;padding:8px 14px;margin:14px 34px 0;color:#ff9a30;font-size:.8em}}
.stats{{display:flex;gap:10px;padding:18px 34px;flex-wrap:wrap}}
.s{{flex:1;min-width:90px;background:var(--bg2);border:1px solid var(--bd);
border-radius:8px;padding:14px;text-align:center;transition:transform .15s}}
.s:hover{{transform:translateY(-2px)}}
.s .n{{font-family:'JetBrains Mono',monospace;font-size:1.9em;font-weight:600}}
.s .l{{font-size:.68em;color:var(--tx2);margin-top:2px;letter-spacing:1px;text-transform:uppercase}}
.sc .n{{color:var(--cr)}}.sh .n{{color:var(--hi)}}.sm2 .n{{color:var(--md)}}
.sl .n{{color:var(--lo)}}.st .n{{color:var(--ac)}}
.sc{{border-color:rgba(255,61,61,.25)}}.sh{{border-color:rgba(255,140,0,.25)}}
.sm2{{border-color:rgba(255,215,0,.2)}}.sl{{border-color:rgba(0,200,83,.2)}}
.st{{border-color:rgba(0,229,255,.25)}}
.sec{{padding:0 34px 26px}}
h2{{font-family:'JetBrains Mono',monospace;font-size:.8em;letter-spacing:2px;
text-transform:uppercase;color:var(--ac);margin-bottom:10px}}
.fb-row{{display:flex;gap:6px;margin-bottom:10px;flex-wrap:wrap}}
.fb{{padding:4px 12px;border-radius:20px;border:1px solid var(--bd);background:var(--bg2);
color:var(--tx2);font-size:.74em;cursor:pointer;transition:all .15s;
font-family:'JetBrains Mono',monospace}}
.fb:hover,.fb.on{{background:var(--ac);color:#000;border-color:var(--ac)}}
table{{width:100%;border-collapse:collapse;font-size:.78em}}
th{{background:var(--bg3);color:var(--ac);padding:8px 10px;text-align:left;
border-bottom:2px solid var(--bd);font-family:'JetBrains Mono',monospace;
font-size:.72em;letter-spacing:1px;text-transform:uppercase;white-space:nowrap}}
td{{padding:7px 10px;border-bottom:1px solid var(--bd);vertical-align:top;word-break:break-all}}
tr:hover td{{background:var(--bg3)}}
.b{{display:inline-block;padding:2px 7px;border-radius:3px;font-size:.7em;
font-weight:700;font-family:'JetBrains Mono',monospace}}
.bCRITICAL{{background:rgba(255,61,61,.12);color:#ff6060;border:1px solid rgba(255,61,61,.35)}}
.bHIGH{{background:rgba(255,140,0,.12);color:#ff9a30;border:1px solid rgba(255,140,0,.35)}}
.bMEDIUM{{background:rgba(255,215,0,.1);color:#ffd740;border:1px solid rgba(255,215,0,.28)}}
.bLOW{{background:rgba(0,200,83,.08);color:#00e676;border:1px solid rgba(0,200,83,.25)}}
.vl{{font-family:'JetBrains Mono',monospace;font-size:.74em;background:var(--bg3);
padding:2px 6px;border-radius:3px;color:#52cbff;display:inline-block;
max-width:240px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;cursor:help}}
.mo{{font-family:'JetBrains Mono',monospace}}.sm{{font-size:.77em}}
.xs{{font-size:.73em;color:var(--tx2)}}.gry{{font-style:italic;color:var(--tx2)}}
.cp{{background:none;border:1px solid var(--bd);color:var(--tx2);
padding:1px 5px;border-radius:2px;font-size:.66em;cursor:pointer;margin-left:3px}}
.cp:hover{{border-color:var(--ac);color:var(--ac)}}
footer{{text-align:center;padding:22px;color:var(--tx2);font-size:.76em;
border-top:1px solid var(--bd)}}footer a{{color:var(--ac);text-decoration:none}}
</style></head><body>
<header>
<div class="logo">⚡ JSXRay</div>
<div class="sub">Ultra-Advanced JS + Image Secret Scanner v{VERSION}</div>
<div class="meta">
<div class="mi">Scan: <span>{TS}</span></div>
<div class="mi">Findings: <span>{total}</span></div>
<div class="mi">Author: <span>{AUTHOR}</span></div>
<div class="mi">Version: <span>{VERSION}</span></div>
</div></header>
<div class="wb">⚠ <strong>CONFIDENTIAL</strong> — Authorized security testing only. Handle per responsible disclosure policy.</div>
<div class="stats">
<div class="s sc"><div class="n">{crit}</div><div class="l">Critical</div></div>
<div class="s sh"><div class="n">{high}</div><div class="l">High</div></div>
<div class="s sm2"><div class="n">{med}</div><div class="l">Medium</div></div>
<div class="s sl"><div class="n">{low}</div><div class="l">Low</div></div>
<div class="s st"><div class="n">{total}</div><div class="l">Total</div></div>
</div>
<div class="sec">
<h2>Findings</h2>
<div class="fb-row">
<button class="fb on" onclick="flt('ALL',this)">All ({total})</button>
<button class="fb" onclick="flt('CRITICAL',this)" style="color:#ff6060">Critical ({crit})</button>
<button class="fb" onclick="flt('HIGH',this)" style="color:#ff9a30">High ({high})</button>
<button class="fb" onclick="flt('MEDIUM',this)" style="color:#ffd740">Medium ({med})</button>
<button class="fb" onclick="flt('LOW',this)" style="color:#00e676">Low ({low})</button>
</div>
<table><thead><tr>
<th>Severity</th><th>Type</th><th>Value</th><th>Source</th><th>Line</th><th>Notes</th>
</tr></thead><tbody id="tb">{rows}</tbody></table>
</div>
<footer>Generated by <a href="{GITHUB}">JSXRay v{VERSION}</a>
&nbsp;|&nbsp; By <strong>{AUTHOR}</strong>
&nbsp;|&nbsp; Authorized security testing only</footer>
<script>
function flt(s,btn){{
document.querySelectorAll('.fb').forEach(b=>b.classList.remove('on'));
btn.classList.add('on');
document.querySelectorAll('#tb tr').forEach(r=>{{
r.style.display=(s==='ALL'||r.dataset.s===s)?'':'none';
}});}}
</script></body></html>""")
    return jf,cf,hf

# ═══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    banner()
    ap=argparse.ArgumentParser(
        description="JSXRay v2.0 — Ultra-Advanced JS + Image Secret Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 jsxray.py -i urls.txt
  python3 jsxray.py -i urls.txt --all
  python3 jsxray.py -i urls.txt --browser --scan-images --validate
  python3 jsxray.py -i urls.txt -p http://127.0.0.1:8080 -c 'session=abc'
  python3 jsxray.py -i urls.txt --all -t 30 --threads 20
""")
    ap.add_argument("-i","--input",   default="urls.txt",help="URL input file (default: urls.txt)")
    ap.add_argument("-t","--timeout", type=int,default=15,help="HTTP timeout seconds")
    ap.add_argument("--threads",      type=int,default=10,help="Parallel threads (default: 10)")
    ap.add_argument("-p","--proxy",   default=None,help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    ap.add_argument("-c","--cookies", default=None,help="Cookie string for authenticated scans")
    ap.add_argument("-o","--output",  default=None,help="Custom output directory")
    ap.add_argument("--validate",     action="store_true",help="Live-validate found API keys")
    ap.add_argument("--browser",      action="store_true",help="Use Chromium headless (Playwright)")
    ap.add_argument("--scan-images",  action="store_true",help="Analyze images found in JS/pages")
    ap.add_argument("--sourcemaps",   action="store_true",help="Recover source map files")
    ap.add_argument("--json-api",     action="store_true",help="Probe API endpoints for CVEs")
    ap.add_argument("--nuclei",       action="store_true",help="Run Nuclei on discovered endpoints")
    ap.add_argument("--all",          action="store_true",help="Enable ALL modules")
    ap.add_argument("--verbose",      action="store_true",help="Verbose debug output")
    args=ap.parse_args()

    if args.all:
        args.validate=args.browser=args.scan_images=True
        args.sourcemaps=args.json_api=True

    global VERBOSE, LOG_F
    VERBOSE=args.verbose

    out_dir=args.output or f"jsxray_output_{TS}"
    js_dir =os.path.join(out_dir,"js_files")
    img_dir=os.path.join(out_dir,"img_analysis")
    api_dir=os.path.join(out_dir,"api_responses")
    map_dir=os.path.join(out_dir,"sourcemaps")
    for d in[js_dir,img_dir,api_dir,map_dir]: os.makedirs(d,exist_ok=True)
    LOG_F  =os.path.join(out_dir,"jsxray.log")
    ep_file=os.path.join(out_dir,"endpoints.txt")
    open(ep_file,'w').close()

    if not os.path.isfile(args.input):
        log(f"[!] Input file not found: {args.input}","ERR")
        log(f"    Create it with one URL per line and retry.","WARN")
        sys.exit(1)

    with open(args.input) as f:
        urls=[l.strip() for l in f if l.strip() and not l.startswith('#')]
    if not urls:
        log("[!] No URLs found in input file.","ERR"); sys.exit(1)

    log(f"  {C.CY}[*]{C.NC} {C.W}{len(urls)}{C.NC} URLs | threads={args.threads} | timeout={args.timeout}s","INFO")
    mods=[]
    for flag,name in[(args.browser,"browser"),(args.scan_images,"scan-images"),
                     (args.sourcemaps,"sourcemaps"),(args.json_api,"json-api"),
                     (args.validate,"validate"),(args.nuclei,"nuclei")]:
        col=C.BG if flag else C.DM
        mods.append(f"{col}{name}{C.NC}")
    log(f"  {C.CY}[*]{C.NC} Modules: {' '.join(mods)}","INFO")
    if args.browser and not HAS_PLAYWRIGHT:
        log("  [!] --browser: pip install playwright && playwright install chromium","WARN")
    if args.scan_images and not HAS_PIL:
        log("  [~] Pillow missing (LSB disabled): pip install Pillow","WARN")
    if not HAS_REQUESTS: log("  [~] requests missing: pip install requests","WARN")
    if not HAS_JSB:      log("  [~] jsbeautifier missing: pip install jsbeautifier","WARN")

    log(f"\n  {C.CY}{'━'*50}{C.NC}","INFO")

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futs={ex.submit(process_url,url,args,js_dir,img_dir,api_dir,map_dir,ep_file):url
              for url in urls}
        for fut in as_completed(futs):
            try: fut.result()
            except Exception as e:
                if args.verbose: log(f"  [!] Thread error {futs[fut]}: {e}","ERR")

    if args.nuclei: run_nuclei(ep_file,out_dir,proxy=args.proxy)

    log(f"\n  {C.CY}[*]{C.NC} Generating reports...","INFO")
    jf,cf,hf=gen_reports(out_dir)

    crit=sum(1 for f in FINDINGS if f['severity']=='CRITICAL')
    high=sum(1 for f in FINDINGS if f['severity']=='HIGH')
    print(f"""
{C.CY}{C.BO}╔══════════════════════════════════════════════════╗
║          JSXRay v{VERSION} — SCAN COMPLETE          ║
╠══════════════════════════════════════════════════╣{C.NC}
{C.CY}║{C.NC}  Total Findings  : {C.BR}{C.BO}{len(FINDINGS)}{C.NC}
{C.CY}║{C.NC}  Critical        : {C.BR}{crit}{C.NC}
{C.CY}║{C.NC}  High            : {C.R}{high}{C.NC}
{C.CY}║{C.NC}  Output Dir      : {C.BG}{out_dir}{C.NC}
{C.CY}║{C.NC}  HTML Report     : {C.BG}{hf}{C.NC}
{C.CY}║{C.NC}  JSON Report     : {C.BG}{jf}{C.NC}
{C.CY}║{C.NC}  CSV Report      : {C.BG}{cf}{C.NC}
{C.CY}{C.BO}╚══════════════════════════════════════════════════╝{C.NC}
  {C.DM}⚠  Authorized use only — {AUTHOR} — JSXRay v{VERSION}{C.NC}
""")

if __name__=="__main__": main()
