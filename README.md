<div align="center">

```
  ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
  ██║╚════██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
  ██║    ██╔╝ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
  ██║   ██╔╝  ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
  ██║   ██║  ██╔╝ ██╗██║  ██║██║  ██║   ██║
  ╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
```

# JSXRay ⚡

**Advanced JavaScript Secret & Vulnerability Scanner**

[![License: MIT](https://img.shields.io/badge/License-MIT-cyan.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blueviolet.svg)]()
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS-lightgrey.svg)]()
[![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)]()
[![Author](https://img.shields.io/badge/author-Hari%20Kamma-orange.svg)](https://github.com/harikamma)

*The scanner that actually reads your image URLs.*

> ⚠️ **Authorized security testing and bug bounty only. Unauthorized use is illegal.**

</div>

---

## 🔍 What is JSXRay?

JSXRay is a powerful, all-in-one JavaScript security scanner built for **bug hunters and penetration testers**. It goes beyond simple grep-based scanning by combining:

- **90+ regex patterns** covering every major API and service
- **Image URL analysis** — the gap that NO other public tool covers
- **Source map recovery** — recover original source from minified files
- **Shannon entropy analysis** — finds secrets no regex can catch
- **Deobfuscation engine** — decodes `atob()`, `fromCharCode`, hex strings
- **Live key validation** — confirms if a found key is actually working
- **JSON API CVE checks** — GraphQL introspection, IDOR, mass data exposure
- **Nuclei integration** — automatic vuln scanning on discovered endpoints
- **3 report formats** — HTML dashboard + JSON + CSV

---

## 🆚 JSXRay vs. Existing Tools

| Feature | JSXRay | SecretFinder | LinkFinder | JS Miner | TruffleHog |
|---|:---:|:---:|:---:|:---:|:---:|
| JS secret scanning | ✅ | ✅ | ⚠️ | ✅ | ✅ |
| Image URL analysis | ✅ | ❌ | ❌ | ❌ | ❌ |
| EXIF metadata extraction | ✅ | ❌ | ❌ | ❌ | ❌ |
| Binary strings from images | ✅ | ❌ | ❌ | ❌ | ❌ |
| SVG script analysis | ✅ | ❌ | ❌ | ❌ | ❌ |
| Source map recovery | ✅ | ❌ | ❌ | ❌ | ❌ |
| Shannon entropy analysis | ✅ | ❌ | ❌ | ❌ | ✅ |
| atob / fromCharCode decode | ✅ | ❌ | ❌ | ❌ | ❌ |
| Base64 secret detection | ✅ | ❌ | ❌ | ❌ | ⚠️ |
| Live API key validation | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| GraphQL introspection check | ✅ | ❌ | ❌ | ❌ | ❌ |
| IDOR detection | ✅ | ❌ | ❌ | ❌ | ❌ |
| Inline script extraction | ✅ | ❌ | ❌ | ❌ | ❌ |
| Nuclei integration | ✅ | ❌ | ❌ | ❌ | ❌ |
| HTML report dashboard | ✅ | ❌ | ❌ | ⚠️ | ❌ |
| Authenticated scanning | ✅ | ⚠️ | ❌ | ❌ | ❌ |
| Proxy support (Burp) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Deobfuscation | ✅ | ❌ | ❌ | ❌ | ❌ |
| 90+ patterns | ✅ | ⚠️ | ❌ | ⚠️ | ✅ |

---

## 📦 Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/harikamma/JSXRay.git
cd JSXRay
chmod +x install.sh
./install.sh
```

The installer automatically handles:
- Core dependencies (`curl`, `jq`, `python3`, `exiftool`, etc.)
- Optional tools (`js-beautify`, `binwalk`, `nuclei`)
- Global symlink (`jsxray` command available everywhere)

### Manual Install

```bash
# Clone
git clone https://github.com/harikamma/JSXRay.git
cd JSXRay

# Make executable
chmod +x jsxray.sh jsxray_analyze.py

# Install core deps (Ubuntu/Debian)
sudo apt install curl gawk python3 jq libimage-exiftool-perl binutils

# Install core deps (macOS)
brew install curl gawk python3 jq exiftool

# Optional: JS beautifier (for minified file readability)
npm install -g js-beautify

# Optional: binwalk (for steganography analysis)
sudo apt install binwalk

# Optional: Nuclei (for automated CVE scanning)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

### Verify Installation

```bash
./jsxray.sh --help
python3 jsxray_analyze.py --help
```

---

## 🚀 Usage

### Step 1 — Collect JS URLs

```bash
# Using gau + waybackurls (recommended)
gau target.com | grep "\.js$" > urls.txt
waybackurls target.com | grep "\.js" >> urls.txt

# Using subfinder + httpx
subfinder -d target.com | httpx -silent | gau | grep "\.js" >> urls.txt

# Using katana
katana -u https://target.com -jc -d 3 | grep "\.js" > urls.txt

# Or manually
echo "https://target.com/static/js/main.chunk.js" > urls.txt
echo "https://target.com/static/js/vendors.js" >> urls.txt
```

### Step 2 — Run JSXRay

```bash
# Basic scan
./jsxray.sh -i urls.txt

# Full scan — all modules enabled
./jsxray.sh -i urls.txt -d target.com --all

# With key validation
./jsxray.sh -i urls.txt --validate

# Authenticated (with session cookies)
./jsxray.sh -i urls.txt -c "session=abc123; auth=xyz789"

# Through Burp Suite proxy
./jsxray.sh -i urls.txt -p http://127.0.0.1:8080

# High-thread scan for speed
./jsxray.sh -i urls.txt -t 30 -T 20
```

### Step 3 — View Results

```bash
# Open HTML report (interactive, filterable)
open jsxray_output_*/report.html           # macOS
xdg-open jsxray_output_*/report.html      # Linux

# Quick terminal view
cat jsxray_output_*/report.csv

# JSON (pipe-friendly)
jq '.findings[] | select(.severity=="CRITICAL")' jsxray_output_*/findings.json
```

---

## ⚙️ All Options

```
USAGE:
  ./jsxray.sh [OPTIONS]

INPUT:
  -i, --input <file>         File with JS/JSON URLs, one per line (default: urls.txt)
  -d, --domain <domain>      Scope domain for crawl filtering (e.g. target.com)

PERFORMANCE:
  -t, --threads <n>          Parallel download threads (default: 10)
  -T, --timeout <n>          HTTP request timeout in seconds (default: 15)

AUTH / PROXY:
  -p, --proxy <url>          HTTP/S proxy (e.g. http://127.0.0.1:8080)
  -c, --cookies <str>        Cookie string for authenticated scanning
  -H, --header <str>         Custom HTTP header (repeatable)

SCAN MODULES:
  --validate                 Live-validate discovered API keys
  --deep-crawl               Crawl HTML pages, extract inline + linked JS
  --scan-images              Analyze image URLs (EXIF, strings, SVG, params)
  --sourcemaps               Download .map files → recover original source code
  --json-api                 Probe API endpoints for CVEs and data exposure
  --nuclei                   Run Nuclei with exposure/CVE templates
  --all                      Enable ALL modules above

OUTPUT:
  -o, --output <dir>         Custom output directory
  --silent                   Suppress banner; findings only (pipe-friendly)
  --verbose                  Debug-level output

OTHER:
  -h, --help                 Show this help
```

---

## 🧠 Python Analyzer (Deep Mode)

The Python companion `jsxray_analyze.py` provides deeper analysis for already-downloaded files:

```bash
# Analyze a single file
python3 jsxray_analyze.py app.js

# Analyze a whole directory of JS files
python3 jsxray_analyze.py ./jsxray_output_*/js_files/

# Multiple files
python3 jsxray_analyze.py main.js chunk.js vendor.js

# Custom entropy threshold (lower = more results)
python3 jsxray_analyze.py ./js/ --entropy-threshold 4.2 --min-len 16

# Save to custom output
python3 jsxray_analyze.py ./js/ -o my_analysis.json
```

**What the Python analyzer adds:**

| Capability | Description |
|---|---|
| Shannon entropy | Flags high-entropy strings (likely tokens/keys) even without matching patterns |
| `atob()` decode | Decodes all base64-encoded strings called via `atob()` |
| `fromCharCode` decode | Reconstructs strings encoded as character codes |
| Hex string decode | Decodes `\x41\x50\x49` style strings |
| Obfuscation score | Rates JS files 0-8 on obfuscation indicators |
| Image URL params | Checks every image URL in the file for sensitive query parameters |
| Sensitive comments | Finds `// password:`, `/* TODO: remove key */` style leaks |

---

## 🔬 Scan Modules Explained

### `--scan-images` *(Unique to JSXRay)*

Most tools skip image URLs entirely. JSXRay analyzes every image URL found inside JS:

```
Image URL found in JS: https://cdn.target.com/assets/logo.png?token=sk_live_xxxxx
                                                               ↑
                                               JSXRay catches this. Others don't.
```

For each image URL JSXRay:
1. **Downloads** the image
2. **EXIF extraction** — checks metadata for API keys, author fields, comments
3. **Binary strings** — runs `strings` to find embedded text data
4. **URL parameter scan** — checks for `?key=`, `?token=`, `?auth=` in the URL
5. **SVG scripts** — SVG files can contain `<script>` tags and JavaScript
6. **Binwalk** — detects and extracts hidden files inside images (steganography)

### `--sourcemaps`

Minified JS often has a reference like `//# sourceMappingURL=main.js.map`. JSXRay:
1. Detects this comment in downloaded JS
2. Downloads the `.map` file
3. Extracts all original source files (often React/Vue/Angular components)
4. Scans those recovered files — which usually contain real variable names and readable secrets

### `--json-api`

Probes extracted endpoints for:
- **GraphQL introspection** — sends `{__schema{types{name}}}` test query
- **Unauthenticated credential leak** — JSON responses containing password/token fields
- **Mass data exposure** — arrays with >10 records returned without auth
- **IDOR** — numeric IDs in URL paths
- **Stack trace disclosure** — verbose error pages leaking framework/DB info
- **API spec exposure** — Swagger / OpenAPI accessible publicly

### `--validate`

Validates found keys against real APIs (carefully, read-only calls only):

| Key Type | Validation Method |
|---|---|
| Google / GCP API Key | Geocoding API test request |
| Stripe (live/test) | List charges (limit=1) |
| GitHub PAT | `/user` endpoint — returns username |
| Slack Token | `auth.test` endpoint |
| SendGrid Key | `/v3/user/profile` endpoint |
| Telegram Bot | `getMe` endpoint — returns bot username |

---

## 🎯 Pattern Coverage (90+ patterns)

<details>
<summary>Click to expand full pattern list</summary>

**Cloud — AWS**
- AWS Access Key (`AKIA...`)
- AWS Secret Key
- AWS MWS Key
- AWS Account ID

**Cloud — GCP / Firebase**
- GCP API Key
- GCP OAuth Client
- GCP Service Account
- Firebase Server Key
- Firebase Config object
- Firebase Realtime DB URL

**Cloud — Azure**
- Azure Storage Connection String
- Azure Client Secret

**Payment / Fintech**
- Stripe Secret (live + test)
- Stripe Publishable
- Stripe Restricted Key
- PayPal Braintree
- Square Token + Secret
- Razorpay Key
- Shopify Access Token + Shared Secret

**Auth / JWT**
- JWT Token
- Google OAuth Token
- Bearer Token
- Basic Auth Header
- Auth credentials in URL

**Source Control & CI/CD**
- GitHub PAT, OAuth, App Token
- GitLab PAT + Runner Token
- BitBucket Secret
- CircleCI Token
- Travis CI Token
- Jenkins Token

**Communication / Messaging**
- Slack Token + Webhook URL
- Discord Token + Webhook URL
- Telegram Bot Token
- Twilio Account SID + Auth Token
- SendGrid API Key
- Mailgun API Key
- Mailchimp API Key
- Mandrill Key
- Vonage / Nexmo Key

**Databases**
- MongoDB URI
- PostgreSQL URI
- MySQL URI
- Redis URI
- Elasticsearch URI
- Supabase JWT
- S3 Bucket URL

**Social / Dev APIs**
- Twitter API Key + Bearer
- Facebook Access Token
- YouTube API Key
- HubSpot Key
- Mapbox Token
- HERE Maps Key

**Crypto / Web3**
- Ethereum Private Key
- Crypto Mnemonic / Seed Phrase
- Infura Key
- Alchemy Key

**Cryptographic Material**
- RSA Private Key
- EC Private Key
- OpenSSH Private Key
- PGP Private Key Block
- X.509 Certificate

**Generic / Catch-all**
- Generic API Key variables
- Generic Secret variables
- Generic Password variables
- Generic Token variables
- Internal IP addresses (RFC 1918)
- SMTP/FTP URIs with credentials
- SSN / PII patterns
- Hardcoded admin credentials
- Debug flags
- Admin, GraphQL, Swagger routes

</details>

---

## 📁 Output Structure

```
jsxray_output_YYYYMMDD_HHMMSS/
├── report.html                ← Interactive HTML dashboard (filterable by severity)
├── findings.json              ← Full machine-readable findings (jq-friendly)
├── report.csv                 ← Spreadsheet-compatible output
├── jsxray.log                 ← Full verbose log
├── endpoints_discovered.txt   ← All extracted endpoints (for Nuclei / manual testing)
│
├── js_files/                  ← Downloaded JS/JSON files
│   ├── abc123def456.js
│   └── abc123def456_pretty.js ← Beautified version
│
├── img_analysis/              ← Downloaded images + analysis
│   ├── *.png / *.jpg / *.svg
│   └── binwalk_*/             ← Binwalk-extracted hidden files
│
├── sourcemaps/                ← Recovered source files
│   └── src_*/                 ← Original React/Vue/Angular components
│
├── api_responses/             ← JSON API responses
│   └── *.json
│
├── deobfuscated/              ← Deobfuscated versions of JS files
└── .tmp/                      ← Internal temp (dedup index, etc.)
```

---

## 🔄 Full Bug Bounty Workflow

```bash
# ── 1. Recon: collect all JS URLs ──────────────────────────
TARGET="target.com"

subfinder -d $TARGET -silent | \
  httpx -silent | \
  gau | \
  grep -iP '\.js(\?|$)' | \
  sort -u > urls.txt

waybackurls $TARGET | grep -iP '\.js(\?|$)' >> urls.txt
sort -u urls.txt -o urls.txt

echo "[*] $(wc -l < urls.txt) JS URLs collected"

# ── 2. Run JSXRay full scan ─────────────────────────────────
./jsxray.sh \
  -i urls.txt \
  -d $TARGET \
  --all \
  --validate \
  -t 20 \
  -T 20

# ── 3. Deep Python analysis on downloaded files ─────────────
python3 jsxray_analyze.py jsxray_output_*/js_files/ \
  --entropy-threshold 4.3 \
  -o deep_analysis.json

# ── 4. Review critical findings ────────────────────────────
jq '.findings[] | select(.severity=="CRITICAL")' \
  jsxray_output_*/findings.json

# ── 5. Open HTML dashboard ─────────────────────────────────
xdg-open jsxray_output_*/report.html
```

---

## 🛡️ Complementary Tools

JSXRay works best alongside:

| Tool | Purpose | Install |
|---|---|---|
| `gau` | Fetch all JS URLs from archives | `go install github.com/lc/gau/v2/cmd/gau@latest` |
| `waybackurls` | Wayback Machine URL fetch | `go install github.com/tomnomnom/waybackurls@latest` |
| `subfinder` | Subdomain enumeration | `go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| `httpx` | HTTP probe / filter live hosts | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `katana` | Modern JS-aware web crawler | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| `nuclei` | CVE / template scanning | `go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| `Burp Suite` | Proxy + manual inspection | https://portswigger.net |

---

## 📋 Common Errors

| Error | Fix |
|---|---|
| `js.txt not found` | Create `urls.txt` with target URLs, or use `-i yourfile.txt` |
| `jq: command not found` | `sudo apt install jq` |
| `No matches found` | Try `--deep-crawl` to extract more JS from HTML pages |
| `curl: (28) Timeout` | Increase timeout: `-T 30` |
| `exiftool not found` | `sudo apt install libimage-exiftool-perl` — image EXIF skipped |
| `nuclei: not found` | Install Go, then `go install ...nuclei@latest` |
| `Permission denied` | `chmod +x jsxray.sh` |

---

## 🤝 Contributing

Pull requests welcome! Please:

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/new-pattern`
3. Add patterns to the `PATTERNS` array in `jsxray.sh` with proper severity
4. Test with a sample file
5. Submit PR with description

**Ideas for contribution:**
- New secret patterns (new services, new token formats)
- Additional validation methods
- Docker container
- Web UI for the HTML report
- Windows (PowerShell) port

---

## 📜 Changelog

### v1.0.0 (2025)
- Initial public release
- 90+ secret patterns across all major services
- Image URL analysis module (EXIF, strings, binwalk, SVG, URL params)
- Source map recovery
- Shannon entropy analysis (Python module)
- Deobfuscation engine (atob, fromCharCode, hex)
- Live key validation (6 services)
- JSON API CVE checks (GraphQL, IDOR, mass exposure)
- Nuclei integration
- Triple report output (HTML + JSON + CSV)
- Deep crawl mode
- Proxy & cookie auth support

---

## ⚖️ Legal & Ethics

JSXRay is a security research tool. By using it you agree to:

- **Only test systems you own or have explicit written permission to test**
- **Report findings responsibly** via the target's security disclosure program
- **Not use this tool** for unauthorized access, data theft, or any illegal purpose
- **Comply with all applicable laws** in your jurisdiction

The author (**Hari Kamma**) assumes zero liability for misuse.

Unauthorized testing is illegal under:
- Computer Fraud and Abuse Act (CFAA) — USA
- Computer Misuse Act — UK
- IT Act 2000 — India
- And equivalent laws worldwide

---

<div align="center">

**Made with ⚡ by [Hari Kamma](https://github.com/harikamma)**

*If this tool helped you find a bug, consider giving it a ⭐ on GitHub*

</div>
