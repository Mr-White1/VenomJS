<div align="center">

```
   ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
   ██║╚════██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
   ██║    ██╔╝ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
   ██║   ██╔╝  ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
   ██║   ██║  ██╔╝ ██╗██║  ██║██║  ██║   ██║
   ╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
```

**Ultra-Advanced JS + Image Secret Scanner**

[![Version](https://img.shields.io/badge/version-2.0.0-00e5ff?style=flat-square)](https://github.com/Mr-White1/VenomJS)
[![Python](https://img.shields.io/badge/python-3.8+-00e5ff?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-00e5ff?style=flat-square)](LICENSE)
[![Author](https://img.shields.io/badge/author-Hari%20Kamma-7c3aed?style=flat-square)](https://github.com/Mr-White1)

*The only JS scanner that also reads secrets hidden inside image files*

</div>

---

## ⚡ What is JSXRay?

JSXRay is an ultra-advanced secret scanner for bug bounty hunters and pentesters. It scans JavaScript files, API endpoints, and web pages for exposed secrets — **and goes further than any other tool by also analyzing image files** for hidden credentials.

Tools like **SecretFinder**, **LinkFinder**, and **JSFinder** scan JS content only. JSXRay v2.0 adds something none of them do:

> **Real-world finding:** When you manually browse a target's JS-heavy web app, images load. Those images sometimes contain API keys in their EXIF metadata, tokens in PNG text chunks, or credentials in pixel-level steganography. No automation tool covered this — until now.

---

## 🆚 JSXRay v2.0 vs Every Other Tool

| Capability | SecretFinder | LinkFinder | JSFinder | **JSXRay v2.0** |
|---|:---:|:---:|:---:|:---:|
| JS secret scanning | ✅ | ✅ | ✅ | ✅ |
| Bulk URL input | ❌ | ❌ | ✅ | ✅ |
| Chromium headless browser (SPA support) | ❌ | ❌ | ❌ | ✅ |
| **Image EXIF metadata secret extraction** | ❌ | ❌ | ❌ | **✅** |
| **PNG text chunk analysis** | ❌ | ❌ | ❌ | **✅** |
| **JPEG comment marker parsing** | ❌ | ❌ | ❌ | **✅** |
| **LSB steganography detection** | ❌ | ❌ | ❌ | **✅** |
| **Binary string extraction from images** | ❌ | ❌ | ❌ | **✅** |
| **SVG inline script scanning** | ❌ | ❌ | ❌ | **✅** |
| **Image URL query param secrets** | ❌ | ❌ | ❌ | **✅** |
| Shannon entropy (unknown secrets) | ❌ | ❌ | ❌ | ✅ |
| Deobfuscation (atob / fromCharCode / hex) | ❌ | ❌ | ❌ | ✅ |
| Source map recovery | ❌ | ❌ | ❌ | ✅ |
| Live API key validation | ❌ | ❌ | ❌ | ✅ |
| Nuclei integration | ❌ | ❌ | ❌ | ✅ |
| GraphQL / IDOR / CVE checks | ❌ | ❌ | ❌ | ✅ |
| HTML + JSON + CSV reports | ❌ | ❌ | ❌ | ✅ |
| **110+ secret patterns** | ~30 | ~10 | ~20 | **✅ 110+** |

---

## 🔍 Modules

### Module 1 — Chromium Headless Browser
Uses **Playwright** to launch a real Chromium browser that:
- Renders full React/Vue/Angular/Next.js SPAs
- Intercepts all network requests in real-time
- Extracts lazy-loaded JS files that static scanners miss
- Captures DOM image URLs including CSS `background-image` values
- Returns rendered HTML for secret scanning

### Module 2 — Image Secret Analysis *(The Gap No Other Tool Covers)*
When JS files or pages reference image URLs (`.png`, `.jpg`, `.svg`, `.webp`, etc.), JSXRay downloads and analyzes each image through 9 sub-techniques:

| # | Technique | What it Finds |
|---|---|---|
| 1 | **URL query params** | `?token=sk_live_xxx`, `?key=AKIA...` in image request URLs |
| 2 | **EXIF metadata** | API keys in Author, Comment, Description EXIF fields |
| 3 | **PNG text chunks** | Secrets in `tEXt`, `iTXt`, `zTXt` PNG metadata chunks |
| 4 | **JPEG comment markers** | Hidden text in JPEG `0xFFFE` comment segments |
| 5 | **Appended data** | Data after PNG IEND or JPEG EOI markers |
| 6 | **LSB steganography** | Pixel-level hidden data via LSB encoding |
| 7 | **Binary strings** | Readable strings extracted from image binary data |
| 8 | **SVG scripts** | Inline `<script>` tags + base64 data URIs inside SVG files |
| 9 | **steghide / zsteg** | Integration with specialized stego tools if installed |

### Module 3 — Source Map Recovery
Detects `//# sourceMappingURL=` references, downloads `.map` files, and recovers **original unminified React/Vue/Angular source code** — including files that were never meant to be public.

### Module 4 — API Endpoint CVE Checks
Discovers API endpoints from JS content and probes them for:
- **Unauthenticated credential leaks** — JSON responses with `password`/`token` fields
- **Mass data exposure** — array responses with 10+ records without auth
- **IDOR** — numeric IDs in URL paths
- **Stack trace disclosure** — debug traces in error responses
- **GraphQL introspection** — full schema exposed publicly

### Module 5 — Live API Key Validation
Validates found keys against real APIs:

| Service | What it Confirms |
|---|---|
| Google GCP | Key active + which APIs enabled |
| Stripe | Live key valid + can list charges |
| GitHub | Valid token + username |
| Slack | Bot token active + workspace |
| Telegram | Bot token + bot username |
| OpenAI | Key active + can list models |
| SendGrid | Key valid + account email |

### Module 6 — Nuclei Integration
Auto-updates Nuclei templates from [projectdiscovery/nuclei-templates](https://github.com/projectdiscovery/nuclei-templates) and runs the following tag groups on all discovered endpoints:
```
exposure, token, api, secret, config, debug, disclosure,
misconfig, cve, js, auth-bypass, ssrf, xss
```

### Module 7 — Deobfuscation Engine
Decodes commonly obfuscated JS before scanning:
- `atob('base64string')` — Base64 decode
- `fromCharCode(72,101,108,108,111)` — char code sequences
- `'\x41\x50\x49\x4b\x45\x59'` — hex escape strings

### Module 8 — Shannon Entropy Detection
Identifies high-entropy strings (entropy ≥ 4.5) that no regex can catch — unknown secrets, custom tokens, and encryption keys.

---

## 📦 Installation

### One-Click Install (Linux/macOS)
```bash
git clone https://github.com/Mr-White1/VenomJS.git
cd VenomJS
chmod +x install.sh
./install.sh
```

### Manual Install
```bash
git clone https://github.com/Mr-White1/VenomJS.git
cd VenomJS

# Install Python dependencies
pip3 install requests Pillow jsbeautifier playwright

# Install Chromium for browser mode
playwright install chromium

# Install system tools (optional but recommended)
# Ubuntu/Debian:
sudo apt-get install exiftool steghide binutils

# macOS:
brew install exiftool steghide

# Install zsteg (PNG stego detection)
gem install zsteg

# Install Nuclei (optional)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates
```

---

## 🚀 Usage

### Step 1 — Create your URL input file

```bash
# urls.txt — one URL per line
https://target.com/static/js/main.chunk.js
https://target.com/static/js/vendors~main.chunk.js
https://target.com/assets/app.bundle.js
https://target.com/api/config
```

**Pro tip:** Use [subjs](https://github.com/lc/subjs) or [getJS](https://github.com/003random/getJS) to extract all JS URLs from a domain first:
```bash
echo "https://target.com" | subjs >> urls.txt
cat js_urls.txt >> urls.txt
```

### Step 2 — Run JSXRay

```bash
# Basic scan (secrets in JS files)
python3 jsxray.py -i urls.txt

# Full scan — enable ALL modules
python3 jsxray.py -i urls.txt --all

# Browser mode — renders SPAs + captures lazy-loaded JS and images
python3 jsxray.py -i urls.txt --browser --scan-images

# Authenticated scan (with session cookie)
python3 jsxray.py -i urls.txt --all -c 'session=abc123; csrf=xyz'

# Through Burp Suite proxy
python3 jsxray.py -i urls.txt --all -p http://127.0.0.1:8080

# Custom threads + timeout for large scope
python3 jsxray.py -i urls.txt --all --threads 20 -t 30

# Image analysis only — just scan images found in JS
python3 jsxray.py -i urls.txt --scan-images

# With live key validation
python3 jsxray.py -i urls.txt --validate

# Save output to custom directory
python3 jsxray.py -i urls.txt --all -o my_target_results
```

### All Flags

```
-i, --input FILE     URL input file (default: urls.txt)
-t, --timeout N      HTTP timeout in seconds (default: 15)
    --threads N      Parallel scan threads (default: 10)
-p, --proxy URL      HTTP proxy (e.g. http://127.0.0.1:8080)
-c, --cookies STR    Cookie string for authenticated scans
-o, --output DIR     Custom output directory

Modules:
    --browser        Chromium headless browser (Playwright required)
    --scan-images    Analyze all image files found in JS/pages
    --sourcemaps     Recover .map source files
    --json-api       Probe discovered API endpoints for CVEs
    --validate       Live-validate found API keys against APIs
    --nuclei         Run Nuclei on discovered endpoints
    --all            Enable ALL modules above

Output:
    --verbose        Show debug output
```

---

## 📁 Output Structure

```
jsxray_output_20241201_143022/
├── report.html          ← Interactive HTML dashboard (open in browser)
├── findings.json        ← All findings in JSON format
├── findings.csv         ← Spreadsheet-friendly CSV export
├── jsxray.log           ← Full scan log
├── endpoints.txt        ← Discovered API endpoints (for Nuclei)
├── js_files/            ← Downloaded raw JS files
├── img_analysis/        ← Downloaded images + analysis output
├── api_responses/       ← API endpoint response bodies
├── sourcemaps/          ← Recovered source map files
└── nuclei_results.txt   ← Nuclei scan output (if --nuclei used)
```

---

## 🔎 Secret Pattern Coverage (110+)

| Category | Patterns |
|---|---|
| **Cloud** | AWS Access Key, AWS Secret, AWS Session Token, GCP API Key, GCP Service Account, Firebase Server Key, Firebase Config, Azure Storage, Azure Client Secret, Azure SAS |
| **Payments** | Stripe Live/Test/Restricted, Stripe Webhook, PayPal Braintree, Square Token/Secret, Razorpay, Shopify Access/Secret, Adyen |
| **Auth / JWT** | JWT Token, OAuth Google, Bearer Token, Auth-in-URL, API Key in URL |
| **Source Control** | GitHub PAT/OAuth/App/Fine-Grained, GitLab PAT/Runner, CircleCI, Netlify, Vercel |
| **Communication** | Slack Bot/User/Webhook, Discord Token/Webhook, Telegram Bot, Twilio SID/Auth, SendGrid, Mailgun, Mailchimp, Postmark |
| **Databases** | MongoDB URI, PostgreSQL URI, MySQL URI, Redis URI, Supabase Key, S3 Bucket, PlanetScale, Neon DB |
| **AI / LLM** | OpenAI Key (sk-/sk-proj-), Anthropic Key, Groq Key, Replicate Token, HuggingFace Token |
| **Social APIs** | Twitter API/Bearer, Facebook Token, Mapbox Token, Algolia Key |
| **Crypto / Web3** | ETH Private Key, Seed Phrase/Mnemonic, Infura Key, Alchemy Key |
| **Crypto Material** | RSA Private Key, EC Private Key, OpenSSH Key, PGP Private Key |
| **Sensitive Data** | Credit Cards, SSN, SMTP Credentials |
| **Generic** | Generic API Key, Generic Secret, Generic Password, Generic Token |
| **Endpoints** | Admin Routes, GraphQL, Swagger/OpenAPI, Debug Flags, SSRF Metadata |

---

## 🌊 Real-World Bug Bounty Workflow

```bash
# 1. Gather all JS URLs from target
subfinder -d target.com -silent | httpx -silent | subjs > js_urls.txt
cat js_urls.txt | getJS --complete >> js_urls.txt
sort -u js_urls.txt > urls.txt

# 2. Run JSXRay with all modules
python3 jsxray.py -i urls.txt --all --threads 15

# 3. Open the HTML report
open jsxray_output_*/report.html    # macOS
xdg-open jsxray_output_*/report.html  # Linux

# 4. Validate any Critical findings immediately
python3 jsxray.py -i urls.txt --validate
```

---

## 🛠️ System Tool Dependencies

| Tool | Purpose | Required? |
|---|---|---|
| `python3` | Run the scanner | **Required** |
| `pip` packages | See requirements.txt | **Required** |
| `playwright + chromium` | Browser mode (`--browser`) | Optional |
| `exiftool` | EXIF metadata analysis | Optional (recommended) |
| `strings` | Binary string extraction | Optional (auto-fallback) |
| `steghide` | JPEG/BMP steganography | Optional |
| `zsteg` | PNG steganography | Optional |
| `nuclei` + `go` | CVE/exposure scanning | Optional |

---

## 📋 Requirements

- Python 3.8+
- pip packages: `requests`, `Pillow`, `jsbeautifier`, `playwright`

---

## ⚠️ Legal Disclaimer

> JSXRay is developed for **authorized security testing only**.
> Unauthorized use against systems you don't own or have explicit permission to test is **illegal** and punishable under computer fraud laws worldwide.
> The author assumes **zero liability** for misuse.
> Always operate within the scope of your bug bounty program or written authorization.

---

## 👤 Author

**Hari Kamma**
- GitHub: [@Mr-White1](https://github.com/Mr-White1)
- Tool Repo: [github.com/Mr-White1/VenomJS](https://github.com/Mr-White1/VenomJS)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

⚡ **JSXRay v2.0** — *Find what others miss*

Made with 🔥 by **Hari Kamma**

</div>
