#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════
#
#       ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
#       ██║██╔════╝╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
#       ██║███████╗ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
#  ██   ██║╚════██║ ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
#  ╚█████╔╝███████║██╔╝ ██╗██║  ██║██║  ██║   ██║
#   ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
#
#   JSXRay — Advanced JavaScript Secret & Vulnerability Scanner
#   Version  : 1.0.0
#   Author   : Hari Kamma
#   GitHub   : https://github.com/harikamma/JSXRay
#   License  : MIT
#
#   ⚠  For authorized bug bounty and penetration testing ONLY.
#      Unauthorized use is illegal and unethical.
# ═══════════════════════════════════════════════════════════════════════

set -euo pipefail

# ──────────────────────────────────────────────────────────
#  VERSION & META
# ──────────────────────────────────────────────────────────
TOOL_NAME="JSXRay"
VERSION="1.0.0"
AUTHOR="Hari Kamma"
GITHUB="https://github.com/harikamma/JSXRay"

# ──────────────────────────────────────────────────────────
#  COLORS
# ──────────────────────────────────────────────────────────
RED='\033[0;31m';    BRED='\033[1;31m'
GREEN='\033[0;32m';  BGREEN='\033[1;32m'
CYAN='\033[1;36m';   BCYAN='\033[0;36m'
YELLOW='\033[1;33m'; BYELLOW='\033[0;33m'
MAGENTA='\033[1;35m';BLUE='\033[1;34m'
WHITE='\033[1;37m';  DIM='\033[2m'
BOLD='\033[1m';      NC='\033[0m'

# ──────────────────────────────────────────────────────────
#  DEFAULTS
# ──────────────────────────────────────────────────────────
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="jsxray_output_${TIMESTAMP}"
JS_DUMP="${OUTPUT_DIR}/js_files"
IMG_DUMP="${OUTPUT_DIR}/img_analysis"
MAP_DUMP="${OUTPUT_DIR}/sourcemaps"
JSON_API_DUMP="${OUTPUT_DIR}/api_responses"
DEOBF_DIR="${OUTPUT_DIR}/deobfuscated"
TEMP_DIR="${OUTPUT_DIR}/.tmp"
REPORT_JSON="${OUTPUT_DIR}/findings.json"
REPORT_HTML="${OUTPUT_DIR}/report.html"
REPORT_CSV="${OUTPUT_DIR}/report.csv"
LOG_FILE="${OUTPUT_DIR}/jsxray.log"
ENDPOINTS_FILE="${OUTPUT_DIR}/endpoints_discovered.txt"

INPUT_FILE="urls.txt"
THREADS=10
TIMEOUT=15
USER_AGENT="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36"
PROXY=""
COOKIES=""
CUSTOM_HEADERS=""
DOMAIN_SCOPE=""

# Feature flags
VALIDATE_KEYS=false
DEEP_CRAWL=false
SCAN_IMAGES=false
EXTRACT_SOURCEMAPS=false
SCAN_JSON_API=false
NUCLEI_SCAN=false
VERBOSE=false
SILENT=false

# Counters
TOTAL_FILES=0
TOTAL_SECRETS=0
TOTAL_ENDPOINTS=0
TOTAL_IMAGES=0

# ──────────────────────────────────────────────────────────
#  BANNER
# ──────────────────────────────────────────────────────────
banner() {
  [[ "$SILENT" == true ]] && return
  echo -e "${CYAN}"
  cat << 'BANNER'

       ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
       ██║██╔════╝╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
       ██║███████╗ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
  ██   ██║╚════██║ ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
  ╚█████╔╝███████║██╔╝ ██╗██║  ██║██║  ██║   ██║
   ╚════╝ ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝

BANNER
  echo -e "${NC}${BOLD}  Advanced JavaScript Secret & Vulnerability Scanner${NC}"
  echo -e "  ${DIM}v${VERSION} | By ${AUTHOR} | ${GITHUB}${NC}"
  echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo -e "  ${DIM}⚠  Authorized security testing only. Illegal use prohibited.${NC}"
  echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
  echo ""
}

# ──────────────────────────────────────────────────────────
#  HELP
# ──────────────────────────────────────────────────────────
usage() {
  echo -e "${CYAN}${BOLD}USAGE:${NC}"
  echo -e "  ./jsxray.sh [OPTIONS]\n"

  echo -e "${CYAN}${BOLD}INPUT:${NC}"
  echo -e "  ${YELLOW}-i, --input <file>${NC}         File with JS/JSON URLs, one per line (default: urls.txt)"
  echo -e "  ${YELLOW}-d, --domain <domain>${NC}      Scope domain for crawl filtering (e.g. target.com)"

  echo -e "\n${CYAN}${BOLD}PERFORMANCE:${NC}"
  echo -e "  ${YELLOW}-t, --threads <n>${NC}          Parallel download threads (default: 10)"
  echo -e "  ${YELLOW}-T, --timeout <n>${NC}          HTTP request timeout in seconds (default: 15)"

  echo -e "\n${CYAN}${BOLD}AUTH / PROXY:${NC}"
  echo -e "  ${YELLOW}-p, --proxy <url>${NC}          HTTP/S proxy (e.g. http://127.0.0.1:8080)"
  echo -e "  ${YELLOW}-c, --cookies <str>${NC}        Cookie string for authenticated scanning"
  echo -e "  ${YELLOW}-H, --header <str>${NC}         Custom HTTP header (repeatable)"

  echo -e "\n${CYAN}${BOLD}SCAN MODULES:${NC}"
  echo -e "  ${YELLOW}--validate${NC}                 Live-validate discovered API keys"
  echo -e "  ${YELLOW}--deep-crawl${NC}               Crawl HTML pages and extract inline + linked JS"
  echo -e "  ${YELLOW}--scan-images${NC}              Analyze image URLs found in JS (EXIF, strings, SVG, params)"
  echo -e "  ${YELLOW}--sourcemaps${NC}               Download & parse .map files → recover original source"
  echo -e "  ${YELLOW}--json-api${NC}                 Probe discovered API endpoints for CVEs & data exposure"
  echo -e "  ${YELLOW}--nuclei${NC}                   Run Nuclei with secret/exposure templates on endpoints"
  echo -e "  ${YELLOW}--all${NC}                      Enable ALL scan modules"

  echo -e "\n${CYAN}${BOLD}OUTPUT:${NC}"
  echo -e "  ${YELLOW}-o, --output <dir>${NC}         Custom output directory name"
  echo -e "  ${YELLOW}--silent${NC}                   Suppress banner; print findings only"
  echo -e "  ${YELLOW}--verbose${NC}                  Debug-level output"

  echo -e "\n${CYAN}${BOLD}EXAMPLES:${NC}"
  echo -e "  ${DIM}# Basic scan${NC}"
  echo -e "  ./jsxray.sh -i urls.txt\n"
  echo -e "  ${DIM}# Full scan with all modules${NC}"
  echo -e "  ./jsxray.sh -i urls.txt -d target.com --all --validate -t 20\n"
  echo -e "  ${DIM}# Authenticated scan through Burp Suite${NC}"
  echo -e "  ./jsxray.sh -i urls.txt -p http://127.0.0.1:8080 -c 'session=abc123'\n"
  echo -e "  ${DIM}# Silent mode (pipe-friendly)${NC}"
  echo -e "  ./jsxray.sh -i urls.txt --silent | grep CRITICAL\n"
}

# ──────────────────────────────────────────────────────────
#  ARG PARSING
# ──────────────────────────────────────────────────────────
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -i|--input)        INPUT_FILE="$2";           shift 2 ;;
      -d|--domain)       DOMAIN_SCOPE="$2";         shift 2 ;;
      -t|--threads)      THREADS="$2";              shift 2 ;;
      -T|--timeout)      TIMEOUT="$2";              shift 2 ;;
      -p|--proxy)        PROXY="$2";                shift 2 ;;
      -c|--cookies)      COOKIES="$2";              shift 2 ;;
      -H|--header)       CUSTOM_HEADERS="$CUSTOM_HEADERS -H \"$2\""; shift 2 ;;
      -o|--output)       OUTPUT_DIR="$2";           shift 2 ;;
      --validate)        VALIDATE_KEYS=true;        shift ;;
      --deep-crawl)      DEEP_CRAWL=true;           shift ;;
      --scan-images)     SCAN_IMAGES=true;          shift ;;
      --sourcemaps)      EXTRACT_SOURCEMAPS=true;   shift ;;
      --json-api)        SCAN_JSON_API=true;        shift ;;
      --nuclei)          NUCLEI_SCAN=true;          shift ;;
      --all)
        VALIDATE_KEYS=true; DEEP_CRAWL=true; SCAN_IMAGES=true
        EXTRACT_SOURCEMAPS=true; SCAN_JSON_API=true
        shift ;;
      --silent)          SILENT=true;               shift ;;
      --verbose)         VERBOSE=true;              shift ;;
      -h|--help)         banner; usage; exit 0 ;;
      *) echo -e "${RED}[!] Unknown option: $1${NC}"; usage; exit 1 ;;
    esac
  done
}

# ──────────────────────────────────────────────────────────
#  LOGGING
# ──────────────────────────────────────────────────────────
log()         { echo -e "$1" | tee -a "$LOG_FILE"; }
log_verbose() { [[ "$VERBOSE" == true ]] && echo -e "${DIM}[DBG] $1${NC}" | tee -a "$LOG_FILE"; }
log_silent()  { echo -e "$1" >> "$LOG_FILE"; }

print_finding() {
  local sev="$1" type="$2" val="$3" file="$4" line="$5"
  local color="$YELLOW"
  [[ "$sev" == "CRITICAL" ]] && color="$BRED"
  [[ "$sev" == "HIGH" ]]     && color="$RED"
  [[ "$sev" == "MEDIUM" ]]   && color="$YELLOW"
  [[ "$sev" == "LOW" ]]      && color="$BLUE"
  echo -e "${color}[${sev}]${NC} ${MAGENTA}${type}${NC}"
  echo -e "         ${GREEN}→${NC} ${WHITE}${val:0:120}${NC}"
  echo -e "         ${DIM}Source: ${file} | Line: ${line}${NC}"
}

# ──────────────────────────────────────────────────────────
#  SETUP
# ──────────────────────────────────────────────────────────
setup() {
  # Recalculate subdirs if custom output set
  JS_DUMP="${OUTPUT_DIR}/js_files"
  IMG_DUMP="${OUTPUT_DIR}/img_analysis"
  MAP_DUMP="${OUTPUT_DIR}/sourcemaps"
  JSON_API_DUMP="${OUTPUT_DIR}/api_responses"
  DEOBF_DIR="${OUTPUT_DIR}/deobfuscated"
  TEMP_DIR="${OUTPUT_DIR}/.tmp"
  REPORT_JSON="${OUTPUT_DIR}/findings.json"
  REPORT_HTML="${OUTPUT_DIR}/report.html"
  REPORT_CSV="${OUTPUT_DIR}/report.csv"
  LOG_FILE="${OUTPUT_DIR}/jsxray.log"
  ENDPOINTS_FILE="${OUTPUT_DIR}/endpoints_discovered.txt"

  mkdir -p "$JS_DUMP" "$IMG_DUMP" "$MAP_DUMP" \
           "$JSON_API_DUMP" "$DEOBF_DIR" "$TEMP_DIR"
  touch "${TEMP_DIR}/dedup"
  > "$ENDPOINTS_FILE"

  # Bootstrap JSON report
  echo "{\"tool\":\"${TOOL_NAME}\",\"version\":\"${VERSION}\",\"author\":\"${AUTHOR}\",\"timestamp\":\"${TIMESTAMP}\",\"findings\":[]}" \
    > "$REPORT_JSON"

  # Bootstrap CSV report
  echo "Severity,Type,Value,Source,Line,Validated,Notes" > "$REPORT_CSV"
}

check_deps() {
  local missing=()
  for dep in curl grep sed awk python3 jq; do
    command -v "$dep" &>/dev/null || missing+=("$dep")
  done
  if [[ ${#missing[@]} -gt 0 ]]; then
    echo -e "${BRED}[!] Missing required tools: ${missing[*]}${NC}"
    echo -e "${YELLOW}[*] sudo apt install curl grep gawk python3 jq${NC}"
    exit 1
  fi

  local optional_ok=() optional_no=()
  for dep in js-beautify exiftool strings binwalk nuclei node; do
    command -v "$dep" &>/dev/null && optional_ok+=("$dep") || optional_no+=("$dep")
  done
  log "${BGREEN}[✓] Core deps OK${NC}"
  [[ ${#optional_ok[@]} -gt 0 ]]  && log "${GREEN}[✓] Optional available: ${optional_ok[*]}${NC}"
  [[ ${#optional_no[@]} -gt 0 ]] && log "${DIM}[~] Optional not found (some features reduced): ${optional_no[*]}${NC}"
}

# ──────────────────────────────────────────────────────────
#  HTTP FETCH
# ──────────────────────────────────────────────────────────
http_fetch() {
  local url="$1" out="$2"
  curl -s -L \
    --max-time "$TIMEOUT" \
    -A "$USER_AGENT" \
    ${PROXY:+--proxy "$PROXY"} \
    ${COOKIES:+-b "$COOKIES"} \
    -w "%{http_code}" \
    -o "$out" \
    "$url" 2>/dev/null || echo "000"
}

# ──────────────────────────────────────────────────────────
#  SAVE FINDING
# ──────────────────────────────────────────────────────────
save_finding() {
  local sev="$1" type="$2" val="$3" src="$4" line="$5" \
        validated="${6:-false}" notes="${7:-}"

  # Deduplicate
  local dk="${type}::${val}"
  grep -qF "$dk" "${TEMP_DIR}/dedup" 2>/dev/null && return
  echo "$dk" >> "${TEMP_DIR}/dedup"

  print_finding "$sev" "$type" "$val" "$src" "$line"

  # JSON
  local tmp="${REPORT_JSON}.tmp"
  jq --arg s "$sev" --arg t "$type" --arg v "$val" \
     --arg f "$src" --arg l "$line" --arg vl "$validated" --arg n "$notes" \
    '.findings += [{"severity":$s,"type":$t,"value":$v,"source":$f,"line":$l,"validated":$vl,"notes":$n}]' \
    "$REPORT_JSON" > "$tmp" && mv "$tmp" "$REPORT_JSON"

  # CSV
  printf '"%s","%s","%s","%s","%s","%s","%s"\n' \
    "$sev" "$type" "$(echo "$val" | sed 's/"/""/g')" "$src" "$line" "$validated" "$notes" \
    >> "$REPORT_CSV"

  TOTAL_SECRETS=$((TOTAL_SECRETS + 1))
}

# ══════════════════════════════════════════════════════════
#  PATTERN LIBRARY  (90+ patterns)
# ══════════════════════════════════════════════════════════
declare -A PATTERNS SEVERITY

# ── Cloud: AWS ──
PATTERNS[AWS_Access_Key]='AKIA[0-9A-Z]{16}'
PATTERNS[AWS_Secret_Key]='(?i)(aws_secret_access_key|aws_secret)["\s:=]{1,10}[A-Za-z0-9/+=]{40}'
PATTERNS[AWS_MWS_Key]='amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}'
PATTERNS[AWS_Account_ID]='(?<!\d)[0-9]{4}-[0-9]{4}-[0-9]{4}(?!\d)'
SEVERITY[AWS_Access_Key]=CRITICAL; SEVERITY[AWS_Secret_Key]=CRITICAL
SEVERITY[AWS_MWS_Key]=HIGH;        SEVERITY[AWS_Account_ID]=LOW

# ── Cloud: GCP / Firebase ──
PATTERNS[GCP_API_Key]='AIza[0-9A-Za-z\-_]{35}'
PATTERNS[GCP_OAuth_Client]='[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'
PATTERNS[GCP_Service_Account]='"type":\s*"service_account"'
PATTERNS[Firebase_Server_Key]='AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}'
PATTERNS[Firebase_Config]='apiKey:\s*["'"'"'][A-Za-z0-9_-]{39}["'"'"']'
PATTERNS[Firebase_URL]='https://[a-z0-9-]+\.firebaseio\.com'
SEVERITY[GCP_API_Key]=HIGH;            SEVERITY[GCP_OAuth_Client]=MEDIUM
SEVERITY[GCP_Service_Account]=CRITICAL;SEVERITY[Firebase_Server_Key]=CRITICAL
SEVERITY[Firebase_Config]=HIGH;        SEVERITY[Firebase_URL]=LOW

# ── Cloud: Azure ──
PATTERNS[Azure_Storage_Key]='DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/]{88}=='
PATTERNS[Azure_Client_Secret]='(?i)(client_secret|clientsecret)["\s:=]{1,10}[A-Za-z0-9~._-]{34,}'
SEVERITY[Azure_Storage_Key]=CRITICAL; SEVERITY[Azure_Client_Secret]=CRITICAL

# ── Stripe / Payment ──
PATTERNS[Stripe_Secret_Live]='sk_live_[0-9a-zA-Z]{24}'
PATTERNS[Stripe_Secret_Test]='sk_test_[0-9a-zA-Z]{24}'
PATTERNS[Stripe_Publishable]='pk_(live|test)_[0-9a-zA-Z]{24}'
PATTERNS[Stripe_Restricted]='rk_live_[0-9a-zA-Z]{24}'
PATTERNS[PayPal_Braintree]='access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}'
PATTERNS[Square_Token]='sq0atp-[0-9A-Za-z\-_]{22}'
PATTERNS[Square_Secret]='sq0csp-[0-9A-Za-z\-_]{43}'
PATTERNS[Razorpay_Key]='rzp_(live|test)_[A-Za-z0-9]{14}'
PATTERNS[Shopify_AccessToken]='shpat_[a-fA-F0-9]{32}'
PATTERNS[Shopify_SharedSecret]='shpss_[a-fA-F0-9]{32}'
SEVERITY[Stripe_Secret_Live]=CRITICAL; SEVERITY[Stripe_Secret_Test]=MEDIUM
SEVERITY[Stripe_Publishable]=LOW;      SEVERITY[Stripe_Restricted]=CRITICAL
SEVERITY[PayPal_Braintree]=CRITICAL;   SEVERITY[Square_Token]=HIGH
SEVERITY[Square_Secret]=CRITICAL;      SEVERITY[Razorpay_Key]=HIGH
SEVERITY[Shopify_AccessToken]=CRITICAL;SEVERITY[Shopify_SharedSecret]=CRITICAL

# ── Auth / JWT / OAuth ──
PATTERNS[JWT_Token]='eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'
PATTERNS[OAuth_Token]='ya29\.[0-9A-Za-z\-_]+'
PATTERNS[Bearer_Token]='(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*'
PATTERNS[Basic_Auth_Header]='(?i)basic\s+[A-Za-z0-9+/]{20,}=*'
PATTERNS[Auth_In_URL]='https?://[^:@\s]+:[^:@\s]+@[^\s]+'
SEVERITY[JWT_Token]=HIGH; SEVERITY[OAuth_Token]=HIGH
SEVERITY[Bearer_Token]=HIGH; SEVERITY[Basic_Auth_Header]=HIGH
SEVERITY[Auth_In_URL]=HIGH

# ── Source Control & CI/CD ──
PATTERNS[GitHub_PAT]='ghp_[0-9A-Za-z]{36}'
PATTERNS[GitHub_OAuth]='gho_[0-9A-Za-z]{36}'
PATTERNS[GitHub_App_Token]='(ghu|ghs)_[0-9A-Za-z]{36}'
PATTERNS[GitLab_PAT]='glpat-[0-9a-zA-Z\-]{20}'
PATTERNS[GitLab_Runner]='GR1348941[0-9a-zA-Z\-_]{20}'
PATTERNS[BitBucket_Secret]='(?i)bitbucket.{0,30}[A-Za-z0-9]{32,}'
PATTERNS[CircleCI_Token]='(?i)circle.?ci.{0,10}["'"'"'][0-9a-f]{40}["'"'"']'
PATTERNS[Travis_Token]='(?i)travis.{0,10}["'"'"'][A-Za-z0-9]{22}["'"'"']'
PATTERNS[Jenkins_Token]='(?i)jenkins.{0,10}["'"'"'][A-Za-z0-9]{32,}["'"'"']'
SEVERITY[GitHub_PAT]=CRITICAL; SEVERITY[GitHub_OAuth]=CRITICAL
SEVERITY[GitHub_App_Token]=HIGH; SEVERITY[GitLab_PAT]=CRITICAL
SEVERITY[GitLab_Runner]=HIGH; SEVERITY[CircleCI_Token]=HIGH

# ── Communication ──
PATTERNS[Slack_Token]='xox[baprs]-([0-9a-zA-Z]{10,48})'
PATTERNS[Slack_Webhook]='https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+'
PATTERNS[Discord_Token]='[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}'
PATTERNS[Discord_Webhook]='https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+'
PATTERNS[Telegram_Bot_Token]='[0-9]{8,10}:[A-Za-z0-9_-]{35}'
PATTERNS[Twilio_SID]='AC[a-zA-Z0-9]{32}'
PATTERNS[Twilio_Auth_Token]='(?i)twilio.{0,20}["'"'"'][0-9a-f]{32}["'"'"']'
PATTERNS[SendGrid_Key]='SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}'
PATTERNS[Mailgun_Key]='key-[0-9a-zA-Z]{32}'
PATTERNS[Mailchimp_Key]='[0-9a-f]{32}-us[0-9]{1,2}'
PATTERNS[Mandrill_Key]='(?i)mandrill.{0,20}["'"'"'][A-Za-z0-9_-]{22}["'"'"']'
PATTERNS[Vonage_Key]='(?i)(nexmo|vonage).{0,20}["'"'"'][0-9a-f]{8,}["'"'"']'
SEVERITY[Slack_Token]=HIGH;     SEVERITY[Slack_Webhook]=HIGH
SEVERITY[Discord_Token]=HIGH;   SEVERITY[Discord_Webhook]=MEDIUM
SEVERITY[Telegram_Bot_Token]=MEDIUM; SEVERITY[Twilio_Auth_Token]=HIGH
SEVERITY[SendGrid_Key]=HIGH;    SEVERITY[Mailgun_Key]=HIGH

# ── Databases ──
PATTERNS[MongoDB_URI]='mongodb(\+srv)?://[^:]+:[^@]+@[^\s]+'
PATTERNS[PostgreSQL_URI]='postgres(ql)?://[^:]+:[^@]+@[^\s]+'
PATTERNS[MySQL_URI]='mysql://[^:]+:[^@]+@[^\s]+'
PATTERNS[Redis_URI]='redis://[^:]*:?[^@]*@[^\s]+'
PATTERNS[Elasticsearch_URI]='https?://[^:]+:[^@]+@[a-z0-9.-]+:9200'
PATTERNS[Supabase_Key]='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
PATTERNS[S3_Bucket_URL]='https?://[a-z0-9.-]+\.s3[.-][a-z0-9-]*\.amazonaws\.com'
SEVERITY[MongoDB_URI]=CRITICAL;     SEVERITY[PostgreSQL_URI]=CRITICAL
SEVERITY[MySQL_URI]=CRITICAL;        SEVERITY[Redis_URI]=HIGH
SEVERITY[Elasticsearch_URI]=CRITICAL;SEVERITY[Supabase_Key]=HIGH
SEVERITY[S3_Bucket_URL]=MEDIUM

# ── Social / Dev APIs ──
PATTERNS[Twitter_API_Key]='(?i)twitter.{0,30}["'"'"'][A-Za-z0-9]{25,}["'"'"']'
PATTERNS[Twitter_Bearer]='AAAAAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+%[A-Za-z0-9%]+'
PATTERNS[Facebook_Token]='EAACEdEose0cBA[0-9A-Za-z]+'
PATTERNS[YouTube_Key]='(?i)youtube.{0,20}["'"'"'][A-Za-z0-9_-]{35,}["'"'"']'
PATTERNS[HubSpot_Key]='(?i)(hubspot|hapikey).{0,20}["'"'"'][0-9a-f-]{36}["'"'"']'
PATTERNS[Mapbox_Token]='pk\.eyJ1[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
PATTERNS[HERE_Key]='(?i)here.{0,20}["'"'"'][A-Za-z0-9_-]{43}["'"'"']'
SEVERITY[Twitter_API_Key]=HIGH; SEVERITY[Facebook_Token]=HIGH
SEVERITY[HubSpot_Key]=MEDIUM;   SEVERITY[Mapbox_Token]=MEDIUM

# ── Crypto / Web3 ──
PATTERNS[ETH_Private_Key]='(?i)(private.?key|eth.?key).{0,20}["'"'"'][0-9a-fA-F]{64}["'"'"']'
PATTERNS[Crypto_Mnemonic]='(?i)(mnemonic|seed.?phrase).{0,30}([a-z]+\s){11}[a-z]+'
PATTERNS[Infura_Key]='(?i)infura.{0,20}["'"'"'][0-9a-f]{32}["'"'"']'
PATTERNS[Alchemy_Key]='(?i)alchemy.{0,20}["'"'"'][A-Za-z0-9_-]{32,}["'"'"']'
SEVERITY[ETH_Private_Key]=CRITICAL; SEVERITY[Crypto_Mnemonic]=CRITICAL
SEVERITY[Infura_Key]=HIGH;           SEVERITY[Alchemy_Key]=HIGH

# ── Keys / Certs ──
PATTERNS[RSA_Private_Key]='-----BEGIN RSA PRIVATE KEY-----'
PATTERNS[EC_Private_Key]='-----BEGIN EC PRIVATE KEY-----'
PATTERNS[OPENSSH_Key]='-----BEGIN OPENSSH PRIVATE KEY-----'
PATTERNS[PGP_Key]='-----BEGIN PGP PRIVATE KEY BLOCK-----'
PATTERNS[X509_Cert]='-----BEGIN CERTIFICATE-----'
SEVERITY[RSA_Private_Key]=CRITICAL; SEVERITY[EC_Private_Key]=CRITICAL
SEVERITY[OPENSSH_Key]=CRITICAL;      SEVERITY[PGP_Key]=CRITICAL

# ── Generic catch-all ──
PATTERNS[Generic_API_Key]='(?i)(api[-_]?key|apikey)["\s:=]{1,10}["'"'"'][A-Za-z0-9_\-]{20,}["'"'"']'
PATTERNS[Generic_Secret]='(?i)(secret|client_secret|client[-_]?secret)["\s:=]{1,10}["'"'"'][A-Za-z0-9_\-+/]{16,}["'"'"']'
PATTERNS[Generic_Password]='(?i)(password|passwd|pwd)["\s:=]{1,10}["'"'"'][^"'"'"'\s]{8,}["'"'"']'
PATTERNS[Generic_Token]='(?i)(token|access_token|refresh_token)["\s:=]{1,10}["'"'"'][A-Za-z0-9_\-.]{20,}["'"'"']'
PATTERNS[Internal_IP]='(10\.[0-9]{1,3}|172\.(1[6-9]|2[0-9]|3[01])|192\.168)\.[0-9]{1,3}\.[0-9]{1,3}'
PATTERNS[SMTP_URI]='smtp(s)?://[^:]+:[^@]+@[^\s]+'
PATTERNS[FTP_URI]='ftp(s)?://[^:]+:[^@]+@[^\s]+'
PATTERNS[SSN]='(?<!\d)[0-9]{3}-[0-9]{2}-[0-9]{4}(?!\d)'
PATTERNS[Debug_Endpoint]='(?i)(debug|backdoor|internal|test)["\s:=]{1,5}true'
PATTERNS[Admin_Route]='/admin[/"'"'"']'
PATTERNS[GraphQL_Route]='/graphql["'"'"'?]'
PATTERNS[Swagger_Route]='/(swagger|openapi|api-docs)[-/v0-9]'
PATTERNS[Hardcoded_User]='(?i)(username|user|login)["\s:=]{1,10}["'"'"']admin["'"'"']'
SEVERITY[Generic_API_Key]=HIGH;    SEVERITY[Generic_Secret]=HIGH
SEVERITY[Generic_Password]=HIGH;   SEVERITY[Generic_Token]=HIGH
SEVERITY[Internal_IP]=MEDIUM;      SEVERITY[SMTP_URI]=CRITICAL
SEVERITY[Debug_Endpoint]=MEDIUM;   SEVERITY[Admin_Route]=MEDIUM
SEVERITY[GraphQL_Route]=LOW;       SEVERITY[Swagger_Route]=MEDIUM
SEVERITY[Hardcoded_User]=HIGH;     SEVERITY[SSN]=CRITICAL

get_severity() { echo "${SEVERITY[$1]:-MEDIUM}"; }

# ══════════════════════════════════════════════════════════
#  MODULE 1 — JS FILE SCANNER
# ══════════════════════════════════════════════════════════
beautify_js() {
  local f="$1" out="${1%.js}_pretty.js"
  if command -v js-beautify &>/dev/null; then
    js-beautify --indent-size 2 "$f" > "$out" 2>/dev/null && echo "$out" && return
  fi
  echo "$f"
}

scan_patterns_in_file() {
  local filepath="$1" src_url="$2"
  local scan_file
  scan_file=$(beautify_js "$filepath")
  [[ -z "$scan_file" ]] && scan_file="$filepath"
  local fname
  fname=$(basename "$filepath")

  for pname in "${!PATTERNS[@]}"; do
    local regex="${PATTERNS[$pname]}"
    local sev
    sev=$(get_severity "$pname")

    while IFS=: read -r linenum rest; do
      local val
      val=$(echo "$rest" | grep -aoP "$regex" 2>/dev/null | head -1)
      [[ -z "$val" || ${#val} -lt 8 ]] && continue
      save_finding "$sev" "$pname" "$val" "$src_url" "$linenum"
    done < <(grep -nP "$regex" "$scan_file" 2>/dev/null | head -30)
  done

  # Sensitive comments
  grep -nP '(?i)(//|/\*|\*).{0,5}(password|secret|api.?key|token|credential|hack|bypass|todo.*(remove|delete|fix))' \
    "$scan_file" 2>/dev/null | head -10 | while IFS=: read -r ln rest; do
    save_finding "MEDIUM" "Sensitive_Comment" "$rest" "$src_url" "$ln" "false" "Manual review needed"
  done

  # Base64 encoded secrets (atob / raw)
  grep -oP '[A-Za-z0-9+/]{40,}={0,2}' "$scan_file" 2>/dev/null | head -20 | while read -r b64; do
    local decoded
    decoded=$(echo "$b64" | base64 -d 2>/dev/null | strings 2>/dev/null | head -3)
    echo "$decoded" | grep -qiP '(password|secret|key|token|aws|BEGIN|firebase)' || continue
    save_finding "HIGH" "Base64_Encoded_Secret" "$b64" "$src_url" "?" "false" \
      "Decoded hint: ${decoded:0:80}"
  done

  # process.env / REACT_APP_ exposure
  grep -nP 'process\.env\.[A-Z_]{4,}|REACT_APP_[A-Z_]+|window\.__env__|__ENV__' \
    "$scan_file" 2>/dev/null | head -10 | while IFS=: read -r ln rest; do
    save_finding "MEDIUM" "Env_Var_Exposure" "$rest" "$src_url" "$ln" "false" "Check if value hardcoded"
  done
}

# ══════════════════════════════════════════════════════════
#  MODULE 2 — IMAGE URL ANALYSIS  (gap fix in existing tools)
# ══════════════════════════════════════════════════════════
extract_image_urls_from_file() {
  grep -oP 'https?://[^\s"'"'"']+\.(png|jpg|jpeg|gif|webp|svg|bmp|ico)(\?[^\s"'"'"']*)?' \
    "$1" 2>/dev/null | sort -u
}

analyze_image_url() {
  local img_url="$1"
  local ext="${img_url##*.}"; ext="${ext%%\?*}"; ext="${ext,,}"
  local safe="${img_url//[^a-zA-Z0-9]/_}"
  local img_file="${IMG_DUMP}/${safe}.${ext}"

  http_fetch "$img_url" "$img_file" >/dev/null
  [[ ! -s "$img_file" ]] && return
  TOTAL_IMAGES=$((TOTAL_IMAGES + 1))
  log_verbose "Image downloaded: $img_url"

  # ── Check URL query params for secrets ──
  if echo "$img_url" | grep -qP '[?&](key|token|auth|secret|api|access)[=]'; then
    local qp
    qp=$(echo "$img_url" | grep -oP '[?&](key|token|auth|secret|api|access)=[^&\s"'"'"']+')
    save_finding "HIGH" "Image_URL_Secret_Param" "$qp" "$img_url" "URL" "false" \
      "Sensitive value in image request URL parameter"
  fi

  # ── EXIF metadata ──
  if command -v exiftool &>/dev/null; then
    exiftool "$img_file" 2>/dev/null | grep -iP '(api|key|token|secret|password|author|comment|copyright)' \
    | while IFS= read -r exline; do
      save_finding "HIGH" "Image_EXIF_Secret" "$exline" "$img_url" "EXIF" "false" ""
    done
  fi

  # ── strings — catches embedded tokens in binary ──
  if command -v strings &>/dev/null; then
    strings "$img_file" 2>/dev/null | grep -P '[A-Za-z0-9+/]{20,}|https?://' \
    | while read -r s; do
      for pname in "${!PATTERNS[@]}"; do
        echo "$s" | grep -qP "${PATTERNS[$pname]}" 2>/dev/null || continue
        val=$(echo "$s" | grep -oP "${PATTERNS[$pname]}" | head -1)
        save_finding "HIGH" "Image_Embedded_${pname}" "$val" "$img_url" "binary:strings" "false" \
          "Secret found in image binary data"
      done
    done
  fi

  # ── SVG: can contain <script>, JS, data URIs ──
  if [[ "$ext" == "svg" ]]; then
    grep -oP '(?i)(<script[^>]*>.*?</script>|href="[^"]+"|\bdata:[^"]+)' \
      "$img_file" 2>/dev/null | while read -r chunk; do
      for pname in "${!PATTERNS[@]}"; do
        echo "$chunk" | grep -qP "${PATTERNS[$pname]}" 2>/dev/null || continue
        val=$(echo "$chunk" | grep -oP "${PATTERNS[$pname]}" | head -1)
        save_finding "HIGH" "SVG_Script_${pname}" "$val" "$img_url" "SVG" "false" ""
      done
    done
  fi

  # ── binwalk: hidden files steganography ──
  if command -v binwalk &>/dev/null; then
    local bw_dir="${IMG_DUMP}/binwalk_${safe}"
    binwalk -e "$img_file" -C "$bw_dir" --run-as=root -q 2>/dev/null || true
    find "$bw_dir" -type f 2>/dev/null | while read -r extracted; do
      scan_patterns_in_file "$extracted" "${img_url} [binwalk extracted]"
    done
  fi
}

# ══════════════════════════════════════════════════════════
#  MODULE 3 — SOURCE MAP RECOVERY
# ══════════════════════════════════════════════════════════
process_sourcemap() {
  local js_url="$1" js_file="$2"
  local map_ref
  map_ref=$(grep -oP '//# sourceMappingURL=\K[^\s]+' "$js_file" 2>/dev/null | head -1)
  [[ -z "$map_ref" ]] && return

  # Resolve relative path
  local map_url="$map_ref"
  if [[ "$map_ref" != http* ]]; then
    local base
    base=$(echo "$js_url" | grep -oP 'https?://[^/]+')
    local path
    path=$(echo "$js_url" | grep -oP 'https?://[^/]+\K/[^?]+/' | head -1)
    map_url="${base}${path}${map_ref}"
  fi

  log "${CYAN}[SOURCEMAP]${NC} Downloading: $map_url"
  local mf="${MAP_DUMP}/$(echo "$map_url" | sed 's/[^a-zA-Z0-9]/_/g').map"
  http_fetch "$map_url" "$mf" >/dev/null
  [[ ! -s "$mf" ]] && return

  # Extract original source files via Python
  python3 - "$mf" "$map_url" "$MAP_DUMP" << 'PYEOF'
import json, sys, os, re

map_file, map_url, out_base = sys.argv[1], sys.argv[2], sys.argv[3]
safe_name = re.sub(r'[^a-zA-Z0-9]', '_', map_url)
extract_dir = os.path.join(out_base, f"src_{safe_name}")
os.makedirs(extract_dir, exist_ok=True)

try:
    with open(map_file, 'r', errors='replace') as f:
        data = json.load(f)
    sources = data.get('sources', [])
    contents = data.get('sourcesContent', [])
    print(f"[SOURCEMAP] {len(sources)} original files recovered from {map_url}")
    for i, src in enumerate(sources):
        safe = re.sub(r'[^a-zA-Z0-9._-]', '_', src)
        dest = os.path.join(extract_dir, safe)
        if i < len(contents) and contents[i]:
            with open(dest, 'w') as f:
                f.write(contents[i])
            print(f"  [+] {src}")
except Exception as e:
    print(f"[!] Sourcemap parse error: {e}")
PYEOF

  # Scan recovered source files
  local extract_dir="${MAP_DUMP}/src_$(echo "$map_url" | sed 's/[^a-zA-Z0-9]/_/g')"
  find "$extract_dir" -type f 2>/dev/null | while read -r sf; do
    log "${BCYAN}[SOURCEMAP-SCAN]${NC} Scanning recovered: $(basename "$sf")"
    scan_patterns_in_file "$sf" "${map_url} → $(basename "$sf")"
  done
}

# ══════════════════════════════════════════════════════════
#  MODULE 4 — API ENDPOINT DISCOVERY + CVE CHECKS
# ══════════════════════════════════════════════════════════
ENDPOINT_SIGS=(
  '/api/' '/api/v[0-9]' '/_api/' '/graphql' '/swagger' '/openapi'
  '/api-docs' '/admin' '/management' '/console' '/debug' '/test/'
  '/staging/' '/internal/' '/__debug__' '/phpinfo' '/.env'
  '/config.json' '/settings.json' '/appsettings.json' '/web.config'
  '/package.json' '/.git/config' '/wp-config.php' '/backup'
  '/export' '/upload' '/reset-password' '/oauth' '/token'
  '/users' '/accounts' '/login' '/auth'
  '169.254.169.254' 'metadata.google.internal'
)

extract_endpoints() {
  grep -oP '["'"'"'](\/[a-zA-Z0-9_\-\/\.]{3,})["'"'"']|(https?://[^\s"'"'"'<>]{10,})' \
    "$1" 2>/dev/null | tr -d '"'"'" | grep -P '^(/|https?://)' | sort -u
}

probe_endpoint() {
  local ep="$1" base="$2"
  local full="$ep"
  [[ "$ep" != http* ]] && full="${base}${ep}"
  echo "$full" >> "$ENDPOINTS_FILE"
  TOTAL_ENDPOINTS=$((TOTAL_ENDPOINTS + 1))

  local resp="${JSON_API_DUMP}/$(echo "$full" | md5sum | cut -c1-12).json"
  local code
  code=$(http_fetch "$full" "$resp")
  [[ ! -s "$resp" || "$code" == "000" ]] && return

  log_verbose "Probed $full → HTTP $code"

  if [[ "$code" =~ ^2 ]]; then
    # Scan response for secrets
    scan_patterns_in_file "$resp" "$full"
    check_api_cves "$resp" "$full"
  fi

  if [[ "$code" == "401" || "$code" == "403" ]]; then
    log "${BLUE}[AUTH-ENDPOINT]${NC} ${code}: $full"
    save_finding "LOW" "Auth_Protected_Endpoint" "$full" "$full" "-" "false" "HTTP $code"
  fi
}

check_api_cves() {
  local resp="$1" url="$2"

  # Unauth credential leak
  jq -e '.[] | select(has("password") or has("passwd") or has("token"))' \
    "$resp" &>/dev/null 2>&1 && \
    save_finding "CRITICAL" "Unauth_API_Credential_Leak" "$url" "$url" "-" "false" \
      "JSON response exposes password/token fields without authentication"

  # Mass data exposure
  local cnt
  cnt=$(jq '. | if type=="array" then length else 0 end' "$resp" 2>/dev/null || echo 0)
  [[ "$cnt" -gt 10 ]] && \
    save_finding "HIGH" "Mass_Data_Exposure" "$url" "$url" "-" "false" \
      "${cnt} records exposed without authentication"

  # IDOR: sequential numeric ID in path
  echo "$url" | grep -qP '/[0-9]+(/|$)' && \
    save_finding "MEDIUM" "Potential_IDOR" "$url" "$url" "-" "false" \
      "Numeric ID in URL — test adjacent IDs for IDOR"

  # Stack trace / debug info
  grep -qiP '(stack trace|traceback|exception|at [A-Za-z]+\.[A-Za-z]+\()' \
    "$resp" 2>/dev/null && \
    save_finding "MEDIUM" "Debug_Stack_Trace_Leak" "$url" "$url" "-" "false" \
      "Server returning debug stack trace — information disclosure"

  # GraphQL introspection
  if echo "$url" | grep -qi 'graphql'; then
    local gql_resp="${JSON_API_DUMP}/gql_$(date +%s%N | md5sum | cut -c1-8).json"
    curl -s -X POST "$url" \
      -H "Content-Type: application/json" \
      -d '{"query":"{__schema{types{name}}}"}' \
      -o "$gql_resp" --max-time "$TIMEOUT" 2>/dev/null || true
    grep -q '__schema' "$gql_resp" 2>/dev/null && \
      save_finding "HIGH" "GraphQL_Introspection_Enabled" "$url" "$url" "-" "false" \
        "Full schema introspection is publicly accessible — enumerate with InQL"
  fi

  # Swagger / OpenAPI exposed
  echo "$url" | grep -qiP '(swagger|openapi|api-docs)' && \
    save_finding "MEDIUM" "API_Spec_Exposed" "$url" "$url" "-" "false" \
      "API specification publicly accessible — full endpoint enumeration possible"
}

# ══════════════════════════════════════════════════════════
#  MODULE 5 — KEY VALIDATION
# ══════════════════════════════════════════════════════════
validate_key() {
  local type="$1" val="$2"
  local result="UNCHECKED"

  case "$type" in
    GCP_API_Key|Google_Maps_Key)
      local r
      r=$(curl -s --max-time 8 \
        "https://maps.googleapis.com/maps/api/geocode/json?address=test&key=${val}" 2>/dev/null)
      echo "$r" | grep -q '"OK"' && result="✅ VALID — ACTIVE KEY" || \
      echo "$r" | grep -q 'REQUEST_DENIED' && result="❌ DENIED/RESTRICTED"
      ;;
    Stripe_Secret_Live|Stripe_Secret_Test)
      local r
      r=$(curl -s --max-time 8 -u "${val}:" "https://api.stripe.com/v1/charges?limit=1" 2>/dev/null)
      echo "$r" | grep -q '"data"' && result="✅ VALID — STRIPE LIVE"
      ;;
    GitHub_PAT|GitHub_OAuth)
      local r
      r=$(curl -s --max-time 8 -H "Authorization: token ${val}" \
        "https://api.github.com/user" 2>/dev/null)
      local user; user=$(echo "$r" | grep -oP '"login":\s*"\K[^"]+')
      [[ -n "$user" ]] && result="✅ VALID — GitHub user: $user"
      ;;
    Slack_Token)
      local r
      r=$(curl -s --max-time 8 "https://slack.com/api/auth.test?token=${val}" 2>/dev/null)
      echo "$r" | grep -q '"ok":true' && result="✅ VALID — SLACK ACTIVE"
      ;;
    SendGrid_Key)
      local r
      r=$(curl -s --max-time 8 -H "Authorization: Bearer ${val}" \
        "https://api.sendgrid.com/v3/user/profile" 2>/dev/null)
      echo "$r" | grep -q '"email"' && result="✅ VALID — SENDGRID ACTIVE"
      ;;
    Telegram_Bot_Token)
      local r
      r=$(curl -s --max-time 8 "https://api.telegram.org/bot${val}/getMe" 2>/dev/null)
      local name; name=$(echo "$r" | grep -oP '"username":"\K[^"]+')
      [[ -n "$name" ]] && result="✅ VALID — Bot: @$name"
      ;;
    Shopify_AccessToken)
      result="⚠  Requires store domain to validate"
      ;;
  esac

  if [[ "$result" == *"✅"* ]]; then
    log "${BRED}${BOLD}[KEY-VALID] ${result} → ${val:0:30}...${NC}"
    # Update last finding notes in JSON
    local tmp="${REPORT_JSON}.tmp"
    jq --arg t "$type" --arg vl "$result" \
      '(.findings | map(if .type == $t then .validated = $vl else . end))' \
      "$REPORT_JSON" > "$tmp" 2>/dev/null && mv "$tmp" "$REPORT_JSON" || true
  else
    log_verbose "[VALIDATE] $type → $result"
  fi
}

# ══════════════════════════════════════════════════════════
#  MODULE 6 — DEEP CRAWL
# ══════════════════════════════════════════════════════════
deep_crawl() {
  local url="$1"
  log "${CYAN}[CRAWL]${NC} Extracting JS from: $url"
  local tmp="${TEMP_DIR}/page_$(echo "$url" | md5sum | cut -c1-8).html"
  http_fetch "$url" "$tmp" >/dev/null
  [[ ! -s "$tmp" ]] && return

  # Linked JS files
  grep -oP '(?<=src=")[^"]+\.js[^"]*|(?<=src='"'"')[^'"'"']+\.js[^'"'"']*' \
    "$tmp" 2>/dev/null | while read -r jspath; do
    local full="$jspath"
    [[ "$jspath" != http* ]] && full="$(echo "$url" | grep -oP 'https?://[^/]+')${jspath}"
    grep -qxF "$full" "$INPUT_FILE" 2>/dev/null || echo "$full" >> "$INPUT_FILE"
  done

  # Inline scripts
  python3 - "$tmp" "$url" "$JS_DUMP" << 'PYEOF'
import re, sys, os

html, url, dump = open(sys.argv[1], errors='replace').read(), sys.argv[2], sys.argv[3]
scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL|re.IGNORECASE)
safe = re.sub(r'[^a-zA-Z0-9]', '_', url)
for i, s in enumerate(scripts):
    if len(s.strip()) > 80:
        path = os.path.join(dump, f"inline_{safe}_{i}.js")
        open(path,'w').write(s)
        print(f"[INLINE-JS] Extracted script #{i} from {url}")
PYEOF
}

# ══════════════════════════════════════════════════════════
#  MODULE 7 — NUCLEI
# ══════════════════════════════════════════════════════════
run_nuclei() {
  command -v nuclei &>/dev/null || {
    log "${YELLOW}[!] Nuclei not installed. Skip. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest${NC}"
    return
  }
  [[ ! -s "$ENDPOINTS_FILE" ]] && { log "${DIM}[NUCLEI] No endpoints to scan.${NC}"; return; }

  log "${CYAN}[NUCLEI]${NC} Scanning ${ENDPOINTS_FILE} with exposure/secret/CVE templates..."
  local nout="${OUTPUT_DIR}/nuclei_results.txt"
  nuclei \
    -l "$ENDPOINTS_FILE" \
    -tags "exposure,token,api,secret,config,debug,disclosure,misconfig,cve,auth-bypass" \
    -severity "critical,high,medium" \
    -o "$nout" \
    -silent \
    -timeout "$TIMEOUT" \
    ${PROXY:+-proxy "$PROXY"} 2>/dev/null || true

  [[ -s "$nout" ]] && {
    log "${BGREEN}[NUCLEI]${NC} Results:"
    while IFS= read -r nl; do log "  ${MAGENTA}→${NC} $nl"; done < "$nout"
  } || log "${DIM}[NUCLEI] No findings.${NC}"
}

# ══════════════════════════════════════════════════════════
#  HTML REPORT
# ══════════════════════════════════════════════════════════
generate_report() {
  local total crit high med low
  total=$(jq '.findings|length' "$REPORT_JSON" 2>/dev/null || echo 0)
  crit=$(jq '[.findings[]|select(.severity=="CRITICAL")]|length' "$REPORT_JSON" 2>/dev/null || echo 0)
  high=$(jq '[.findings[]|select(.severity=="HIGH")]|length' "$REPORT_JSON" 2>/dev/null || echo 0)
  med=$(jq '[.findings[]|select(.severity=="MEDIUM")]|length' "$REPORT_JSON" 2>/dev/null || echo 0)
  low=$(jq '[.findings[]|select(.severity=="LOW")]|length' "$REPORT_JSON" 2>/dev/null || echo 0)

  cat > "$REPORT_HTML" << HTMLEOF
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>JSXRay Report — ${TIMESTAMP}</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;600;700&family=Inter:wght@300;400;600;700&display=swap');
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0e17;--bg2:#0f1624;--bg3:#161f30;
  --border:#1e2d45;--accent:#00d4ff;--accent2:#7c3aed;
  --crit:#ff4444;--high:#ff8c00;--med:#ffd700;--low:#00c851;
  --text:#c8d6e5;--text2:#8096b0;--white:#f0f6ff
}
body{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}
header{
  background:linear-gradient(135deg,#0a0e17 0%,#0d1526 50%,#0a0e17 100%);
  border-bottom:1px solid var(--border);padding:32px 40px;
  position:relative;overflow:hidden
}
header::before{
  content:'';position:absolute;top:-50%;left:-10%;width:500px;height:500px;
  background:radial-gradient(circle,rgba(0,212,255,0.06) 0%,transparent 70%);
  pointer-events:none
}
.logo{font-family:'JetBrains Mono',monospace;font-size:2.2em;font-weight:700;
  background:linear-gradient(135deg,#00d4ff,#7c3aed);
  -webkit-background-clip:text;-webkit-text-fill-color:transparent;
  background-clip:text;letter-spacing:2px}
.tagline{color:var(--text2);font-size:.9em;margin-top:6px}
.meta-row{display:flex;gap:24px;margin-top:16px;flex-wrap:wrap}
.meta-item{color:var(--text2);font-size:.82em;font-family:'JetBrains Mono',monospace}
.meta-item span{color:var(--accent)}
.warning-bar{
  background:linear-gradient(90deg,rgba(255,140,0,.12),rgba(255,68,68,.08));
  border:1px solid rgba(255,140,0,.3);border-radius:8px;
  padding:12px 20px;margin:24px 40px 0;color:#ffa040;
  font-size:.85em;display:flex;align-items:center;gap:10px
}
.stats{display:flex;gap:16px;padding:24px 40px;flex-wrap:wrap}
.stat{
  flex:1;min-width:120px;background:var(--bg2);border:1px solid var(--border);
  border-radius:12px;padding:20px;text-align:center;
  transition:transform .2s;cursor:default
}
.stat:hover{transform:translateY(-2px)}
.stat .num{font-size:2.4em;font-weight:700;font-family:'JetBrains Mono',monospace}
.stat .lbl{font-size:.78em;color:var(--text2);margin-top:4px;letter-spacing:1px;text-transform:uppercase}
.stat.crit .num{color:var(--crit)}
.stat.high .num{color:var(--high)}
.stat.med  .num{color:var(--med)}
.stat.low  .num{color:var(--low)}
.stat.tot  .num{color:var(--accent)}
.stat.crit{border-color:rgba(255,68,68,.3)}
.stat.high{border-color:rgba(255,140,0,.3)}
.stat.med {border-color:rgba(255,215,0,.3)}
.stat.low {border-color:rgba(0,200,81,.3)}
.stat.tot {border-color:rgba(0,212,255,.3)}
.section{padding:0 40px 32px}
h2{font-size:1em;font-weight:600;letter-spacing:2px;text-transform:uppercase;
  color:var(--accent);margin-bottom:16px;font-family:'JetBrains Mono',monospace}
.filter-bar{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}
.filter-btn{
  padding:6px 14px;border-radius:20px;border:1px solid var(--border);
  background:var(--bg2);color:var(--text2);font-size:.8em;cursor:pointer;
  transition:all .2s;font-family:'JetBrains Mono',monospace
}
.filter-btn:hover,.filter-btn.active{background:var(--accent);color:#000;border-color:var(--accent)}
table{width:100%;border-collapse:collapse;font-size:.82em}
th{background:var(--bg3);color:var(--accent);padding:12px 14px;text-align:left;
   border-bottom:2px solid var(--border);font-family:'JetBrains Mono',monospace;
   font-size:.78em;letter-spacing:1px;text-transform:uppercase;white-space:nowrap}
td{padding:10px 14px;border-bottom:1px solid var(--border);vertical-align:top;
   word-break:break-all;max-width:300px}
tr:hover td{background:var(--bg3)}
.badge{display:inline-block;padding:3px 10px;border-radius:4px;font-size:.75em;
  font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:.5px}
.badge-CRITICAL{background:rgba(255,68,68,.15);color:#ff6b6b;border:1px solid rgba(255,68,68,.4)}
.badge-HIGH{background:rgba(255,140,0,.15);color:#ffa040;border:1px solid rgba(255,140,0,.4)}
.badge-MEDIUM{background:rgba(255,215,0,.15);color:#ffd740;border:1px solid rgba(255,215,0,.4)}
.badge-LOW{background:rgba(0,200,81,.12);color:#00e676;border:1px solid rgba(0,200,81,.3)}
.val-cell{font-family:'JetBrains Mono',monospace;font-size:.78em;
  background:var(--bg3);padding:4px 8px;border-radius:4px;
  color:#64d8ff;display:inline-block;max-width:280px;
  overflow:hidden;text-overflow:ellipsis;white-space:nowrap;
  cursor:help}
.src-cell{font-family:'JetBrains Mono',monospace;font-size:.72em;color:var(--text2)}
.note-cell{font-size:.78em;color:var(--text2);font-style:italic}
.valid-cell{font-size:.75em}
.footer{text-align:center;padding:32px;color:var(--text2);font-size:.8em;
  border-top:1px solid var(--border)}
.footer a{color:var(--accent);text-decoration:none}
.copy-btn{background:none;border:1px solid var(--border);color:var(--text2);
  padding:2px 6px;border-radius:3px;font-size:.7em;cursor:pointer;margin-left:4px}
.copy-btn:hover{border-color:var(--accent);color:var(--accent)}
.empty{text-align:center;padding:40px;color:var(--text2)}
.progress-bar{height:3px;background:linear-gradient(90deg,var(--accent),var(--accent2));
  position:fixed;top:0;left:0;z-index:999;transition:width .3s}
</style>
</head>
<body>
<div class="progress-bar" id="pbar" style="width:0"></div>
<header>
  <div class="logo">⚡ JSXRay</div>
  <div class="tagline">Advanced JavaScript Secret & Vulnerability Scanner</div>
  <div class="meta-row">
    <div class="meta-item">Scan: <span>${TIMESTAMP}</span></div>
    <div class="meta-item">Files: <span>${TOTAL_FILES}</span></div>
    <div class="meta-item">Images: <span>${TOTAL_IMAGES}</span></div>
    <div class="meta-item">Endpoints: <span>${TOTAL_ENDPOINTS}</span></div>
    <div class="meta-item">Author: <span>${AUTHOR}</span></div>
    <div class="meta-item">v<span>${VERSION}</span></div>
  </div>
</header>

<div class="warning-bar">⚠ <strong>CONFIDENTIAL</strong> — Authorized security testing only. Handle per responsible disclosure policy.</div>

<div class="stats">
  <div class="stat crit"><div class="num">${crit}</div><div class="lbl">Critical</div></div>
  <div class="stat high"><div class="num">${high}</div><div class="lbl">High</div></div>
  <div class="stat med"><div class="num">${med}</div><div class="lbl">Medium</div></div>
  <div class="stat low"><div class="num">${low}</div><div class="lbl">Low</div></div>
  <div class="stat tot"><div class="num">${total}</div><div class="lbl">Total</div></div>
</div>

<div class="section">
  <h2>Findings</h2>
  <div class="filter-bar">
    <button class="filter-btn active" onclick="filter('ALL')">All (${total})</button>
    <button class="filter-btn" onclick="filter('CRITICAL')" style="color:#ff6b6b">Critical (${crit})</button>
    <button class="filter-btn" onclick="filter('HIGH')" style="color:#ffa040">High (${high})</button>
    <button class="filter-btn" onclick="filter('MEDIUM')" style="color:#ffd740">Medium (${med})</button>
    <button class="filter-btn" onclick="filter('LOW')" style="color:#00e676">Low (${low})</button>
  </div>
  <table id="findings-table">
    <thead>
      <tr>
        <th>Severity</th>
        <th>Type</th>
        <th>Value</th>
        <th>Source</th>
        <th>Line</th>
        <th>Validated</th>
        <th>Notes</th>
      </tr>
    </thead>
    <tbody id="findings-body">
HTMLEOF

  # Append sorted rows
  jq -r '
    .findings |
    sort_by(
      if .severity=="CRITICAL" then 0
      elif .severity=="HIGH" then 1
      elif .severity=="MEDIUM" then 2
      else 3 end
    )[] |
    "<tr data-sev=\"\(.severity)\">
      <td><span class=\"badge badge-\(.severity)\">\(.severity)</span></td>
      <td style=\"font-family:JetBrains Mono,monospace;font-size:.8em\">\(.type)</td>
      <td><span class=\"val-cell\" title=\"\(.value)\">\(.value | .[0:90])</span>
          <button class=\"copy-btn\" onclick=\"navigator.clipboard.writeText(this.dataset.val)\" data-val=\"\(.value)\">copy</button></td>
      <td class=\"src-cell\">\(.source | .[0:70])</td>
      <td style=\"font-family:JetBrains Mono,monospace;font-size:.75em\">\(.line)</td>
      <td class=\"valid-cell\">\(.validated)</td>
      <td class=\"note-cell\">\(.notes | .[0:80])</td>
    </tr>"
  ' "$REPORT_JSON" 2>/dev/null >> "$REPORT_HTML"

  cat >> "$REPORT_HTML" << 'HTMLEOF'
    </tbody>
  </table>
</div>

<div class="footer">
  Generated by <a href="https://github.com/harikamma/JSXRay">JSXRay</a> v1.0.0
  &nbsp;|&nbsp; By <strong>Hari Kamma</strong>
  &nbsp;|&nbsp; For authorized security testing only
</div>

<script>
function filter(sev){
  document.querySelectorAll('.filter-btn').forEach(b=>b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findings-body tr').forEach(row=>{
    row.style.display = (sev==='ALL' || row.dataset.sev===sev) ? '' : 'none';
  });
}
window.onscroll=()=>{
  const p=window.scrollY/(document.body.scrollHeight-window.innerHeight)*100;
  document.getElementById('pbar').style.width=p+'%';
};
</script>
</body>
</html>
HTMLEOF
  log "${BGREEN}[✓] HTML report → ${REPORT_HTML}${NC}"
}

# ══════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════
print_summary() {
  echo ""
  log "${CYAN}${BOLD}╔══════════════════════════════════════════════╗${NC}"
  log "${CYAN}${BOLD}║           JSXRay — SCAN COMPLETE             ║${NC}"
  log "${CYAN}${BOLD}╠══════════════════════════════════════════════╣${NC}"
  log "${CYAN}║${NC}  JS Files Scanned   : ${WHITE}${BOLD}${TOTAL_FILES}${NC}"
  log "${CYAN}║${NC}  Images Analyzed    : ${WHITE}${BOLD}${TOTAL_IMAGES}${NC}"
  log "${CYAN}║${NC}  Endpoints Found    : ${WHITE}${BOLD}${TOTAL_ENDPOINTS}${NC}"
  log "${CYAN}║${NC}  Total Findings     : ${BRED}${BOLD}${TOTAL_SECRETS}${NC}"
  log "${CYAN}${BOLD}╠══════════════════════════════════════════════╣${NC}"
  log "${CYAN}║${NC}  Output Dir         : ${BGREEN}${OUTPUT_DIR}${NC}"
  log "${CYAN}║${NC}  HTML Report        : ${BGREEN}${REPORT_HTML}${NC}"
  log "${CYAN}║${NC}  JSON Report        : ${BGREEN}${REPORT_JSON}${NC}"
  log "${CYAN}║${NC}  CSV Report         : ${BGREEN}${REPORT_CSV}${NC}"
  log "${CYAN}${BOLD}╚══════════════════════════════════════════════╝${NC}"
  echo ""
  log "${DIM}⚠  Perform testing only on systems you have written authorization for.${NC}"
  log "${DIM}   Report findings responsibly. — ${AUTHOR}${NC}"
  echo ""
}

# ══════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════
main() {
  parse_args "$@"
  banner
  setup
  check_deps

  [[ ! -f "$INPUT_FILE" ]] && {
    log "${RED}[!] Input file not found: ${INPUT_FILE}${NC}"
    log "${YELLOW}[*] Create ${INPUT_FILE} with one URL per line, or use -i <file>${NC}"
    exit 1
  }

  local total_urls
  total_urls=$(grep -vc '^\s*#\|^\s*$' "$INPUT_FILE" 2>/dev/null || echo 0)
  log "${CYAN}[*] Loaded ${WHITE}${total_urls}${CYAN} URLs | Threads: ${WHITE}${THREADS}${CYAN} | Timeout: ${WHITE}${TIMEOUT}s${NC}"
  log "${CYAN}[*] Modules: validate=${WHITE}${VALIDATE_KEYS}${CYAN} images=${WHITE}${SCAN_IMAGES}${CYAN} sourcemaps=${WHITE}${EXTRACT_SOURCEMAPS}${CYAN} api=${WHITE}${SCAN_JSON_API}${CYAN} nuclei=${WHITE}${NUCLEI_SCAN}${NC}"
  echo ""

  # ── Deep crawl first (adds more URLs to input) ──
  if [[ "$DEEP_CRAWL" == true ]]; then
    log "${CYAN}[CRAWL]${NC} Deep crawl mode — extracting JS from HTML pages..."
    while IFS= read -r url; do
      [[ "$url" =~ ^#|^$ || -z "$url" ]] && continue
      echo "$url" | grep -qiP '\.(js|json|map)(\?|$)' || deep_crawl "$url"
    done < "$INPUT_FILE"
    log "${GREEN}[✓] Deep crawl complete. Updated URL list.${NC}"
    echo ""
  fi

  # ── Main loop ──
  while IFS= read -r url; do
    [[ "$url" =~ ^#|^$ || -z "$url" ]] && continue

    log "${YELLOW}[→]${NC} ${DIM}${url}${NC}"
    local ext="js"
    echo "$url" | grep -qi '\.json' && ext="json"
    echo "$url" | grep -qi '\.map'  && ext="map"
    local outfile="${JS_DUMP}/$(echo "$url" | md5sum | cut -c1-12).${ext}"

    local code
    code=$(http_fetch "$url" "$outfile")
    if [[ ! -s "$outfile" ]]; then
      log "${RED}  [-] Failed (HTTP ${code})${NC}"; continue
    fi
    TOTAL_FILES=$((TOTAL_FILES + 1))
    log "${GREEN}  [✓] HTTP ${code}${NC}"

    # Pattern scan
    scan_patterns_in_file "$outfile" "$url"

    # Key validation
    if [[ "$VALIDATE_KEYS" == true ]]; then
      for pname in GCP_API_Key Stripe_Secret_Live Stripe_Secret_Test \
                   GitHub_PAT GitHub_OAuth Slack_Token SendGrid_Key Telegram_Bot_Token; do
        local regex="${PATTERNS[$pname]}"
        local found_val
        found_val=$(grep -oP "$regex" "$outfile" 2>/dev/null | head -1)
        [[ -n "$found_val" ]] && validate_key "$pname" "$found_val"
      done
    fi

    # Source maps
    [[ "$EXTRACT_SOURCEMAPS" == true ]] && process_sourcemap "$url" "$outfile"

    # Image analysis
    if [[ "$SCAN_IMAGES" == true ]]; then
      while IFS= read -r img_url; do
        [[ -z "$img_url" ]] && continue
        log "${BLUE}  [IMG]${NC} ${DIM}${img_url}${NC}"
        analyze_image_url "$img_url"
      done < <(extract_image_urls_from_file "$outfile")
    fi

    # API endpoint probe
    if [[ "$SCAN_JSON_API" == true ]]; then
      local base
      base=$(echo "$url" | grep -oP 'https?://[^/]+')
      while IFS= read -r ep; do
        [[ -z "$ep" ]] && continue
        local probe=false
        for sig in "${ENDPOINT_SIGS[@]}"; do
          echo "$ep" | grep -qP "$sig" && probe=true && break
        done
        [[ "$probe" == true ]] && probe_endpoint "$ep" "$base"
      done < <(extract_endpoints "$outfile")
    fi

    echo ""
  done < "$INPUT_FILE"

  # ── Nuclei ──
  [[ "$NUCLEI_SCAN" == true ]] && run_nuclei

  # ── Reports ──
  log "${CYAN}[*] Generating reports...${NC}"
  generate_report
  print_summary
}

main "$@"
