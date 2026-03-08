#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════
#  JSXRay v2.0 — One-Click Installer
#  Author: Hari Kamma | github.com/Mr-White1/VenomJS
# ══════════════════════════════════════════════════════════
set -euo pipefail

CY='\033[1;36m'; GN='\033[1;32m'; YL='\033[1;33m'; RD='\033[1;31m'; NC='\033[0m'

print_banner() {
echo -e "${CY}"
cat << 'B'
   ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
   ██║╚════██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
   ██║    ██╔╝ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
   ██║   ██╔╝  ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
   ██║   ██║  ██╔╝ ██╗██║  ██║██║  ██║   ██║
   ╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
          v2.0  Installer  |  Hari Kamma
B
echo -e "${NC}"
}

OK() { echo -e "  ${GN}[✓]${NC} $1"; }
WN() { echo -e "  ${YL}[~]${NC} $1"; }
ER() { echo -e "  ${RD}[!]${NC} $1"; }
HD() { echo -e "\n${CY}[$1]${NC}"; }

print_banner
OS=$(uname -s)
echo -e "  ${CY}[*]${NC} OS detected: ${YL}${OS}${NC}"

# ── 1. System packages ──────────────────────────────────
HD "1/6 System dependencies"
if [[ "$OS" == "Linux" ]]; then
    if command -v apt-get &>/dev/null; then
        sudo apt-get update -qq 2>/dev/null
        sudo apt-get install -y \
            python3 python3-pip curl wget git jq binutils \
            libimage-exiftool-perl steghide ruby-full 2>/dev/null || true
        OK "apt packages installed"
    elif command -v yum &>/dev/null; then
        sudo yum install -y python3 python3-pip curl wget git jq perl-Image-ExifTool binutils 2>/dev/null || true
        OK "yum packages installed"
    elif command -v pacman &>/dev/null; then
        sudo pacman -S --noconfirm python python-pip curl wget git jq perl-image-exiftool 2>/dev/null || true
        OK "pacman packages installed"
    fi
elif [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew &>/dev/null; then
        WN "Installing Homebrew..."
        /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install python3 jq exiftool wget git steghide 2>/dev/null || true
    OK "brew packages installed"
fi

# ── 2. Python packages ──────────────────────────────────
HD "2/6 Python packages"
pip3 install --break-system-packages requests Pillow jsbeautifier playwright 2>/dev/null || \
pip3 install requests Pillow jsbeautifier playwright 2>/dev/null || \
pip install requests Pillow jsbeautifier playwright 2>/dev/null || true
OK "Python packages: requests Pillow jsbeautifier playwright"

# ── 3. Playwright Chromium ──────────────────────────────
HD "3/6 Playwright Chromium browser"
if python3 -m playwright install chromium 2>/dev/null; then
    OK "Chromium browser installed (--browser mode enabled)"
else
    WN "Chromium install failed — --browser mode will be disabled"
    WN "Try manually: python3 -m playwright install chromium"
fi

# ── 4. zsteg (PNG steganography) ────────────────────────
HD "4/6 zsteg (PNG stego tool)"
if command -v gem &>/dev/null; then
    gem install zsteg 2>/dev/null && OK "zsteg installed" || WN "zsteg install failed (optional)"
else
    WN "Ruby gems not found — zsteg skipped (optional)"
fi

# ── 5. Nuclei ───────────────────────────────────────────
HD "5/6 Nuclei vulnerability scanner"
if command -v go &>/dev/null; then
    GO_BIN=$(go env GOPATH)/bin
    export PATH="$PATH:$GO_BIN"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null && \
        OK "Nuclei installed" || WN "Nuclei install failed"
    nuclei -update-templates -silent 2>/dev/null || true
    OK "Nuclei templates updated"
else
    WN "Go not found — Nuclei skipped"
    WN "Install Go from: https://go.dev/dl/"
    WN "Then: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
fi

# ── 6. Finalize ─────────────────────────────────────────
HD "6/6 Permissions & setup"
chmod +x jsxray.py install.sh

# Global symlink
sudo ln -sf "$(pwd)/jsxray.py" /usr/local/bin/jsxray 2>/dev/null && \
    OK "Symlink: jsxray → /usr/local/bin/jsxray" || \
    WN "Symlink failed — use: python3 jsxray.py"

# Create sample urls.txt
if [[ ! -f "urls.txt" ]]; then
cat > urls.txt << 'SAMPLE'
# JSXRay v2.0 — URL Input File
# Add one target URL per line | Lines starting with # are ignored
#
# === JS Files (direct) ===
# https://target.com/static/js/main.chunk.js
# https://target.com/static/js/vendors~main.chunk.js
# https://target.com/assets/app.js
#
# === Pages (use with --browser to extract + scan all JS & images) ===
# https://target.com/
# https://app.target.com/dashboard
#
# === API endpoints ===
# https://target.com/api/config
# https://target.com/api/v1/settings
SAMPLE
    OK "Created sample urls.txt"
fi

echo ""
echo -e "${GN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GN}║          JSXRay v2.0 — Ready to fire! ⚡              ║${NC}"
echo -e "${GN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GN}║${NC}                                                      ${GN}║${NC}"
echo -e "${GN}║${NC}  Quick scan:                                         ${GN}║${NC}"
echo -e "${GN}║${NC}    python3 jsxray.py -i urls.txt                     ${GN}║${NC}"
echo -e "${GN}║${NC}                                                      ${GN}║${NC}"
echo -e "${GN}║${NC}  Full scan (all modules):                            ${GN}║${NC}"
echo -e "${GN}║${NC}    python3 jsxray.py -i urls.txt --all               ${GN}║${NC}"
echo -e "${GN}║${NC}                                                      ${GN}║${NC}"
echo -e "${GN}║${NC}  Browser + image analysis:                          ${GN}║${NC}"
echo -e "${GN}║${NC}    python3 jsxray.py -i urls.txt --browser \\         ${GN}║${NC}"
echo -e "${GN}║${NC}      --scan-images --validate                        ${GN}║${NC}"
echo -e "${GN}║${NC}                                                      ${GN}║${NC}"
echo -e "${GN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  ${YL}⚠  Authorized security testing only — Hari Kamma${NC}"
