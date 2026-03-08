#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════
#  JSXRay — Installer
#  Author: Hari Kamma | https://github.com/harikamma/JSXRay
# ═══════════════════════════════════════════════════════════

set -euo pipefail

C='\033[1;36m'; G='\033[1;32m'; Y='\033[1;33m'; R='\033[1;31m'; N='\033[0m'

echo -e "${C}"
cat << 'BANNER'
  ██╗███████╗██╗  ██╗██████╗  █████╗ ██╗   ██╗
  ██║╚════██║╚██╗██╔╝██╔══██╗██╔══██╗╚██╗ ██╔╝
  ██║    ██╔╝ ╚███╔╝ ██████╔╝███████║ ╚████╔╝
  ██║   ██╔╝  ██╔██╗ ██╔══██╗██╔══██║  ╚██╔╝
  ██║   ██║  ██╔╝ ██╗██║  ██║██║  ██║   ██║
  ╚═╝   ╚═╝  ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝
                            Installer
BANNER
echo -e "${N}"

OS=$(uname -s)
echo -e "${C}[*] Detected OS: ${Y}${OS}${N}"

install_core() {
  echo -e "${C}[*] Installing core dependencies...${N}"
  if [[ "$OS" == "Linux" ]]; then
    if command -v apt &>/dev/null; then
      sudo apt update -qq
      sudo apt install -y curl grep gawk python3 python3-pip jq libimage-exiftool-perl binutils
    elif command -v yum &>/dev/null; then
      sudo yum install -y curl grep gawk python3 python3-pip jq perl-Image-ExifTool binutils
    elif command -v pacman &>/dev/null; then
      sudo pacman -Sy --noconfirm curl grep gawk python python-pip jq perl-image-exiftool binutils
    fi
  elif [[ "$OS" == "Darwin" ]]; then
    if ! command -v brew &>/dev/null; then
      echo -e "${Y}[*] Installing Homebrew...${N}"
      /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    fi
    brew install curl gawk python3 jq exiftool binutils
  fi
  echo -e "${G}[✓] Core dependencies installed${N}"
}

install_optional() {
  echo -e "${C}[*] Installing optional dependencies...${N}"

  # js-beautify
  if command -v npm &>/dev/null; then
    npm install -g js-beautify 2>/dev/null && echo -e "${G}  [✓] js-beautify${N}" \
      || echo -e "${Y}  [~] js-beautify install skipped${N}"
  fi

  # binwalk
  if [[ "$OS" == "Linux" ]]; then
    sudo apt install -y binwalk 2>/dev/null && echo -e "${G}  [✓] binwalk${N}" \
      || echo -e "${Y}  [~] binwalk not available${N}"
  fi

  # strings (usually in binutils)
  command -v strings &>/dev/null && echo -e "${G}  [✓] strings (binutils)${N}"

  # nuclei
  if command -v go &>/dev/null; then
    echo -e "${C}  [*] Installing Nuclei...${N}"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null \
      && echo -e "${G}  [✓] Nuclei installed${N}" \
      || echo -e "${Y}  [~] Nuclei install failed (check Go PATH)${N}"
  else
    echo -e "${Y}  [~] Go not found — Nuclei skipped. Install Go first: https://go.dev/dl/${N}"
  fi

  echo -e "${G}[✓] Optional dependencies done${N}"
}

make_executable() {
  chmod +x jsxray.sh jsxray_analyze.py install.sh
  echo -e "${G}[✓] Made executable${N}"
}

create_sample_input() {
  if [[ ! -f "urls.txt" ]]; then
    cat > urls.txt << 'EOF'
# JSXRay — URL Input File
# Add one URL per line (JS files, JSON endpoints, or pages for --deep-crawl)
# Lines starting with # are ignored
#
# Examples:
# https://target.com/static/js/main.chunk.js
# https://target.com/static/js/vendors~main.chunk.js
# https://target.com/api/config
EOF
    echo -e "${G}[✓] Created sample urls.txt${N}"
  fi
}

symlink_global() {
  local INSTALL_DIR="/usr/local/bin"
  if [[ -w "$INSTALL_DIR" ]] || sudo -n true 2>/dev/null; then
    sudo ln -sf "$(pwd)/jsxray.sh" "$INSTALL_DIR/jsxray" 2>/dev/null && \
      echo -e "${G}[✓] jsxray available globally as 'jsxray'${N}" || true
  fi
}

main() {
  echo -e "${C}[1/5] Installing core dependencies...${N}"
  install_core

  echo -e "${C}[2/5] Installing optional dependencies...${N}"
  install_optional

  echo -e "${C}[3/5] Setting permissions...${N}"
  make_executable

  echo -e "${C}[4/5] Creating sample input...${N}"
  create_sample_input

  echo -e "${C}[5/5] Creating global symlink...${N}"
  symlink_global

  echo ""
  echo -e "${G}╔═══════════════════════════════════════════╗${N}"
  echo -e "${G}║       JSXRay installed successfully!       ║${N}"
  echo -e "${G}╠═══════════════════════════════════════════╣${N}"
  echo -e "${G}║${N}  Quick start:                              ${G}║${N}"
  echo -e "${G}║${N}    ./jsxray.sh --help                      ${G}║${N}"
  echo -e "${G}║${N}    ./jsxray.sh -i urls.txt                 ${G}║${N}"
  echo -e "${G}║${N}    ./jsxray.sh -i urls.txt --all           ${G}║${N}"
  echo -e "${G}╚═══════════════════════════════════════════╝${N}"
  echo ""
  echo -e "  ${Y}⚠  Authorized security testing only.${N}"
  echo -e "  ${Y}   Unauthorized use is illegal.${N}"
}

main "$@"
