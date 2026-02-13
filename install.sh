#!/usr/bin/env bash
# Copyright (c) 2026 z3r0_ru135
###############################################################################
# install.sh — z3r0-toolkit Dependency Installer
# Installs all required tools for the bug bounty automation toolkit
# Run inside WSL/Linux: chmod +x install.sh && ./install.sh
###############################################################################
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { echo -e "${CYAN}[*]${NC} $*"; }
log_ok()    { echo -e "${GREEN}[✓]${NC} $*"; }
log_warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
log_err()   { echo -e "${RED}[✗]${NC} $*"; }

echo -e "${MAGENTA}${BOLD}"
echo "╔══════════════════════════════════════════════════════════╗"
echo "║           z3r0-toolkit • DEPENDENCY INSTALLER            ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ── System packages ──
log_info "Updating package lists..."
sudo apt-get update -qq

log_info "Installing system dependencies..."
sudo apt-get install -y -qq \
    curl wget git jq bc unzip \
    dnsutils libpcap-dev \
    python3 python3-pip \
    2>/dev/null

log_ok "System packages installed"

# ── Go (required for most tools) ──
GO_VERSION="1.22.5"
if command -v go &>/dev/null; then
    log_ok "Go already installed: $(go version)"
else
    log_info "Installing Go ${GO_VERSION}..."
    wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -O /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    rm /tmp/go.tar.gz
    log_ok "Go ${GO_VERSION} installed"
fi

# Set up Go paths
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin
if ! grep -q 'go/bin' ~/.bashrc 2>/dev/null; then
    echo '' >> ~/.bashrc
    echo '# Go paths (z3r0-toolkit)' >> ~/.bashrc
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
fi

mkdir -p "$HOME/go/bin"

# ── Install Go tools ──
declare -A GO_TOOLS=(
    ["subfinder"]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    ["dnsx"]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    ["httpx"]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    ["katana"]="github.com/projectdiscovery/katana/cmd/katana@latest"
    ["nuclei"]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    ["waybackurls"]="github.com/tomnomnom/waybackurls@latest"
    ["assetfinder"]="github.com/tomnomnom/assetfinder@latest"
    ["anew"]="github.com/tomnomnom/anew@latest"
    ["gau"]="github.com/lc/gau/v2/cmd/gau@latest"
)

for tool in "${!GO_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        log_ok "$tool already installed"
    else
        log_info "Installing $tool..."
        go install "${GO_TOOLS[$tool]}" 2>/dev/null && \
            log_ok "$tool installed" || \
            log_warn "$tool failed — install manually: go install ${GO_TOOLS[$tool]}"
    fi
done

# ── Amass ──
if command -v amass &>/dev/null; then
    log_ok "amass already installed"
else
    log_info "Installing amass..."
    go install github.com/owasp-amass/amass/v4/...@master 2>/dev/null && \
        log_ok "amass installed" || \
        log_warn "amass failed — try: sudo snap install amass"
fi

# ── Make toolkit scripts executable ──
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
chmod +x "$SCRIPT_DIR"/*.sh 2>/dev/null || true
log_ok "Toolkit scripts marked executable"

# ── Verification ──
echo ""
echo -e "${BOLD}━━━ Installation Summary ━━━${NC}"
echo ""

TOOLS=(subfinder amass assetfinder dnsx httpx waybackurls gau katana nuclei anew jq curl bc)
missing=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo -e "  ${GREEN}✓${NC} $tool"
    else
        echo -e "  ${RED}✗${NC} $tool ${YELLOW}(missing)${NC}"
        missing=$((missing + 1))
    fi
done

echo ""
if [[ $missing -eq 0 ]]; then
    echo -e "${GREEN}${BOLD}All tools installed! You're ready to go.${NC}"
else
    echo -e "${YELLOW}${BOLD}$missing tool(s) missing — toolkit will still work with reduced functionality.${NC}"
fi

echo ""
echo -e "${BOLD}Quick start:${NC}"
echo -e "  ${CYAN}./08-pipeline.sh -d target.com${NC}"
echo ""
