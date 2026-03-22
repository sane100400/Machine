#!/usr/bin/env bash
# Machine — CTF Tool Setup
# Ubuntu 24.04 LTS (WSL2)

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
info() { echo -e "${CYAN}[>>]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }
err()  { echo -e "${RED}[ERR]${NC} $*"; }
section() { echo -e "\n${CYAN}━━━ $* ━━━${NC}"; }

TOOLS_DIR="$HOME/tools"
mkdir -p "$TOOLS_DIR"

# ──────────────────────────────────────────────
section "APT 패키지"
# ──────────────────────────────────────────────

info "apt update..."
sudo apt-get update -qq

APT_PKGS=(
    # PWN / REV
    gdb
    gdb-multiarch
    checksec
    ltrace
    strace
    patchelf
    # FORENSICS
    tshark
    wireshark-common
    steghide
    exiftool
    foremost
    binutils
    file
    # CRYPTO
    hashcat
    john
    # WEB
    sqlmap
    # 공통 유틸
    ruby
    ruby-dev
    build-essential
    git
    curl
    wget
    python3-pip
    python3-dev
    libssl-dev
    libffi-dev
    # SageMath (optional — 용량 큼, 주석 해제하여 설치)
    # sagemath
)

for pkg in "${APT_PKGS[@]}"; do
    if dpkg -s "$pkg" &>/dev/null; then
        ok "$pkg (already installed)"
    else
        info "Installing $pkg..."
        sudo apt-get install -y -qq "$pkg" && ok "$pkg" || err "$pkg FAILED"
    fi
done

# ──────────────────────────────────────────────
section "pip 패키지"
# ──────────────────────────────────────────────

PIP_PKGS=(
    pwntools
    ROPgadget
    frida-tools
    frida
    slither-analyzer
    mythril
    volatility3
    pycryptodome
)

for pkg in "${PIP_PKGS[@]}"; do
    info "pip install $pkg..."
    pip3 install --quiet --user "$pkg" && ok "$pkg" || err "$pkg FAILED"
done

# ──────────────────────────────────────────────
section "Ruby Gems"
# ──────────────────────────────────────────────

GEM_PKGS=(
    one_gadget
    zsteg
)

for gem in "${GEM_PKGS[@]}"; do
    if gem list | grep -q "^$gem "; then
        ok "$gem (already installed)"
    else
        info "gem install $gem..."
        gem install "$gem" --quiet && ok "$gem" || err "$gem FAILED"
    fi
done

# ──────────────────────────────────────────────
section "GDB 플러그인 — GEF"
# ──────────────────────────────────────────────

GEF_DIR="$HOME/.gef"
if [ -f "$HOME/.gdbinit" ] && grep -q "gef" "$HOME/.gdbinit" 2>/dev/null; then
    ok "GEF (already configured)"
else
    info "Installing GEF..."
    bash -c "$(curl -fsSL https://gef.blah.cat/sh)" 2>/dev/null && ok "GEF" || {
        warn "GEF install failed, trying fallback..."
        wget -q https://raw.githubusercontent.com/hugsy/gef/main/gef.py -O ~/.gef.py \
            && echo "source ~/.gef.py" >> ~/.gdbinit \
            && ok "GEF (fallback)" || err "GEF FAILED"
    }
fi

# ──────────────────────────────────────────────
section "ffuf (Go binary)"
# ──────────────────────────────────────────────

if command -v ffuf &>/dev/null; then
    ok "ffuf (already installed)"
else
    info "Downloading ffuf..."
    FFUF_VER="2.1.0"
    FFUF_URL="https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz"
    wget -q "$FFUF_URL" -O /tmp/ffuf.tar.gz \
        && tar -xzf /tmp/ffuf.tar.gz -C /tmp \
        && mv /tmp/ffuf "$HOME/.local/bin/ffuf" \
        && chmod +x "$HOME/.local/bin/ffuf" \
        && ok "ffuf" || err "ffuf FAILED"
    rm -f /tmp/ffuf.tar.gz
fi

# ──────────────────────────────────────────────
section "dalfox (Go binary)"
# ──────────────────────────────────────────────

if command -v dalfox &>/dev/null; then
    ok "dalfox (already installed)"
else
    info "Downloading dalfox..."
    DALFOX_VER="2.9.2"
    DALFOX_URL="https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VER}/dalfox_linux_amd64.tar.gz"
    wget -q "$DALFOX_URL" -O /tmp/dalfox.tar.gz \
        && tar -xzf /tmp/dalfox.tar.gz -C /tmp \
        && mv /tmp/dalfox "$HOME/.local/bin/dalfox" \
        && chmod +x "$HOME/.local/bin/dalfox" \
        && ok "dalfox" || err "dalfox FAILED"
    rm -f /tmp/dalfox.tar.gz
fi

# ──────────────────────────────────────────────
section "RsaCtfTool"
# ──────────────────────────────────────────────

RSACTF_DIR="$TOOLS_DIR/RsaCtfTool"
if [ -d "$RSACTF_DIR" ]; then
    ok "RsaCtfTool (already cloned)"
else
    info "Cloning RsaCtfTool..."
    git clone --quiet https://github.com/RsaCtfTool/RsaCtfTool.git "$RSACTF_DIR" \
        && pip3 install --quiet --user -r "$RSACTF_DIR/requirements.txt" \
        && ok "RsaCtfTool" || err "RsaCtfTool FAILED"
fi

# ──────────────────────────────────────────────
section "PayloadsAllTheThings"
# ──────────────────────────────────────────────

PATT_DIR="$HOME/PayloadsAllTheThings"
if [ -d "$PATT_DIR" ]; then
    ok "PayloadsAllTheThings (already cloned)"
else
    info "Cloning PayloadsAllTheThings..."
    git clone --quiet --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git "$PATT_DIR" \
        && ok "PayloadsAllTheThings" || err "PayloadsAllTheThings FAILED"
fi

# ──────────────────────────────────────────────
section "Ghidra (바이너리 다운로드)"
# ──────────────────────────────────────────────

GHIDRA_DIR="$TOOLS_DIR/ghidra"
if [ -d "$GHIDRA_DIR" ]; then
    ok "Ghidra (already installed at $GHIDRA_DIR)"
else
    info "Downloading Ghidra 11.1.2..."
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.1.2_build/ghidra_11.1.2_PUBLIC_20240709.zip"
    wget -q --show-progress "$GHIDRA_URL" -O /tmp/ghidra.zip \
        && unzip -q /tmp/ghidra.zip -d "$TOOLS_DIR" \
        && mv "$TOOLS_DIR"/ghidra_11.1.2_PUBLIC "$GHIDRA_DIR" \
        && ok "Ghidra → $GHIDRA_DIR" \
        || err "Ghidra FAILED (수동 설치 필요)"
    rm -f /tmp/ghidra.zip
fi

# ──────────────────────────────────────────────
section "SageMath (선택 설치)"
# ──────────────────────────────────────────────

if command -v sage &>/dev/null; then
    ok "SageMath (already installed)"
else
    warn "SageMath is NOT installed."
    warn "용량이 크므로 수동 설치 권장:"
    warn "  sudo apt-get install -y sagemath"
    warn "  또는: pip install sagemath (느릴 수 있음)"
fi

# ──────────────────────────────────────────────
section "PATH 설정 확인"
# ──────────────────────────────────────────────

if ! grep -q 'HOME/.local/bin' "$HOME/.bashrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    info "~/.local/bin added to PATH in .bashrc"
fi

if ! grep -q 'HOME/.local/bin' "$HOME/.zshrc" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
fi

# ──────────────────────────────────────────────
section "최종 확인"
# ──────────────────────────────────────────────

export PATH="$HOME/.local/bin:$PATH"

check() {
    local name="$1"; local cmd="$2"
    if eval "$cmd" &>/dev/null; then
        ok "$name"
    else
        err "$name — NOT FOUND (설치 실패 확인 필요)"
    fi
}

echo ""
check "gdb"             "command -v gdb"
check "pwntools"        "python3 -c 'import pwn'"
check "ROPgadget"       "command -v ROPgadget"
check "one_gadget"      "command -v one_gadget"
check "checksec"        "command -v checksec"
check "frida"           "command -v frida"
check "GEF"             "grep -q gef ~/.gdbinit"
check "sqlmap"          "command -v sqlmap"
check "ffuf"            "command -v ffuf"
check "dalfox"          "command -v dalfox"
check "z3"              "python3 -c 'from z3 import *'"
check "angr"            "python3 -c 'import angr'"
check "SageMath"        "command -v sage"
check "hashcat"         "command -v hashcat"
check "john"            "command -v john"
check "RsaCtfTool"      "test -f $TOOLS_DIR/RsaCtfTool/RsaCtfTool.py"
check "slither"         "command -v slither"
check "mythril"         "command -v myth"
check "forge (Foundry)" "command -v forge"
check "cast (Foundry)"  "command -v cast"
check "binwalk"         "command -v binwalk"
check "tshark"          "command -v tshark"
check "zsteg"           "command -v zsteg"
check "steghide"        "command -v steghide"
check "exiftool"        "command -v exiftool"
check "foremost"        "command -v foremost"
check "volatility3"     "python3 -c 'import volatility3'"
check "Ghidra"          "test -f $TOOLS_DIR/ghidra/ghidraRun"
check "PayloadsAllTheThings" "test -d $HOME/PayloadsAllTheThings"

echo ""
info "완료. 새 터미널 열거나 'source ~/.bashrc' 실행 후 사용하세요."
