#!/bin/bash
set +e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${CYAN}"
echo "╔══════════════════════════════════════════════════╗"
echo "║          RPairip - Auto Installer               ║"
echo "╚══════════════════════════════════════════════════╝"
echo -e "${NC}"

REPO_URL="https://github.com/c0derArmy/RPairip"
INSTALL_DIR="$HOME/.RPairip"

detect_termux() {
    if [ -d "/data/data/com.termux" ] || [ -n "$PREFIX" ]; then
        return 0
    fi
    return 1
}

if [ -d "$INSTALL_DIR" ]; then
    echo -e "${YELLOW}[i] Updating existing installation...${NC}"
    cd "$INSTALL_DIR" && git pull 2>/dev/null || true
else
    echo -e "${CYAN}[i] Downloading RPairip...${NC}"
    git clone "$REPO_URL" "$INSTALL_DIR" 2>/dev/null || {
        echo -e "${RED}[!] Git clone failed. Trying zip...${NC}"
        curl -Ls "$REPO_URL/archive/refs/heads/main.zip" -o /tmp/RPairip.zip
        unzip -qo /tmp/RPairip.zip -d /tmp/RPairip_tmp
        mkdir -p "$INSTALL_DIR"
        mv /tmp/RPairip_tmp/*/* "$INSTALL_DIR/" 2>/dev/null || true
        rm -rf /tmp/RPairip.zip /tmp/RPairip_tmp
    }
fi

cd "$INSTALL_DIR"

echo -e "${CYAN}[i] Installing system dependencies...${NC}"
if detect_termux; then
    pkg update -y
    pkg install -y python python-pip git openjdk-17 default-jdk wget unzip
else
    if command -v apt &>/dev/null; then
        apt update -y
        apt install -y python3 python3-pip git default-jdk wget unzip
    elif command -v dnf &>/dev/null; then
        dnf install -y python3 python3-pip git java-latest-openjdk wget unzip
    elif command -v pacman &>/dev/null; then
        pacman -Sy --noconfirm python python-pip git jdk-openjdk wget unzip
    else
        echo -e "${RED}[!] Unknown package manager. Install manually: python3, java, git${NC}"
    fi
fi

echo -e "${CYAN}[i] Installing Python dependencies...${NC}"
if detect_termux; then
    pip install --upgrade pip
    pip install -r requirements.txt 2>/dev/null || true
    pip install -e . 2>/dev/null || python3 setup.py install 2>/dev/null || true
else
    pip3 install --upgrade pip 2>/dev/null || true
    pip3 install -r requirements.txt 2>/dev/null || true
    pip3 install --break-system-packages -e . 2>/dev/null || pip3 install -e . 2>/dev/null || python3 setup.py install 2>/dev/null || true
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║      Installed Successfully!                   ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Run: ${NC}RPairip -h${GREEN}  to get started           ║${NC}"
echo -e "${GREEN}║                                              ║${NC}"
echo -e "${GREEN}║  Example:                                      ║${NC}"
echo -e "${GREEN}║    ${NC}RPairip -i app.apks${GREEN}                     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════╝${NC}"
echo ""
