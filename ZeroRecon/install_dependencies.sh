#!/bin/bash

# ZeroRecon Dependency Installer v1.1
# Author: R00t3dbyFa17h
# Slogan: 🛑 → Zero in on targets with accuracy.

# ANSI Colors
RED='\033[91m'
GREEN='\033[92m'
YELLOW='\033[93m'
CYAN='\033[96m'
RESET='\033[0m'

echo -e "${RED}"
cat << "EOF"
  ______                    _____                         
 |___  /                   |  __ \                        
    / /   ___  _ __   ___  | |__) |  ___   ___   ___   _ __ 
   / /   / _ \| '__| / _ \ |  _  /  / _ \ / __| / _ \ | '_ \ 
  / /__ |  __/| |   | (_) || | \ \ |  __/| (__ | (_) || | | |
 /_____| \___||_|    \___/ |_|  \_\ \___| \___| \___/ |_| |_|
EOF
echo -e "${CYAN}    🛑 → Zero in on targets with accuracy.${RESET}"
echo -e "${YELLOW}    [INSTALLER V1.1]${RESET}"
echo "======================================================="

# 1. Check Root
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}[!] Please run as root (sudo ./install_dependencies.sh)${RESET}"
  exit 1
fi

# 2. Update System
echo -e "${GREEN}[+] Updating APT repositories...${RESET}"
apt-get update -y
apt-get install -y git python3 python3-pip curl wget unzip tar jq

# 3. Install Golang (if missing)
if ! command -v go &> /dev/null; then
    echo -e "${YELLOW}[*] Golang not found. Installing...${RESET}"
    apt-get install -y golang
else
    echo -e "${GREEN}[+] Golang is already installed.${RESET}"
fi

# Setup GO Path for the installation session
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
mkdir -p $GOPATH/bin

# 4. Install Go Tools
echo -e "${GREEN}[+] Installing Go-based tools (This may take a moment)...${RESET}"

install_go_tool() {
    package=$1
    name=$2
    echo -e "${CYAN}   -> Installing $name...${RESET}"
    go install -v $package@latest
    # Move to /usr/bin for global access
    cp $GOPATH/bin/$name /usr/local/bin/ 2>/dev/null || cp $GOPATH/bin/$name /usr/bin/
}

install_go_tool "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "subfinder"
install_go_tool "github.com/tomnomnom/assetfinder" "assetfinder"
install_go_tool "github.com/projectdiscovery/httpx/cmd/httpx" "httpx"
install_go_tool "github.com/tomnomnom/httprobe" "httprobe"
install_go_tool "github.com/lc/gau/v2/cmd/gau" "gau"
install_go_tool "github.com/projectdiscovery/nuclei/v3/cmd/nuclei" "nuclei"
install_go_tool "github.com/projectdiscovery/katana/cmd/katana" "katana"
install_go_tool "github.com/projectdiscovery/naabu/v2/cmd/naabu" "naabu"
install_go_tool "github.com/projectdiscovery/chaos-client/cmd/chaos" "chaos"
install_go_tool "github.com/d3mondev/puredns/v2/cmd/puredns" "puredns"

# 5. Install Findomain (Rust Binary)
if ! command -v findomain &> /dev/null; then
    echo -e "${CYAN}   -> Installing Findomain...${RESET}"
    curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
    unzip -o findomain-linux.zip
    chmod +x findomain
    mv findomain /usr/local/bin/
    rm findomain-linux.zip
else
    echo -e "${GREEN}[+] Findomain is already installed.${RESET}"
fi

# 6. Python Dependencies
echo -e "${GREEN}[+] Installing Python libraries...${RESET}"
pip3 install requests argparse

# 7. Amass (Snap is usually best for Amass)
if ! command -v amass &> /dev/null; then
    echo -e "${YELLOW}[*] Installing Amass (via Snap)...${RESET}"
    snap install amass
fi

echo "======================================================="
echo -e "${GREEN}✔ Installation Complete!${RESET}"
echo -e "${CYAN}Run the tool: python3 ZeroRecon.py -h${RESET}"
