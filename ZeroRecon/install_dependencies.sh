#!/bin/bash

# ZeroRecon Dependency Installer
echo "[*] Updating System..."
sudo apt update && sudo apt install -y golang python3 python3-pip unzip jq

# Setup Go Path
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin

echo "[*] Installing Tools..."
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest

# Move Go tools to bin
sudo cp $HOME/go/bin/subfinder /usr/local/bin/ 2>/dev/null
sudo cp $HOME/go/bin/httpx /usr/local/bin/ 2>/dev/null
sudo cp $HOME/go/bin/assetfinder /usr/local/bin/ 2>/dev/null
sudo cp $HOME/go/bin/gau /usr/local/bin/ 2>/dev/null

# Install Findomain
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip -o -q findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
rm findomain-linux.zip

# Install Aquatone
wget -q https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O aquatone.zip
unzip -o -q aquatone.zip -d aquatone_temp
sudo mv aquatone_temp/aquatone /usr/local/bin/
rm -rf aquatone_temp aquatone.zip

# Install Python requests
pip3 install requests --break-system-packages 2>/dev/null || pip3 install requests

echo "✅ Done! All dependencies installed."
