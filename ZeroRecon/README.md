<h1 align="center">
  <br>
  🛑 ZeroRecon v4.0
  <br>
</h1>

<h4 align="center">The "Paranoid" External Attack Surface Management (EASM) Framework.</h4>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-usage">Usage</a> •
  <a href="#-the-paranoid-mode">Paranoid Mode</a> •
  <a href="#-disclaimer">Disclaimer</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Language-Python3-blue?style=for-the-badge&logo=python">
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey?style=for-the-badge&logo=linux">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge">
</p>

---

## 📖 Overview
**ZeroRecon** is not just a wrapper; it is a unified reconnaissance framework designed to reduce "Time-to-Insight" for red teamers and bug bounty hunters. 

It automates the entire discovery lifecycle—from **subdomain discovery** to **vulnerability scanning**—in a single execution flow. Unlike fragmented scripts, ZeroRecon uses a **"Double-Probe"** protocol to ensure no asset is left behind.

> **Slogan:** 🛑 → Zero in on targets with accuracy.

---

## ⚙️ The Architecture
ZeroRecon orchestrates a 7-layer pipeline:

1.  **Paranoid Discovery:** Aggregates data from `Subfinder`, `Assetfinder`, `Findomain`, `Chaos`, and `Crt.sh`.
2.  **Deep Archival Mining:** Uses `Gau` to scrape the Wayback Machine for forgotten subdomains and API endpoints.
3.  **Double-Probe Verification:** Runs `Httpx` AND `Httprobe` simultaneously to catch zombie hosts that other scanners miss.
4.  **Parameter Crawling:** Uses `Katana` to spider live hosts and extract hidden parameters (`?id=`) for IDOR hunting.
5.  **Auto-Nuke:** Automatically launches `Nuclei` templates against live assets to find critical vulnerabilities (CVEs, Exposed Panels).

---

## 🚀 Installation
Stop wasting time installing tools manually. ZeroRecon comes with a bootstrap script that provisions the entire environment.

```bash
# 1. Clone the repository
git clone [https://github.com/R00t3dbyFa17h/hacking-tools.git](https://github.com/R00t3dbyFa17h/hacking-tools.git)

# 2. Navigate to the folder
cd hacking-tools

# 3. Run the Auto-Installer (Root required)
chmod +x install_dependencies.sh
sudo ./install_dependencies.sh
```
## 💻 Usage
**1. The "Quick Map" (Standard Recon)**

Maps the attack surface. Good for a quick overview.


`python3 ZeroRecon.py -t Target.com`

## ParanoidMode
**2. The "Paranoid" Scan (Recommended)**

Enables all 7 layers of discovery, including Amass and DNS brute forcing (if configured). Use this for bug bounties.


`python3 ZeroRecon.py -t Target.com --paranoid`

**3. The "Bug Hunter" (Full Kill Chain)**

This maps the network, crawls for parameters (IDORs), and scans for CVEs automatically.


`python3 ZeroRecon.py -t Target.com --paranoid --crawl --nuclei`

**4. The "API & Ghost" Hunt**

Specifically targets API endpoints (Swagger/GraphQL) and historical endpoints that no longer exist on the main site.


`python3 ZeroRecon.py -t Target.com --api --history`

**5. Remote Alerts (Discord)**

Run the script on a VPS and get a ping on your phone when it's done.


`python3 ZeroRecon.py -t Target.com --paranoid --webhook "YOUR_DISCORD_WEBHOOK_URL"`

## 🛠️ Toolset Integration

**ZeroRecon powers its engine using the best open-source tools available:**


| Category | 🛡️ Tools Used |
| :---: | :--- |
| **Discovery** | `Subfinder`, `Assetfinder`, `Findomain`, `Amass`, `Chaos` |
| **Probing** | `Httpx`, `Httprobe`, `Naabu` |
| **Crawling** | `Katana`, `Gau` (GetAllUrls) |
| **Scanning** | `Nuclei` |

---

> [!CAUTION]
> ## ⚠️ Disclaimer
> This tool is for **educational purposes** and **authorized security testing** only. Do not use this tool on targets you do not have explicit permission to test.


**Authored by: R00t3dbyFa17h**


