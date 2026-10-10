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

---

## 🆕 v5.0 Additions (Strictly Additive)

v5.0 **adds** capabilities without changing any v4.0 behavior. Every existing flag (`-t`, `-w`, `--paranoid`, `--nuclei`, `--crawl`, `--api`) works exactly as before; the banner, phases and output directory are unchanged. All new power is opt-in.

### 🛰️ Passive OSINT Boost — `--osint`
Queries **7 additional archive sources in parallel** using pure Python (no new binaries required): **HackerTarget, AlienVault OTX, RapidDNS, Anubis (jldc), URLScan.io, Wayback CDX, and CertSpotter**. Results are validated and merged into the subdomain set — it only ever *adds* findings.

```bash
python3 ZeroRecon.py -t target.com --osint
```

### 🧱 New opt-in attack-surface phases (run only if the binary is installed)
| Flag | Adds |
| :--- | :--- |
| `--history` | Historical URL mining via `gau`/`waybackurls` |
| `--ports` | Port scan of live hosts via `naabu` (top 1000) |
| `--screenshots` | Visual recon via `gowitness`/`aquatone` |
| `--dns` / `--dnsx` | DNS resolution + A records via `dnsx` |
| `--gf` | Quick-win pattern matching (xss/sqli/ssrf/redirect/idor/lfi) over crawled URLs via `gf` |

### 📊 Reporting & control
| Flag | Description |
| :--- | :--- |
| `--json` | Machine-readable JSON summary (`zerorecon_summary.json`) |
| `--html` | Dark-mode HTML report with live search (`zerorecon_report.html`) |
| `-o, --output-dir DIR` | Custom output directory (default unchanged) |
| `--threads N` | Probe/concurrency threads (default: 25) |
| `--wordlist FILE` / `--resolvers FILE` | Parametrize the `--paranoid` puredns brute force |
| `--version` / `-q, --quiet` | Version string / suppress extra v5.0 output |

### 🧪 Full-power example
```bash
python3 ZeroRecon.py -t target.com --paranoid --osint --crawl --api --nuclei \
    --history --ports --dns --gf --json --html -o ./loot_target
```

> All v5.0 additions are passive-first (the `--osint` sources are OSINT archive lookups) or wrap well-known open-source binaries you already install. No new Python dependencies beyond `requests`.

---

> [!CAUTION]
> ## ⚠️ Disclaimer
> This tool is for **educational purposes** and **authorized security testing** only. Do not use this tool on targets you do not have explicit permission to test.


**Authored by: R00t3dbyFa17h**

## Rooted by Authority. Faith by Design. STAY R00t3d In Fa17h!!
