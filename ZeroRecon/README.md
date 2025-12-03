# ZeroRecon v1.0

> **Slogan:** 🛑 → Zero in on targets with accuracy.

![Python](https://img.shields.io/badge/Language-Python3-blue) ![Status](https://img.shields.io/badge/Status-Stable-green) ![Focus](https://img.shields.io/badge/Focus-Reconnaissance-red)

## 📖 Overview
**ZeroRecon** is an automated external attack surface management (EASM) tool designed to streamline the reconnaissance phase of a penetration test. By chaining together industry-standard tools into a unified pipeline, ZeroRecon eliminates the latency of manual context switching.

It performs **Passive DNS Enumeration**, **Certificate Transparency Analysis**, **Historical URL Archiving**, and **Live Service Probing** to generate a comprehensive "Hit List" of live targets.

## ⚙️ The Pipeline
ZeroRecon executes the following logic flow:

1.  **Aggressive Subdomain Discovery:**
    * `Subfinder` (Passive Sources)
    * `Assetfinder` (Go-based Discovery)
    * `Findomain` (Rust-based Speed)
    * `crt.sh` (Certificate Transparency Logs)
2.  **Historical Analysis:**
    * `Gau` (Wayback Machine/AlienVault) to find "forgotten" endpoints.
3.  **Live Validation:**
    * `Httpx` probes for HTTP/HTTPS services, filtering out dead DNS records.
4.  **Visual Inspection:**
    * `Aquatone` captures screenshots of valid web applications for rapid review.

## 🚀 Installation

**Prerequisites:**
You must have the following tools installed and available in your system `$PATH`:
* `subfinder`, `assetfinder`, `findomain`, `gau`, `httpx`, `aquatone`

**Setup:**
```bash
git clone [https://github.com/R00t3dbyFa17h/hacking-tools.git](https://github.com/R00t3dbyFa17h/hacking-tools.git)
cd hacking-tools/ZeroRecon
pip install -r requirements.txt
