
# ZeroRecon v1.1

> **Slogan:** 🛑 → Zero in on targets with accuracy.

![Python](https://img.shields.io/badge/Language-Python3-blue) ![Status](https://img.shields.io/badge/Status-Stable-green) ![Install](https://img.shields.io/badge/Install-Automated-orange)

## 📖 Overview
**ZeroRecon** is a unified reconnaissance framework designed to reduce the "Time-to-Insight" for red teamers and bug hunters. It automates the entire External Attack Surface Management (EASM) lifecycle—from subdomain discovery to visual validation—in a single execution flow.

Unlike other fragmented scripts, ZeroRecon is **self-contained**. It includes an intelligent dependency resolver that sets up your environment automatically, eliminating the need to manually hunt for Go libraries or Python modules.

## ⚙️ The Architecture
ZeroRecon orchestrates a multi-stage pipeline:

1.  **Passive & Active Discovery:** Aggregates data from `Subfinder`, `Assetfinder`, `Findomain`, and Certificate Transparency logs (`crt.sh`).
2.  **Deep Archival Analysis:** Mining the Wayback Machine via `Gau` to uncover forgotten endpoints.
3.  **Live Service Validation:** Intelligent probing with `Httpx` to filter dead DNS records.
4.  **Visual Reconnaissance:** Automated screenshotting via `Aquatone` for rapid visual assessment.

## 🚀 Rapid Installation
Stop wasting time installing tools manually. ZeroRecon comes with a **bootstrap script** that detects your OS (Kali/Debian) and provisions the entire environment.

```bash
# 1. Clone the repository
git clone [https://github.com/R00t3dbyFa17h/hacking-tools.git](https://github.com/R00t3dbyFa17h/hacking-tools.git)

# 2. Navigate to the tool
cd hacking-tools/ZeroRecon

# 3. Run the Auto-Installer (Root required for apt/mv)
chmod +x install_dependencies.sh
sudo ./install_dependencies.sh
