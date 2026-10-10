# Offensive Security Tooling Archive

![License](https://img.shields.io/badge/license-MIT-green)

## 🛡️ Mission Statement
This repository serves as a centralized archive for custom-developed offensive security tooling, developed by **R00t3dbyFa17h**.

The objective of this collection is to bridge the gap between manual penetration testing methodologies and automated efficiency. Every tool in this repository is engineered to address specific friction points in the Cyber Kill Chain, specifically focusing on:

* **Attack Surface Management (ASM):** Rapid identification of external assets.
* **Reconnaissance Automation:** Reducing the "Time-to-Insight" during red team engagements.
* **Data Aggregation:** Synthesizing data from disparate sources (DNS, HTTP, SSL) into actionable intelligence.

This is a living documentation of the journey from theoretical exploit understanding to practical, programmatic implementation.

## 📂 Current Toolset

| Tool Name | Language | Function |
|:--- |:--- |:--- |
| **ZeroRecon** | Python 3 | A multi-stage reconnaissance pipeline integrating passive and active enumeration. |
| **WAF Whisper** | Python 3 | Stealth-oriented WAF evasion tool for passive detection and payload mutation/obfuscation. |

---

## 🚀 Usage Instructions

### 1. ZeroRecon
*Automated recon script.*
```bash
./zero-recon.sh <target-domain>```

---

## 🆕 2026 Upgrade — Additive Enhancements

Both tools received **strictly additive** upgrades (nothing removed or changed; every new capability is opt-in). Maintained by **R00t3dbyFa17h / K70n0s510** (HTB, Bugcrowd, Microsoft, Intigriti, Google bug bounty handle).

| Tool | New (opt-in) highlights |
| :--- | :--- |
| **ZeroRecon v5.0** | `--osint` (7 pure-Python passive archive sources: HackerTarget, OTX, RapidDNS, Anubis, URLScan, Wayback, CertSpotter), `--history`, `--ports` (naabu), `--screenshots`, `--dns` (dnsx), `--gf`, `--json`, `--html`, `--output-dir`, `--threads`, `--wordlist`, `--resolvers`, `--version`, `--quiet` |
| **WAF Whisper v6.0** | 34-vendor wafw00f-grade fingerprint DB, `--safe`/`--passive` detection-only mode, `-H/--header` & `--cookie` (authenticated testing), `--max-evasion`, `--json`, `--output-dir`, `--version` |

See each tool's own README for full usage. No new Python dependencies were introduced beyond `requests`.
