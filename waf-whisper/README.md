
# 🛡️ WAF Whisper v5.0
### Adaptive WAF Evasion & Orchestration Engine

**Created by:** [R00t3dbyFa17h](https://github.com/R00t3dbyFa17h)

![Python](https://img.shields.io/badge/Language-Python%203-blue?style=flat&logo=python) ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat&logo=linux) ![License](https://img.shields.io/badge/License-MIT-orange.svg?style=flat) ![Focus](https://img.shields.io/badge/Focus-Red%20Teaming-red?style=flat)

---

## 📖 The Foundation
> *"Behold, I send you forth as sheep in the midst of wolves: be ye therefore wise as serpents, and harmless as doves."*
> — **Matthew 10:16**

**WAF Whisper** is not just a scanner; it is an intelligent evasion framework.

Modern Web Application Firewalls (WAFs) like Cloudflare, AWS Shield, and Akamai utilize heuristic analysis and behavior profiling. Traditional tools that simply "fuzz" endpoints get IP-banned immediately. 

**WAF Whisper** was engineered to defeat these defenses using the **Guardrail-Ghost Engine**—adapting to the target's "patience" and mathematically fragmenting attacks to remain invisible.

---

## 🧠 The Guardrail-Ghost Architecture

The engine operates on a decision loop that prioritizes stealth over speed. Instead of blindly firing payloads, it follows this strict logic flow:

1.  **Target Identification:** Checks if the target is live.
2.  **Passive Fingerprinting:** Identifies WAF headers without attacking.
3.  **Ghost Mode Decision:** If a WAF is found, it engages User-Agent rotation and jitter.
4.  **Rate Limit Probing:** Tests the WAF's patience to find the maximum safe speed.
5.  **Payload Fragmentation:** Splits attacks into chunks smaller than the WAF's inspection limit.
6.  **Whisper Attack:** Reassembles the payload on the server side to bypass detection.

---

## 📜 Version History & Changelog

This tool has evolved from a simple fuzzer to a stateful evasion engine.

| Version | Codename | Key Capabilities Added |
| :--- | :--- | :--- |
| **v5.0** | **Guardrail-Ghost** | Current Release. Added MPL Fragmentation, Binary Search Rate Limiting, and Phase 8 Blind Verification. |
| **v4.2** | **Low-and-Slow** | Introduced `--delay` algorithm to defeat heuristic rate monitoring. |
| **v3.0** | **Ghost Mode** | Added Random User-Agent Rotation and Passive WAF Fingerprinting (Cloudflare/AWS detection). |
| **v2.1** | **Proxy Link** | Added `-p` flag for integration with BurpSuite and OWASP ZAP. |
| **v1.0** | **Whisper** | Initial Release. Basic Payload Mutation (URL Encoding/Double URL). |

---

## 🛡️ Key Features

### 👻 Phase 0: Ghost Mode (Client Emulation)
* **Signature Spoofing:** Injects TLS-consistent headers to indistinguishably mimic legitimate browser traffic.
* **Randomized UA Rotation:** Automatically cycles User-Agents to prevent fingerprinting during prolonged scans.

### ⏱️ Phase 4: Adaptive Rate Limit Profiling
* **Dynamic Throttling:** The tool doesn't guess the speed limit; it finds it.
* **Low-and-Slow:** Uses the `--delay` algorithm to introduce randomized "human" latency between requests.

### 🧩 Phase 6: MPL Discovery & Fragmentation
* **Max Payload Length (MPL):** Uses a binary search algorithm to find the exact byte limit the WAF inspects.
* **Fragmentation Attack:** Automatically splits complex payloads into chunks smaller than the MPL, reassembling them on the server side.

### 🗣️ Phase 7: Semantic Polyglots
* **Signature Inversion:** Bypasses keyword filters (e.g., `cat /etc/passwd`) using shell expansion and IFS evasion specific to Linux backends.

---

## ⚙️ Installation

**1. Clone the Repository**

`git clone [https://github.com/R00t3dbyFa17h/WAF-Whisper.git](https://github.com/R00t3dbyFa17h/WAF-Whisper.git)
cd WAF-Whisper`

**2. Install Dependencies**


`pip3 install -r requirements.txt`

## 🚀 Usage
**1. Ghost Mode Scan (Recommended)**

Engage Guardrail-Ghost mode with randomized User-Agents to avoid detection.


`python3 waf_whisper.py -u [https://target.com](https://target.com) --ghost`

**2. Low-and-Slow Evasion**

Manually override the delay (in seconds) to bypass strict rate-limiting sensors.


`python3 waf_whisper.py -u [https://target.com](https://target.com) --delay 5`

**3. Proxied Scan (BurpSuite/Zap)**

Route traffic through a local proxy for deeper analysis.


`python3 waf_whisper.py -u [https://target.com](https://target.com) -p [http://127.0.0.1:8080](http://127.0.0.1:8080) -v`

**4. Full Help Menu**
**Plaintext**

```
usage: waf_whisper.py [-h] -u URL [-v] [-p PROXY] [--delay DELAY] [--ghost]

options:
  -h, --help            show this help message and exit
  -u, --url             Target URL (e.g., [https://example.com](https://example.com))
  -v, --verbose         Enable verbose output
  -p, --proxy           Proxy URL (e.g., [http://127.0.0.1:8080](http://127.0.0.1:8080))
  --delay DELAY         Manual override for Low-and-Slow delay (seconds)
  --ghost               Enable Guardrail-Ghost Mode (Randomized UA Rotation)

  ```


---

## 🆕 v6.0 Additions (Strictly Additive)

v6.0 **adds** capabilities without changing any v5.x behavior. Every existing flag (`-u`, `-v`, `-p`, `--delay`, `--ghost`) and every phase works exactly as before. All new power is opt-in.

### 🔎 wafw00f-grade Fingerprint Database
The passive detection phase now cross-references a **34-vendor fingerprint database** (Cloudflare, AWS, Akamai, Imperva, F5 BIG-IP, ModSecurity, Citrix, Sucuri, Wordfence, Barracuda, FortiWeb, Fastly, Azure, Google Cloud Armor, StackPath, Wallarm, Reblaze, Radware, Signal Sciences, Palo Alto, Varnish, ArvanCloud, and more). It scores each vendor by header, cookie, `Server`, and body signatures and reports confidence — **detection only, it sends no extra requests** (it reuses the response already fetched).

### 🕊️ `--safe` / `--passive` — Detection-Only Mode
Fingerprints the WAF and **stops** — sends **zero attack payloads**. Ideal for safe reconnaissance, asset inventory, or confirming a WAF before deeper (authorized) testing.
```bash
python3 waf_whisper.py -u https://target.com --safe
```

### 🔐 Authenticated Testing — `-H` / `--cookie`
Test endpoints behind authentication by adding session headers/cookies (propagated to every request).
```bash
python3 waf_whisper.py -u https://target.com -H 'Authorization: Bearer <token>' --cookie 'session=abc'
```

### 🧬 `--max-evasion` — Extra Encoding Mutations
Adds standard WAF-evasion encodings to the mutation phase (HTML entity decimal/hex, unicode escape, mixed/double encoding, tab/newline injection, SVG/img vectors). The default mutation set is unchanged.

### 📄 Reporting & control
| Flag | Description |
| :--- | :--- |
| `--json` | Machine-readable JSON report alongside the Markdown one |
| `--output-dir DIR` | Directory for reports (default: `./WAF_Whisper_Reports`) |
| `--version` | Print version and exit |

> All v6.0 additions are detection-, reporting-, or stealth-oriented and introduce **no new Python dependencies**. The `--safe` mode makes responsible, non-intrusive assessment a first-class option.

---

## ⚠️ Legal Disclaimer

**FOR EDUCATIONAL PURPOSES ONLY.**

**Usage of WAF-Whisper for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.**

## "Rooted by Authority. Faith by Design." Stay R00t3d In Fa17h! 
