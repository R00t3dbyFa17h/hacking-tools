# WAF Whisper v5.0
### Adaptive WAF Evasion & Orchestration Engine

**Created by:** [R00t3dbyFa17h](https://github.com/R00t3dbyFa17h)

![Python](https://img.shields.io/badge/Language-Python%203-blue?style=flat&logo=python) ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat&logo=linux) ![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat) ![Version](https://img.shields.io/badge/Version-5.0.0-green?style=flat)

---

## 📖 About The Project

> *"Behold, I send you forth as sheep in the midst of wolves: be ye therefore wise as serpents, and harmless as doves."*
> — **Matthew 10:16**

**WAF Whisper** is an intelligent evasion framework.

Modern Web Application Firewalls (WAFs) like Cloudflare, AWS Shield, and Akamai have moved beyond simple signature matching. Traditional tools that simply "fuzz" endpoints get IP-banned immediately.

WAF Whisper was engineered to defeat these defenses using the **Guardrail-Ghost Engine**. It adapts to the target, dynamically discovering rate limits and payload size restrictions to slip through inspection logic.

**Why use WAF Whisper?**
* **Stealth First:** Mimics a legitimate Chrome/Windows client.
* **Adaptive:** Slows down or speeds up based on the WAF's "patience."
* **Surgical:** Fragments payloads to bypass "Max Length" filters.

---

## 🧠 The Guardrail-Ghost Engine

WAF Whisper moves from passive reconnaissance to active exploitation in 8 phases.

**The Bypass Philosophy:**
Standard scanners force payloads into the URL. WAF Whisper leverages **Protocol Confusion** and **Fragmentation**.

**SCENARIO 1: STANDARD SCRIPT (Blocked)**
* Payload: `GET /?q=<script>alert(1)</script>`
* Result: ⛔ 403 FORBIDDEN

**SCENARIO 2: WAF WHISPER (Bypassed)**
* Payload: Fragmented JSON over POST with delays.
* Result: ✅ 200 OK

---

## ✨ Key Features

### Phase 0-1: Ghost Mode
* **Client Emulation:** Injects TLS-consistent headers to spoof a legitimate Google Chrome session.
* **Passive Detection:** Identifies vendors without triggering active defense rules.

### Phase 4: Adaptive Rate Limit Profiling
* **Dynamic Throttling:** The tool probes the WAF at different speeds (120, 60, 30 RPM) to find the blocking threshold, then automatically sets a safe delay.

### Phase 6: MPL Discovery & Fragmentation
* **Max Payload Length (MPL):** Finds the exact byte limit the WAF inspects.
* **Fragmentation:** Splits complex payloads into chunks smaller than the MPL and reassembles them on the server.

### Phase 7: Semantic Polyglots (Linux/Zsh)
* **Signature Inversion:** Bypasses keyword filters (like `cat /etc/passwd`) using shell expansion techniques.

---

## ⚙️ Installation

1. **Clone the Repo**
   ```bash
   git clone [https://github.com/R00t3dbyFa17h/WAF-Whisper.git](https://github.com/R00t3dbyFa17h/WAF-Whisper.git)
   cd WAF-Whisper

    Install Dependencies
    Bash

    pip3 install -r requirements.txt

🚀 Usage

Basic Scan (Ghost Mode)
Bash

python3 waf_whisper.py -u [https://target.com](https://target.com)

Verbose Mode (Deep Analysis)
Bash

python3 waf_whisper.py -u [https://target.com](https://target.com) -v

⚠️ Legal Disclaimer

FOR EDUCATIONAL PURPOSES ONLY. Usage of WAF-Whisper for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws.
