Markdown

<div align="center">

  <h3 align="center">🛡️ WAF Whisper v5.0</h3>

  <p align="center">
    <strong>Adaptive WAF Evasion & Orchestration Engine</strong>
    <br />
    <a href="#logic-breakdown"><strong>Explore the Logic »</strong></a>
    <br />
    <br />
    <a href="https://github.com/R00t3dbyFa17h">Report Bug</a>
    ·
    <a href="https://github.com/R00t3dbyFa17h">Request Feature</a>
  </p>
</div>
<p align="center">
  <img src="https://img.shields.io/badge/Language-Python%203-blue?style=for-the-badge&logo=python" alt="Python">
  <img src="https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=for-the-badge&logo=linux" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Focus-Red%20Teaming-red?style=for-the-badge&logo=kali-linux" alt="Security">
  <img src="https://img.shields.io/badge/Version-5.0.0-green?style=for-the-badge" alt="Version">
</p>

</div>

<br />

## 📋 Table of Contents
- [About The Project](#about-the-project)
- [The Guardrail-Ghost Engine](#the-guardrail-ghost-engine)
- [Key Features](#key-features)
- [Installation](#installation)
- [Usage](#usage)
- [Roadmap](#roadmap)
- [Legal Disclaimer](#-legal-disclaimer)

---

## 📖 About The Project

> *"Behold, I send you forth as sheep in the midst of wolves: be ye therefore wise as serpents, and harmless as doves."*
> — **Matthew 10:16**

**WAF Whisper** is not just a scanner; it is an **intelligent evasion framework**. 

Modern Web Application Firewalls (WAFs) like Cloudflare, AWS Shield, and Akamai have moved beyond simple signature matching. They utilize heuristic analysis, behavior profiling, and protocol validation. Traditional tools that simply "fuzz" endpoints get IP-banned immediately.

WAF Whisper was engineered to defeat these defenses by **adapting** to the target. It dynamically discovers the WAF's rate limits and payload size restrictions, then mathematically fragments and reshapes attacks to slip through the inspection logic.

**Why use WAF Whisper?**
* **Stealth First:** It doesn't look like a bot; it mimics a legitimate Chrome/Windows client.
* **Adaptive:** It slows down or speeds up based on the WAF's "patience" (Rate Limit Profiling).
* **Surgical:** It fragments payloads to bypass "Max Length" filters.

---

## 🧠 The Guardrail-Ghost Engine

WAF Whisper operates in **8 distinct phases**, moving from passive reconnaissance to active, stateful exploitation. We call this the **Guardrail-Ghost** architecture.

### The Bypass Philosophy
Standard scanners force payloads into the URL. WAF Whisper leverages **Protocol Confusion** and **Fragmentation**.

**[ SCENARIO 1: STANDARD SCRIPT ]**
```http
GET /?q=<script>alert(1)</script> HTTP/1.1
User-Agent: python-requests/2.31
Result: ⛔ 403 FORBIDDEN (Signature Detected)

[ SCENARIO 2: WAF WHISPER (Guardrail-Ghost) ]
HTTP

POST / HTTP/1.1
Content-Type: application/json
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)...

{"q": "chunk1_safe_data"} ... [WAIT 0.5s] ... {"q": "chunk2_payload"}
Result: ✅ 200 OK (Fragmented & Bypassed)

✨ Key Features
🕵️ Phase 0-1: Ghost Mode & Fingerprinting

    Client Emulation: Injects TLS-consistent headers (Sec-Ch-Ua, Upgrade-Insecure-Requests) to spoof a legitimate Google Chrome session.

    Passive Detection: Identifies vendors (Cloudflare, Imperva, F5) without triggering active defense rules.

📉 Phase 4: Adaptive Rate Limit Profiling

    Dynamic Throttling: The tool doesn't guess the speed limit; it finds it. It probes the WAF at 120, 60, and 30 RPM to discover the exact threshold for blocking, then sets a global SAFE_DELAY for all subsequent attacks.

📏 Phase 6: MPL Discovery & Fragmentation

    Max Payload Length (MPL): Uses a binary search algorithm to find the exact byte limit the WAF inspects (e.g., 1024 bytes).

    Fragmentation Attack: Automatically splits complex payloads (like Reverse Shells) into chunks smaller than the MPL, reassembling them on the server side using stateful sessions.

🗣️ Phase 7: Semantic Polyglots (Zsh/Linux)

    Signature Inversion: Bypasses keyword filters (e.g., cat /etc/passwd) using shell expansion and IFS evasion specific to Linux backends.

        Example: $(printf 'c'a't') instead of cat.

⏱️ Phase 8: Blind Verification

    Time-Based Proof: Verifies "blind" vulnerabilities by injecting sleep commands. If the server takes >4.5s to respond, the tool mathematically confirms the vulnerability without needing a visual error message.

⚙️ Installation

WAF Whisper is optimized for Linux environments (Debian/Kali/Ubuntu) but compatible with Windows via GitBash.

    Clone the Repo
    Bash

git clone [https://github.com/R00t3dbyFa17h/WAF-Whisper.git](https://github.com/R00t3dbyFa17h/WAF-Whisper.git)
cd WAF-Whisper

Install Dependencies
Bash

    pip3 install -r requirements.txt

    (Requires: requests, urllib3, argparse)

🚀 Usage
Basic Scan (Ghost Mode)

Engage passive detection and standard bypass tests.
Bash

python3 waf_whisper.py -u [https://target.com](https://target.com)

Verbose Mode (Deep Analysis)

View the specific headers, rate limit calculations, and payload fragmentation steps.
Bash

python3 waf_whisper.py -u [https://target.com](https://target.com) -v

📊 Reporting

The tool automatically generates a Markdown Report in the ./reports directory after every scan.

    Contains all bypassed endpoints.

    Includes curl reproduction commands.

    Ready to commit to GitHub via GitBash.

🗺️ Roadmap

    [x] v1.0: Basic Method Tampering (GET -> POST)

    [x] v3.0: Content-Type Confusion & Header Pollution

    [x] v5.0: Adaptive Rate Limiting & Payload Fragmentation

    [ ] v6.0: HTTP/2 Request Smuggling Support

    [ ] v7.0: AI-Driven Payload Mutation

⚠️ Legal Disclaimer

FOR EDUCATIONAL PURPOSES ONLY.

Usage of WAF-Whisper for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.

<div align="center"> <strong>Created with ❤️ by <a href="https://github.com/R00t3dbyFa17h">R00t3dbyFa17h</a></strong> </div>
