# WAF Whisper v5.0
### Adaptive WAF Evasion & Orchestration Engine

**Created by:** [R00t3dbyFa17h](https://github.com/R00t3dbyFa17h)

![Python](https://img.shields.io/badge/Language-Python%203-blue?style=flat&logo=python) ![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-lightgrey?style=flat&logo=linux) ![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat) ![Version](https://img.shields.io/badge/Version-5.0.0-green?style=flat)

---

## 📖 The Foundation
> *"Behold, I send you forth as sheep in the midst of wolves: be ye therefore wise as serpents, and harmless as doves."*
> — **Matthew 10:16**

**WAF Whisper** is not just a scanner; it is an intelligent evasion framework.

Modern Web Application Firewalls (WAFs) utilize heuristic analysis and behavior profiling. Traditional tools that simply "fuzz" endpoints get IP-banned immediately. WAF Whisper was engineered to defeat these defenses using the **Guardrail-Ghost** engine—adapting to the target's "patience" and mathematically fragmenting attacks.

---

## 🛡️ Key Features: The Guardrail-Ghost Engine

### Phase 0: Ghost Mode (Client Emulation)
* **Signature Spoofing:** Injects TLS-consistent headers to indistinguishably mimic legitimate browser traffic.
* **Randomized UA Rotation:** cycles User-Agents to prevent fingerprinting.

### Phase 4: Adaptive Rate Limit Profiling
* **Dynamic Throttling:** The tool doesn't guess the speed limit; it finds it.
* **Low-and-Slow:** Uses the `--delay` algorithm to introduce randomized "human" latency between requests to defeat rate-limiting heuristics.

### Phase 6: MPL Discovery & Fragmentation
* **Max Payload Length (MPL):** Uses a binary search algorithm to find the exact byte limit the WAF inspects.
* **Fragmentation Attack:** Automatically splits complex payloads into chunks smaller than the MPL, reassembling them on the server side.

### Phase 7: Semantic Polyglots
* **Signature Inversion:** Bypasses keyword filters (e.g., `cat /etc/passwd`) using shell expansion and IFS evasion.

---

## ⚙️ Installation

**1. Clone the Repo**
```bash
git clone [https://github.com/R00t3dbyFa17h/WAF-Whisper.git](https://github.com/R00t3dbyFa17h/WAF-Whisper.git)
cd WAF-Whisper

2. Install Dependencies
Bash

pip3 install -r requirements.txt

🚀 Usage

1. Ghost Mode Scan (Recommended) Engage Guardrail-Ghost mode with randomized User-Agents to avoid detection.
Bash

python3 waf_whisper.py -u [https://target.com](https://target.com) --ghost

2. Low-and-Slow Evasion Manually override the delay (in seconds) to bypass strict rate-limiting sensors.
Bash

python3 waf_whisper.py -u [https://target.com](https://target.com) --delay 5

3. Proxied Scan (BurpSuite/Zap) Route traffic through a local proxy for deeper analysis.
Bash

python3 waf_whisper.py -u [https://target.com](https://target.com) -p [http://127.0.0.1:8080](http://127.0.0.1:8080) -v

4. Full Help Menu
Plaintext

usage: waf_whisper.py [-h] -u URL [-v] [-p PROXY] [--delay DELAY] [--ghost]

options:
  -h, --help            show this help message and exit
  -u, --url             Target URL (e.g., [https://example.com](https://example.com))
  -v, --verbose         Enable verbose output
  -p, --proxy           Proxy URL (e.g., [http://127.0.0.1:8080](http://127.0.0.1:8080))
  --delay DELAY         Manual override for Low-and-Slow delay (seconds)
  --ghost               Enable Guardrail-Ghost Mode (Randomized UA Rotation)

⚠️ Legal Disclaimer

FOR EDUCATIONAL PURPOSES ONLY. Usage of WAF-Whisper for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state, and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program.
