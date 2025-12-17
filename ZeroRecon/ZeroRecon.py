#!/usr/bin/env python3

import os
import sys
import subprocess
import requests
import argparse
import shutil
import re
from datetime import datetime

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'
BOLD = '\033[1m'

SLOGAN = "🛑 → ZERO RECON: V4.0 PARANOID (NO STONE UNTURNED)"

def banner():
    print(f"{RED}")
    print(r"""
  ______                    _____                         
 |___  /                   |  __ \                        
    / /   ___  _ __   ___  | |__) |  ___   ___   ___   _ __ 
   / /   / _ \| '__| / _ \ |  _  /  / _ \ / __| / _ \ | '_ \ 
  / /__ |  __/| |   | (_) || | \ \ |  __/| (__ | (_) || | | |
 /_____| \___||_|    \___/ |_|  \_\ \___| \___| \___/ |_| |_|
    """)
    print(f"{CYAN}       {SLOGAN}{RESET}")
    print(f"{YELLOW}            Author: R00t3dbyFa17h | V4.0 PARANOID{RESET}")
    print(f"{RED}" + "=" * 65 + f"{RESET}")

def check_dependencies():
    # The "Paranoid" Toolset
    tools = [
        "subfinder", "assetfinder", "findomain", "amass", # Core
        "gau", "chaos", "puredns", # Paranoid Extras
        "httpx", "httprobe", "nuclei", "katana", "naabu" # Probing
    ]
    missing = []
    for tool in tools:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        print(f"{RED}[!] Missing tools: {', '.join(missing)}{RESET}")
        print(f"{YELLOW}[*] Warning: Script will skip missing tools. Install them for full 'Paranoid' coverage.{RESET}")

def run_command(command, shell=False):
    try:
        cmd_str = command if isinstance(command, str) else " ".join(command)
        result = subprocess.run(
            command, 
            shell=shell, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True
        )
        return result.stdout.strip()
    except Exception as e:
        # print(f"{RED}[!] Error: {e}{RESET}") # Be silent on errors to avoid clutter
        return ""

def send_discord_alert(webhook_url, message):
    if not webhook_url: return
    data = {"content": "", "embeds": [{"title": "ZeroRecon V4 Alert 👁️", "description": message, "color": 16711680}]}
    try: requests.post(webhook_url, json=data)
    except: pass

# --- CUSTOM MODULE: Crt.sh Manual Query ---
def query_crtsh(domain):
    print(f"{GREEN}[+] Manual Query: Crt.sh...{RESET}")
    subs = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name = entry['name_value']
                for sub in name.split('\n'):
                    if "*" not in sub:
                        subs.add(sub)
    except:
        pass
    return subs

def main():
    banner()
    parser = argparse.ArgumentParser(description="ZeroRecon V4.0")
    
    # Core Arguments
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    parser.add_argument("-w", "--webhook", help="Discord Webhook URL")
    
    # Modes
    parser.add_argument("--paranoid", action="store_true", help="Enable Amass, Puredns & Heavy Scans")
    parser.add_argument("--nuclei", action="store_true", help="Run Vulnerability Scan")
    parser.add_argument("--crawl", action="store_true", help="Crawl for parameters")
    parser.add_argument("--api", action="store_true", help="API Hunt")
    
    args = parser.parse_args()

    # WEBHOOK
    webhook_url = args.webhook
    if not webhook_url: webhook_url = os.environ.get("DISCORD_WEBHOOK")

    target = args.target
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_dir = f"recon_{target}_{date_str}"
    
    check_dependencies()
    if not os.path.exists(output_dir): os.makedirs(output_dir)

    if webhook_url:
        send_discord_alert(webhook_url, f"👁️ ZeroRecon V4 (Paranoid) Started on **{target}**")

    # ==========================================
    # PHASE 1: THE PARANOID ENUMERATION
    # ==========================================
    print(f"\n{BOLD}{YELLOW}[PHASE 1] Enumerating Subdomains (The 7-Layer Scan)...{RESET}")
    all_subs = set()
    
    # 1. Subfinder (Go)
    print(f"{GREEN}[1/7] Subfinder...{RESET}")
    out = run_command(f"subfinder -d {target} -silent", shell=True)
    for line in out.splitlines(): all_subs.add(line)
    
    # 2. Assetfinder (Go)
    print(f"{GREEN}[2/7] Assetfinder...{RESET}")
    out = run_command(f"assetfinder --subs-only {target}", shell=True)
    for line in out.splitlines(): all_subs.add(line)

    # 3. Findomain (Rust) - NEW
    if shutil.which("findomain"):
        print(f"{GREEN}[3/7] Findomain...{RESET}")
        out = run_command(f"findomain -t {target} -q", shell=True)
        for line in out.splitlines(): all_subs.add(line)

    # 4. Chaos (ProjectDiscovery) - NEW
    if shutil.which("chaos"):
        print(f"{GREEN}[4/7] Chaos (PD)...{RESET}")
        out = run_command(f"chaos -d {target} -silent", shell=True)
        for line in out.splitlines(): all_subs.add(line)

    # 5. Gau (Historical Subdomain Scrape) - NEW
    if shutil.which("gau"):
        print(f"{GREEN}[5/7] Gau (History Scrape)...{RESET}")
        # Fetch all URLs, cut to domain, filter for target
        cmd = f"gau {target} --subs | awk -F/ '{{print $3}}' | grep \"{target}\" | sort -u"
        out = run_command(cmd, shell=True)
        for line in out.splitlines(): 
            if line: all_subs.add(line.split(':')[0]) # Remove ports if any

    # 6. Crt.sh (Manual Python Fallback) - NEW
    crt_subs = query_crtsh(target)
    all_subs.update(crt_subs)

    # 7. Amass (The Slow Giant) - Only in Paranoid Mode
    if args.paranoid and shutil.which("amass"):
        print(f"{GREEN}[7/7] Amass (Passive) - This may take time...{RESET}")
        out = run_command(f"amass enum -passive -d {target} -silent", shell=True)
        for line in out.splitlines(): all_subs.add(line)

    # Save Raw List
    print(f"{YELLOW}[*] Total Unique Subdomains Found: {len(all_subs)}{RESET}")
    subs_file = os.path.join(output_dir, "all_subdomains.txt")
    with open(subs_file, "w") as f:
        for sub in all_subs:
            f.write(f"{sub}\n")

    # ==========================================
    # PHASE 2: BRUTE FORCE (OPTIONAL PARANOID)
    # ==========================================
    # If puredns is installed and --paranoid is on, we brute force
    if args.paranoid and shutil.which("puredns"):
        print(f"\n{BOLD}{YELLOW}[PHASE 1.5] DNS Brute Forcing (Puredns)...{RESET}")
        # Note: You need a wordlist at /usr/share/wordlists/dns.txt or similar
        wordlist = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        if os.path.exists(wordlist):
            out = run_command(f"puredns bruteforce {wordlist} {target} -r resolvers.txt --quiet", shell=True)
            for line in out.splitlines(): all_subs.add(line)
        else:
            print(f"{RED}[!] Wordlist not found for Puredns. Skipping.{RESET}")

    # ==========================================
    # PHASE 3: DOUBLE-PROBE VERIFICATION
    # ==========================================
    print(f"\n{BOLD}{YELLOW}[PHASE 2] Probing Live Hosts (Double-Check)...{RESET}")
    
    # Check 1: HTTPX
    print(f"{GREEN}[+] HTTPX Probe...{RESET}")
    run_command(f"cat {subs_file} | httpx -silent -threads 25 -o {output_dir}/alive_httpx.txt", shell=True)
    
    # Check 2: HTTPROBE (The Backup)
    print(f"{GREEN}[+] HTTPROBE Probe...{RESET}")
    run_command(f"cat {subs_file} | httprobe -c 50 -p http:8080 -p https:8443 > {output_dir}/alive_httprobe.txt", shell=True)

    # Merge
    run_command(f"cat {output_dir}/alive_httpx.txt {output_dir}/alive_httprobe.txt | sort -u > {output_dir}/live_hosts.txt", shell=True)
    
    live_count = 0
    with open(f"{output_dir}/live_hosts.txt", 'r') as f: live_count = len(f.readlines())
    print(f"{YELLOW}[*] Live Hosts: {live_count}{RESET}")
    if webhook_url: send_discord_alert(webhook_url, f"✅ Found {live_count} Live Hosts on {target}")

    # ==========================================
    # PHASE 4: THE ATTACK (Crawl / Scan)
    # ==========================================
    if live_count > 0:
        if args.crawl:
            print(f"\n{BOLD}{YELLOW}[PHASE 3] Crawling (IDOR Hunt)...{RESET}")
            run_command(f"katana -list {output_dir}/live_hosts.txt -jc -kf -c 10 -o {output_dir}/crawled.txt", shell=True)

        if args.api:
            print(f"\n{BOLD}{YELLOW}[PHASE 4] API & JS Hunt...{RESET}")
            run_command(f"cat {output_dir}/live_hosts.txt | grep -iE 'api|dev|stage' | httpx -path /v2/api-docs,/swagger.json -mc 200 -o {output_dir}/swagger.txt", shell=True)

        if args.nuclei:
            print(f"\n{BOLD}{YELLOW}[PHASE 5] Nuclei Vulnerability Scan...{RESET}")
            nuclei_file = os.path.join(output_dir, "nuclei_vulns.txt")
            run_command(f"nuclei -l {output_dir}/live_hosts.txt -s critical,high -o {nuclei_file}", shell=True)
            if os.path.exists(nuclei_file) and os.path.getsize(nuclei_file) > 0:
                send_discord_alert(webhook_url, f"🚨 CRITICAL VULNS FOUND ON {target}!")

    print(f"\n{CYAN}--------------------------------------------------{RESET}")
    print(f"{GREEN}[COMPLETED] Results: {output_dir}{RESET}")

if __name__ == "__main__":
    main()
