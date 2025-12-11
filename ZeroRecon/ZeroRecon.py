#!/usr/bin/env python3

import os
import sys
import subprocess
import requests
import argparse
import shutil
from datetime import datetime

# ANSI Colors
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
CYAN = '\033[96m'
RESET = '\033[0m'

SLOGAN = "🛑 → ZERO IN ON TARGETS WITH ACCURACY"

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
    print(f"{YELLOW}            Author: R00t3dbyFa17h{RESET}")
    print(f"{RED}" + "=" * 65 + f"{RESET}")

def check_dependencies():
    tools = ["subfinder", "assetfinder", "findomain", "gau", "httpx", "aquatone"]
    missing = []
    for tool in tools:
        if not shutil.which(tool):
            missing.append(tool)
    if missing:
        print(f"{RED}[!] Missing tools: {', '.join(missing)}{RESET}")
        print(f"{YELLOW}[*] Please install them and ensure they are in your $PATH.{RESET}")
        sys.exit(1)

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
        print(f"{RED}[!] Error running command: {e}{RESET}")
        return ""

def get_crtsh_subs(domain):
    print(f"{CYAN}[*] Querying crt.sh for {domain}...{RESET}")
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
    except Exception as e:
        print(f"{RED}[!] crt.sh failed: {e}{RESET}")
    return subs

def main():
    banner()
    parser = argparse.ArgumentParser(description="ZeroRecon")
    parser.add_argument("-t", "--target", required=True, help="Target domain")
    args = parser.parse_args()

    target = args.target
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_dir = f"recon_{target}_{date_str}"

    check_dependencies()

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    all_subs = set()

    # 1. Subfinder
    print(f"{GREEN}[+] Running Subfinder...{RESET}")
    sf_out = run_command(["subfinder", "-d", target, "-silent"])
    for line in sf_out.splitlines():
        all_subs.add(line)

    # 2. Assetfinder
    print(f"{GREEN}[+] Running Assetfinder...{RESET}")
    af_out = run_command(["assetfinder", "--subs-only", target])
    for line in af_out.splitlines():
        all_subs.add(line)
    
    # 3. Findomain
    print(f"{GREEN}[+] Running Findomain...{RESET}")
    fd_out = run_command(["findomain", "-t", target, "-q"])
    for line in fd_out.splitlines():
        all_subs.add(line)

    # 4. crt.sh
    crt_subs = get_crtsh_subs(target)
    all_subs.update(crt_subs)

    # 5. Gau
    print(f"{GREEN}[+] Running Gau (Historical)...{RESET}")
    gau_cmd = f"gau --subs {target} | awk -F/ '{{print $3}}' | grep '{target}'"
    gau_out = run_command(gau_cmd, shell=True)
    for line in gau_out.splitlines():
        clean_sub = line.split(':')[0]
        all_subs.add(clean_sub)

    # Save Subs
    print(f"{YELLOW}[*] Found {len(all_subs)} unique subdomains.{RESET}")
    subs_file = os.path.join(output_dir, "all_subdomains.txt")
    with open(subs_file, "w") as f:
        for sub in all_subs:
            f.write(f"{sub}\n")

    # 6. HTTPX
    print(f"{GREEN}[+] Probing live hosts with Httpx...{RESET}")
    live_hosts_file = os.path.join(output_dir, "live_hosts.txt")
    
    # [FIXED] Indentation is now correct below:
    httpx_cmd = f"cat {subs_file} | httpx -silent -threads 10 -title -tech-detect -status-code -follow-redirects"
    
    httpx_out = run_command(httpx_cmd, shell=True)
    
    live_urls = []
    for line in httpx_out.splitlines():
        if line:
            live_urls.append(line.split()[0])
    
    with open(live_hosts_file, "w") as f:
        for url in live_urls:
            f.write(f"{url}\n")
    
    print(f"{YELLOW}[*] Found {len(live_urls)} live hosts.{RESET}")

    # 7. Aquatone
    if live_urls:
        print(f"{GREEN}[+] Starting Aquatone...{RESET}")
        aquatone_dir = os.path.join(output_dir, "aquatone_session")
        cat_cmd = f"cat {live_hosts_file} | aquatone -out {aquatone_dir}"
        run_command(cat_cmd, shell=True)
        print(f"{CYAN}[DONE] Report: {aquatone_dir}/aquatone_report.html{RESET}")
    else:
        print(f"{RED}[!] No live hosts.{RESET}")

if __name__ == "__main__":
    main()
