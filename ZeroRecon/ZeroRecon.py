#!/usr/bin/env python3

import os
import sys
import subprocess
import requests
import argparse
import shutil
import re
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
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

# =========================================================================
# v5.0 ADDITIONS BELOW  --  everything above is preserved from v4.0 as-is.
# Strictly ADDITIVE: all new behavior is opt-in via new flags with safe
# defaults, or purely additive passive OSINT that only ADDS findings.
# Author: R00t3dbyFa17h / K70n0s510  (HTB, Bugcrowd, Microsoft, Intigriti, Google)
# =========================================================================

VERSION = "5.0"
QUIET = False

def qprint(msg):
    if not QUIET:
        print(msg)

# ---- Passive OSINT sources (pure Python + requests; NO new binaries) -----
# These are keyed OSINT archive lookups (same class as the existing crt.sh
# fallback). They only ADD subdomains. Opt-in via --osint.

def clean_subdomains(candidates, domain):
    """Normalize + validate a set of candidate hostnames for `domain`."""
    out = set()
    d = domain.lower().lstrip('.')
    for c in candidates:
        if not c:
            continue
        c = c.strip().lower().rstrip('.')
        c = c.replace('*.', '').replace('%2a.', '')
        if ' ' in c or '*' in c or '/' in c or '@' in c:
            continue
        if c == d or c.endswith('.' + d):
            out.add(c)
    return out

def _parse_hostnames_from_urls(text):
    hosts = set()
    for line in text.splitlines():
        line = line.strip()
        m = re.search(r'https?://([^/:\s]+)', line)
        if m:
            hosts.add(m.group(1))
        elif line and '/' not in line:
            hosts.add(line)
    return hosts

def _osint_get(session, url, timeout):
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code == 200:
            return r
    except requests.RequestException:
        return None
    return None

def osint_hackertarget(session, domain, timeout):
    r = _osint_get(session, f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout)
    subs = set()
    if r and 'error' not in r.text.lower() and 'api count' not in r.text.lower():
        for line in r.text.splitlines():
            subs.add(line.split(',')[0])
    return clean_subdomains(subs, domain)

def osint_otx(session, domain, timeout):
    r = _osint_get(session, f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", timeout)
    subs = set()
    if r:
        try:
            for e in r.json().get('passive_dns', []):
                subs.add(e.get('hostname', ''))
        except ValueError:
            pass
    return clean_subdomains(subs, domain)

def osint_rapiddns(session, domain, timeout):
    r = _osint_get(session, f"https://rapiddns.io/subdomain/{domain}?full=1", timeout)
    subs = set()
    if r:
        for m in re.findall(r'<td>([a-zA-Z0-9_.\-]+\.' + re.escape(domain) + r')</td>', r.text):
            subs.add(m)
    return clean_subdomains(subs, domain)

def osint_anubis(session, domain, timeout):
    r = _osint_get(session, f"https://jldc.me/anubis/subdomains/{domain}", timeout)
    subs = set()
    if r:
        try:
            subs.update(r.json())
        except ValueError:
            pass
    return clean_subdomains(subs, domain)

def osint_urlscan(session, domain, timeout):
    r = _osint_get(session, f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=10000", timeout)
    subs = set()
    if r:
        try:
            for res in r.json().get('results', []):
                page = res.get('page', {})
                subs.add(page.get('domain', ''))
        except ValueError:
            pass
    return clean_subdomains(subs, domain)

def osint_wayback(session, domain, timeout):
    url = (f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
           f"&output=text&fl=original&collapse=urlkey&limit=20000")
    r = _osint_get(session, url, timeout)
    subs = set()
    if r:
        subs = _parse_hostnames_from_urls(r.text)
        subs = {h.split(':')[0] for h in subs}
    return clean_subdomains(subs, domain)

def osint_certspotter(session, domain, timeout):
    url = (f"https://api.certspotter.com/v1/issuances?domain={domain}"
           f"&include_subdomains=true&expand=dns_names")
    r = _osint_get(session, url, timeout)
    subs = set()
    if r:
        try:
            for issuance in r.json():
                for name in issuance.get('dns_names', []):
                    subs.add(name)
        except ValueError:
            pass
    return clean_subdomains(subs, domain)

OSINT_SOURCES = {
    "HackerTarget": osint_hackertarget,
    "AlienVault OTX": osint_otx,
    "RapidDNS": osint_rapiddns,
    "Anubis (jldc)": osint_anubis,
    "URLScan.io": osint_urlscan,
    "Wayback CDX": osint_wayback,
    "CertSpotter": osint_certspotter,
}

def gather_osint(domain, threads=7, timeout=25):
    """Run all passive OSINT sources concurrently. Returns (subs, per_source)."""
    session = requests.Session()
    session.headers.update({'User-Agent': 'ZeroRecon/' + VERSION + ' (+passive-osint)'})
    merged = set()
    per_source = {}
    qprint(f"{GREEN}[+] Passive OSINT: querying {len(OSINT_SOURCES)} archive sources (no binaries)...{RESET}")
    with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        futs = {pool.submit(fn, session, domain, timeout): name
                for name, fn in OSINT_SOURCES.items()}
        for fut in as_completed(futs):
            name = futs[fut]
            try:
                found = fut.result()
            except Exception:
                found = set()
            per_source[name] = len(found)
            merged |= found
            qprint(f"{CYAN}    -> {name}: {len(found)} subdomains{RESET}")
    return merged, per_source

# ---- Machine-readable + visual reports (additive; never replace files) ---

def write_json_report(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    qprint(f"{GREEN}[+] JSON summary written: {path}{RESET}")

def write_html_report(path, data):
    subs = sorted(data.get("subdomains", []))
    live = sorted(data.get("live_hosts", []))
    rows_src = "".join(
        f'<span class="chip">{k}: <b>{v}</b></span>' for k, v in data.get("osint_sources", {}).items()
    )
    html = f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ZeroRecon Report: {data.get('target','')}</title>
<style>
 body{{background:#0d1117;color:#c9d1d9;font-family:sans-serif;padding:20px;}}
 h1{{color:#f85149;}} h2{{color:#58a6ff;border-bottom:1px solid #30363d;padding-bottom:6px;}}
 .chip{{display:inline-block;border:1px solid #30363d;border-radius:14px;padding:3px 10px;margin:3px;background:#161b22;font-size:13px;}}
 .col{{display:flex;gap:20px;flex-wrap:wrap;}} .box{{flex:1;min-width:300px;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:10px;}}
 .item{{font-family:monospace;font-size:13px;padding:2px 4px;border-bottom:1px solid #21262d;word-break:break-all;}}
 input{{width:100%;max-width:420px;padding:8px;margin:10px 0;background:#161b22;border:1px solid #30363d;border-radius:6px;color:#c9d1d9;}}
 footer{{margin-top:24px;color:#8b949e;font-size:12px;border-top:1px solid #30363d;padding-top:10px;}}
</style></head><body>
 <h1>&#128721; ZeroRecon Report <span style="font-size:14px;color:#8b949e">v{VERSION}</span></h1>
 <p><b>Target:</b> {data.get('target','')} &nbsp; <b>Generated:</b> {data.get('generated','')}</p>
 <p><span class="chip">Subdomains: <b>{len(subs)}</b></span>
    <span class="chip">Live Hosts: <b>{len(live)}</b></span> {rows_src}</p>
 <input type="text" placeholder="&#128269; filter..." onkeyup="f(this.value)">
 <div class="col">
  <div class="box"><h2>Subdomains ({len(subs)})</h2>{''.join(f'<div class="item s">{s}</div>' for s in subs)}</div>
  <div class="box"><h2>Live Hosts ({len(live)})</h2>{''.join(f'<div class="item s">{h}</div>' for h in live)}</div>
 </div>
 <footer>ZeroRecon v{VERSION} &mdash; R00t3dbyFa17h / K70n0s510. Authorized testing only.</footer>
<script>function f(q){{q=q.toLowerCase();document.querySelectorAll('.item.s').forEach(function(e){{e.style.display=e.textContent.toLowerCase().indexOf(q)>-1?'':'none';}});}}</script>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)
    qprint(f"{GREEN}[+] HTML report written: {path}{RESET}")

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

    # --- v5.0 additive flags (all opt-in, safe defaults) ---
    parser.add_argument("--version", action="version",
                        version=f"ZeroRecon v{VERSION} - R00t3dbyFa17h / K70n0s510")
    parser.add_argument("--osint", action="store_true",
                        help="Passive OSINT boost: query 7 archive sources (HackerTarget, OTX, RapidDNS, Anubis, URLScan, Wayback, CertSpotter) — no extra binaries")
    parser.add_argument("--history", action="store_true",
                        help="Dump historical URLs via gau/waybackurls (if installed)")
    parser.add_argument("--ports", action="store_true",
                        help="Port-scan live hosts with naabu (if installed)")
    parser.add_argument("--screenshots", action="store_true",
                        help="Screenshot live hosts with gowitness/aquatone (if installed)")
    parser.add_argument("--dns", "--dnsx", dest="dns", action="store_true",
                        help="Resolve subdomains with dnsx (if installed)")
    parser.add_argument("--gf", action="store_true",
                        help="Run gf patterns over crawled URLs (if installed)")
    parser.add_argument("--json", action="store_true", help="Write a JSON summary report")
    parser.add_argument("--html", action="store_true", help="Write an HTML report")
    parser.add_argument("-o", "--output-dir", dest="output_dir", help="Custom output directory")
    parser.add_argument("--threads", type=int, default=25, help="Probe/concurrency threads (default: 25)")
    parser.add_argument("--wordlist", help="Wordlist for puredns brute force (--paranoid)")
    parser.add_argument("--resolvers", help="Resolvers file for puredns (default: resolvers.txt)")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress extra v5.0 output")

    args = parser.parse_args()

    global QUIET
    QUIET = args.quiet

    # WEBHOOK
    webhook_url = args.webhook
    if not webhook_url: webhook_url = os.environ.get("DISCORD_WEBHOOK")

    target = args.target
    date_str = datetime.now().strftime("%Y-%m-%d")
    output_dir = args.output_dir or f"recon_{target}_{date_str}"
    osint_sources_stats = {}

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

    # 6.5 Passive OSINT boost (v5.0, opt-in via --osint; pure Python) - ADDITIVE
    if args.osint:
        osint_subs, osint_sources_stats = gather_osint(target, threads=args.threads)
        before = len(all_subs)
        all_subs.update(osint_subs)
        qprint(f"{YELLOW}[*] OSINT added {len(all_subs) - before} new subdomains "
               f"({len(osint_subs)} total from archives).{RESET}")

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
        wordlist = args.wordlist or "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        resolvers = args.resolvers or "resolvers.txt"
        if os.path.exists(wordlist):
            out = run_command(f"puredns bruteforce {wordlist} {target} -r {resolvers} --quiet", shell=True)
            for line in out.splitlines(): all_subs.add(line)
        else:
            print(f"{RED}[!] Wordlist not found for Puredns. Skipping.{RESET}")

    # ==========================================
    # PHASE 3: DOUBLE-PROBE VERIFICATION
    # ==========================================
    print(f"\n{BOLD}{YELLOW}[PHASE 2] Probing Live Hosts (Double-Check)...{RESET}")
    
    # Check 1: HTTPX
    print(f"{GREEN}[+] HTTPX Probe...{RESET}")
    run_command(f"cat {subs_file} | httpx -silent -threads {args.threads} -o {output_dir}/alive_httpx.txt", shell=True)
    
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

        # ---- v5.0 ADDITIVE PHASES (opt-in; only run if binary present) ----
        if args.dns and shutil.which("dnsx"):
            qprint(f"\n{BOLD}{YELLOW}[PHASE 6] DNS Resolution (dnsx)...{RESET}")
            run_command(f"cat {subs_file} | dnsx -silent -a -resp -o {output_dir}/resolved_dns.txt", shell=True)

        if args.ports and shutil.which("naabu"):
            qprint(f"\n{BOLD}{YELLOW}[PHASE 7] Port Scan (naabu top-ports)...{RESET}")
            run_command(f"naabu -list {output_dir}/live_hosts.txt -top-ports 1000 -silent -o {output_dir}/ports.txt", shell=True)

        if args.history:
            qprint(f"\n{BOLD}{YELLOW}[PHASE 8] Historical URL Mining...{RESET}")
            if shutil.which("gau"):
                run_command(f"cat {output_dir}/live_hosts.txt | gau --subs > {output_dir}/history_urls.txt 2>/dev/null", shell=True)
            elif shutil.which("waybackurls"):
                run_command(f"cat {output_dir}/live_hosts.txt | waybackurls > {output_dir}/history_urls.txt", shell=True)

        if args.gf and shutil.which("gf") and os.path.exists(f"{output_dir}/crawled.txt"):
            qprint(f"\n{BOLD}{YELLOW}[PHASE 9] GF Pattern Matching (quick win candidates)...{RESET}")
            for pat in ["xss", "sqli", "ssrf", "redirect", "idor", "lfi"]:
                run_command(f"cat {output_dir}/crawled.txt | gf {pat} >> {output_dir}/gf_{pat}.txt 2>/dev/null", shell=True)

        if args.screenshots:
            tool = "gowitness" if shutil.which("gowitness") else ("aquatone" if shutil.which("aquatone") else None)
            if tool == "gowitness":
                qprint(f"\n{BOLD}{YELLOW}[PHASE 10] Screenshots (gowitness)...{RESET}")
                run_command(f"gowitness scan file -f {output_dir}/live_hosts.txt --screenshot-path {output_dir}/screenshots", shell=True)
            elif tool == "aquatone":
                qprint(f"\n{BOLD}{YELLOW}[PHASE 10] Screenshots (aquatone)...{RESET}")
                run_command(f"cat {output_dir}/live_hosts.txt | aquatone -out {output_dir}/screenshots", shell=True)

    # ---- v5.0 ADDITIVE REPORTS (opt-in) ----
    if args.json or args.html:
        live_hosts = []
        lh_path = f"{output_dir}/live_hosts.txt"
        if os.path.exists(lh_path):
            with open(lh_path) as f:
                live_hosts = [l.strip() for l in f if l.strip()]
        report_data = {
            "tool": "ZeroRecon",
            "version": VERSION,
            "target": target,
            "generated": datetime.now().strftime("%Y-%m-%dT%H:%M:%S"),
            "counts": {"subdomains": len(all_subs), "live_hosts": len(live_hosts)},
            "osint_sources": osint_sources_stats,
            "subdomains": sorted(all_subs),
            "live_hosts": sorted(live_hosts),
        }
        if args.json:
            write_json_report(os.path.join(output_dir, "zerorecon_summary.json"), report_data)
        if args.html:
            write_html_report(os.path.join(output_dir, "zerorecon_report.html"), report_data)

    print(f"\n{CYAN}--------------------------------------------------{RESET}")
    print(f"{GREEN}[COMPLETED] Results: {output_dir}{RESET}")

if __name__ == "__main__":
    main()
