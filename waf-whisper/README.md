# WAF Whisper
**WAF Whisper** is a stealth-oriented firewall evasion tool. It identifies WAFs via passive header analysis and "whispers" payloads using advanced obfuscation to bypass detection rules.

## Usage
python3 waf_whisper.py --target https://example.com --payload "' OR 1=1 --"
