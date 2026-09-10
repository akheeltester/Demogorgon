# Tools Inventory - What We Have

## Go Binaries (Installed)

| Tool | Path | Version | Use |
|------|------|---------|-----|
| subfinder | `/home/akheel/go/bin/subfinder` | Latest | Passive subdomain enum |
| httpx | `/home/akheel/go/bin/httpx` | Latest | Probe live hosts |
| nuclei | `/home/akheel/go/bin/nuclei` | Latest | Template scanner |
| katana | `/home/akheel/go/bin/katana` | Latest | Crawl |
| gau | `/home/akheel/go/bin/gau` | Latest | Known URLs |
| dalfox | `/home/akheel/go/bin/dalfox` | Latest | XSS scanner |
| ffuf | `/usr/bin/ffuf` | Latest | Fuzzer |
| gf | `/home/akheel/go/bin/gf` | Latest | Grep patterns |
| dnsx | `/home/akheel/go/bin/dnsx` | Latest | DNS resolution |

## System Tools

| Tool | Path | Use |
|------|------|-----|
| curl | `/usr/bin/curl` | HTTP requests |
| jq | `/usr/bin/jq` | JSON parsing |
| dig | `/usr/bin/dig` | DNS queries |
| nmap | `/usr/bin/nmap` | Port scanning |
| nikto | `/usr/bin/nikto` | Web scanner |

## Python Tools (demogorgon)

| Tool | Path | Use |
|------|------|-----|
| recon.py | `demogorgon/tools/recon.py` | Recon automation |
| crawler.py | `demogorgon/tools/crawler.py` | Web crawling |
| ffuf_bridge.py | `demogorgon/tools/ffuf_bridge.py` | Fuzzing |
| nuclei_bridge.py | `demogorgon/tools/nuclei_bridge.py` | Vulnerability scanning |
| http_client.py | `demogorgon/tools/http_client.py` | HTTP requests |
| browser.py | `demogorgon/tools/browser.py` | Browser automation |
| auth.py | `demogorgon/tools/auth.py` | Authentication handling |
| reporter.py | `demogorgon/tools/reporter.py` | Report generation |
| katana_bridge.py | `demogorgon/tools/katana_bridge.py` | Crawling |
| amass_bridge.py | `demogorgon/tools/amass_bridge.py` | Subdomain enum |

## Missing Tools (Install if needed)

```bash
# waybackurls
go install github.com/tomnomnom/waybackurls@latest

# interactsh-client (OOB callbacks)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# kiterunner (API endpoint brute)
go install github.com/assetnote/kiterunner/cmd/kr@latest

# subzy (subdomain takeover check)
go install github.com/LukaSikic/subzy@latest

# arjun (hidden parameter discovery)
pip3 install arjun

# paramspider (URL parameter mining)
pip3 install paramspider

# SecretFinder (JS secret extraction)
git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
cd ~/tools/SecretFinder && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# LinkFinder (endpoints in JS)
git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
cd ~/tools/LinkFinder && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

## Wordlists

```bash
# Check if SecLists is installed
ls /usr/share/seclists/ 2>/dev/null || echo "Install: apt install seclists"

# Common wordlists
ls ~/wordlists/ 2>/dev/null || echo "Create: mkdir ~/wordlists"
```

## Quick Commands

```bash
# Full recon pipeline
TARGET="example.com" && subfinder -d $TARGET -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/live.txt

# Quick nuclei scan
nuclei -l /tmp/live.txt -severity critical,high,medium

# ffuf directory fuzzing
ffuf -u "https://target.com/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac

# dalfox XSS scan
dalfox url "https://target.com/?q=test" --skip-bav
```
