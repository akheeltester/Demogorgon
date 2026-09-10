<div align="center">

<img
  src="https://github.com/user-attachments/assets/4104de84-3952-4994-9d05-2e03eed3846d"
  alt="DEMOGORGON"
  width="180"
/>

<br>

<div align="center">
  <img src="https://readme-typing-svg.herokuapp.com/?font=Pixelify+Sans&weight=700&size=55&pause=2000&color=E50914&center=true&vCenter=true&width=600&lines=DEMOGORGON;" alt="Demogorgon Animated Text" />
</div>

### **Autonomous Bug Bounty Hunter Powered by LLM Reasoning**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Active-brightred)](https://github.com/akheeltester/Demogorgon)

---

**Demogorgon** doesn't just scanner it is an **Organism** **thinks** like Human. It forms hypotheses, designs experiments,
executes them, and evaluates results like a senior penetration tester.

</div>

---

## How It Works

```
  TARGET Domain
      │
      ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DEMOGORGON PIPELINE                          │
├─────────────┬──────────────┬──────────────┬────────────────────┤
│  STAGE 1    │   STAGE 2    │   STAGE 3    │     STAGE 4        │
│  DISCOVER   │   UNDERSTAND │   HYPOTHESIZE│     EXECUTE        │
│             │              │              │                    │
│ • Browser   │ • Product    │ • IDOR       │ • HTTP Replay      │
│ • Endpoints │   Type       │ • XSS        │ • Auth Bypass      │
│ • JS/API    │ • Roles      │ • SSRF       │ • CSRF             │
│ • Forms     │ • Workflows  │ • SQLi       │ • Race Conditions  │
│ • Tokens    │ • Trust      │ • Logic      │ • File Upload      │
│             │   Boundaries │ • Priv Esc   │ • SSTI / XXE       │
├─────────────┴──────────────┴──────────────┴────────────────────┤
│                    EVIDENCE → FINDINGS → REPORT                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Clone & Setup (one command)

```bash
git clone https://github.com/akheeltester/Demogorgon.git
cd Demogorgon
bash setup.sh
```

### 2. Configure API Key (free)

```bash
# Get free key at: https://openrouter.ai/keys
cp .env.example .env
# Edit .env and paste your key:
# OPENROUTER_API_KEY=sk-or-v1-your-key-here
```

### 3. Hunt

```bash
source venv/bin/activate

# Basic hunt
python -m demogorgon https://target.com

# Autonomous V3 mode (parallel experiments)
python -m demogorgon https://target.com --v3

# Through Burp Suite proxy
python -m demogorgon https://target.com --proxy http://127.0.0.1:8080

# Custom iterations
python -m demogorgon https://target.com --max-iterations 100
```

### 4. Test with Juice Shop (safe target)

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
python -m demogorgon http://localhost:3000
```

---

## CLI Options

```
python -m demogorgon <target_url> [options]

  --headless          Run browser headless (default)
  --no-headless       Show browser window
  --proxy URL         Route through Burp/ZAP
  --rate-limit SECS  Delay between requests (default: 1.0)
  --max-iterations N  Max reasoning loops (default: 50)
  --output DIR        Output directory (default: hunt_output)
  --v3                Use V3 autonomous researcher
  --benchmark         Run benchmark mode
```

---

## Modules

```
demogorgon/
│
├── main.py                 ← Entry point & CLI
├── researcher.py           ← Core 8-stage hunt orchestrator
├── researcher_v3.py        ← V3 autonomous controller
├── memory.py               ← Working memory
├── app_model.py            ← Application understanding
├── llm_client.py           ← OpenRouter LLM client
├── detectors.py            ← Deterministic vuln detectors
│
├── tools/
│   ├── browser.py          ← Playwright automation
│   ├── http_client.py      ← Async HTTP client
│   ├── replay.py           ← HTTP replay (11 mutation modes)
│   └── ...
│
├── auth/authcore/          ← Auth testing library
│   ├── session.py          ← Sessions, cookies, JWT
│   ├── idor_tester.py      ← Cross-user IDOR
│   ├── role_tester.py      ← Privilege escalation
│   └── ...
│
├── executors/              ← Vulnerability executors
│   ├── cors_detector.py
│   ├── ssti_detector.py
│   ├── xss_detector.py
│   ├── ssrf_tester.py
│   └── ...
│
├── controller/             ← V3 executive controller
├── are/                    ← Attack research engine
└── benchmark/              ← Benchmark runner
```

---

## What Demogorgon Detects

| Module | Vulnerability Class |
|---|---|
| `cors_detector` | CORS misconfiguration |
| `xss_detector` | Cross-Site Scripting |
| `ssti_detector` | Server-Side Template Injection |
| `ssrf_tester` | Server-Side Request Forgery |
| `xxe_detector` | XML External Entity |
| `idor_tester` | Insecure Direct Object Reference |
| `auth_bypass_tester` | Authentication Bypass |
| `csrf_tester` | Cross-Site Request Forgery |
| `info_disclosure_detector` | Information Disclosure |
| `race_detector` | Race Conditions |
| `jwt_attacker` | JWT Weakness |
| `upload_tester` | File Upload Abuse |
| `redirect_tester` | Open Redirect |
| `logic_tester` | Business Logic Flaws |

---

## Requirements

- **Python** 3.11+
- **OpenRouter API key** (free tier available)
- **Playwright** (auto-installed with Chromium)

---

## Getting Your Free API Key

1. Go to **https://openrouter.ai**
2. Sign up → Go to **https://openrouter.ai/keys**
3. Click **Create Key** — name it `Demogorgon`
4. Copy key (starts with `sk-or-...`)
5. Paste in `.env`: `OPENROUTER_API_KEY=sk-or-...`

**Free models:**
| Model | Role |
|---|---|
| `nvidia/llama-3.1-nemotron-70b-instruct:free` | Primary |
| `meta-llama/llama-3.2-11b-vision-instruct:free` | Fallback |

Free tier: ~200 requests/day per model. Auto-rotation on limit hit.

---

## Development

```bash
# Install dev deps
pip install -r requirements-dev.txt

# Run tests
pytest demogorgon/auth/authcore/tests/ -v

# Lint
ruff check demogorgon/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

[MIT](LICENSE)

---

<div align="center">

**Happy Hunting! Remember: Can an attacker do this RIGHT NOW against a real user? If no, STOP.**

</div>
