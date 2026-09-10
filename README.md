# Sentinel V2

Autonomous bug bounty hunting tool powered by LLM reasoning. Sentinel doesn't just scan — it **thinks**. It forms hypotheses, designs experiments, executes them, and evaluates results like a senior pentester.

## Features

- **LLM-Powered Reasoning** — Uses OpenRouter (free models available) to make intelligent testing decisions
- **8-Stage Hunt Pipeline** — Product understanding → endpoint discovery → hypothesis generation → experiment design → execution → evidence collection → finding validation → reporting
- **Browser Automation** — Persistent Playwright session with auto-capture of requests, tokens, forms, and JS state
- **Auth Testing** — Multi-session IDOR, privilege escalation, role-based access, and boundary testing
- **Deterministic Detectors** — Pattern-based detection for SQLi, XSS, info disclosure, SSTI, and CORS misconfigurations
- **HTTP Replay** — Replay captured requests with mutations (auth bypass, CSRF, method override, etc.)

## Quick Start

```bash
# Clone
git clone https://github.com/Akheel-Org/Organism.git
cd Organism/bugbounty-tool

# Setup (one command)
bash setup.sh

# Activate
source venv/bin/activate

# Configure API key (free at https://openrouter.ai/keys)
cp .env.example .env
# Edit .env and add: OPENROUTER_API_KEY=sk-or-v1-...

# Hunt a target
python -m sentinel_v2 https://target.com

# Hunt with V3 autonomous researcher
python -m sentinel_v2 https://target.com --v3

# Route through Burp Suite
python -m sentinel_v2 https://target.com --proxy http://127.0.0.1:8080
```

## Test with Juice Shop

The fastest way to validate the tool:

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
python -m sentinel_v2 http://localhost:3000
```

## Usage

```
python -m sentinel_v2 <target_url> [options]

Options:
  --headless          Run browser in headless mode (default: True)
  --no-headless       Run browser with visible GUI
  --proxy URL         Route traffic through a proxy (e.g., Burp Suite)
  --rate-limit SECS  Delay between requests (default: 1.0)
  --max-iterations N  Max reasoning iterations (default: 50)
  --output DIR        Output directory (default: hunt_output)
  --v3                Use V3 autonomous researcher
  --benchmark         Run benchmark mode against target
```

## Architecture

```
sentinel_v2/
  main.py              — Entry point & CLI
  researcher.py        — Core 8-stage hunt orchestrator
  researcher_v3.py     — V3 autonomous researcher
  memory.py            — Working memory (endpoints, findings, evidence)
  app_model.py         — Application understanding model
  llm_client.py        — OpenRouter LLM client with model rotation
  detectors.py         — Deterministic vulnerability detectors
  tools/
    browser.py         — Playwright browser automation
    http_client.py     — Async HTTP with rate limiting
    replay.py          — HTTP replay with mutations
  auth/
    authcore/          — Multi-session auth testing library
      session.py       — Auth sessions, cookies, JWT
      store.py         — SQLite session store
      idor_tester.py   — Cross-user IDOR testing
      role_tester.py   — Role-based access testing
      boundary_tester.py — Account boundary testing
  executors/           — Vulnerability-specific executors
    cors_detector.py
    ssti_detector.py
    info_disclosure_detector.py
    auth_bypass_tester.py
  programs/            — Per-target hunt data & findings
```

## Modules

| Module | Purpose |
|---|---|
| `researcher.py` | Orchestrates the full hunt pipeline |
| `researcher_v3.py` | Executive controller with parallel experiments |
| `browser.py` | Persistent Playwright with auto-capture |
| `replay.py` | 11 replay modes (auth bypass, CSRF, IDOR, etc.) |
| `authcore/` | Production-quality auth testing (7,400+ lines) |
| `detectors.py` | Pattern-based SQLi, XSS, info disclosure detection |
| `llm_client.py` | OpenRouter client with model rotation & retry |

## Getting API Keys

**OpenRouter (free):**
1. Go to https://openrouter.ai
2. Sign up → https://openrouter.ai/keys
3. Create a key (free tier: ~200 requests/day per model)
4. Add to `.env`: `OPENROUTER_API_KEY=sk-or-v1-...`

**Free models used:**
- `nvidia/llama-3.1-nemotron-70b-instruct:free` (primary)
- `meta-llama/llama-3.2-11b-vision-instruct:free` (fallback)

## Requirements

- Python 3.11+
- Playwright (auto-installed with Chromium)
- OpenRouter API key (free)

## License

MIT
