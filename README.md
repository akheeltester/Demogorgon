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

### **Autonomous Bug Bounty Research Agent — LLM-Driven, Scope-Aware, Human-Overrideable**

[![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python&logoColor=white)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Status-Phase_17-brightred)](https://github.com/akheeltester/Demogorgon)
[![Tests](https://img.shields.io/badge/tests-420%2B-brightgreen)](#development)

---

**Demogorgon** is a general-purpose autonomous security research agent. Give it any authorized bug bounty target and it will:
- Parse scope from any platform (HackerOne, Bugcrowd, Intigriti, Immunefi, custom)
- Enumerate subdomains and discover live assets (parallel probing)
- Crawl endpoints, build an application model, and map the attack surface
- Use **Laya** (dual-model decision engine) + LLM reasoning to form hypotheses and select next actions
- Execute tests safely through an ActionGateway with scope enforcement + human-in-the-loop
- Run deterministic executors (SSRF, upload, IDOR, …) and external tools (subfinder, httpx, nuclei, ffuf)
- Collect evidence, validate findings, detect bug chains, score **CVSS 3.1**, generate **PoC + platform-ready reports**
- Track **hunt metrics** (rates, coverage, severity breakdown) to measure improvement

The LLM is ONE reasoning component inside the brain — deterministic code handles execution, safety, and validation.

</div>

---

## Architecture

```
  Program Policy (any platform)
       │
       ▼
┌─────────────────────────────────────────────────────────────────┐
│                    DEMOGORGON PIPELINE                          │
├──────────────┬──────────────┬──────────────┬───────────────────┤
│  PHASE 1     │  PHASE 2-4   │  PHASE 5-6   │  PHASE 7-10      │
│  ENGAGEMENT  │  RECON       │  RESEARCH     │  EVIDENCE        │
│              │              │  BRAIN        │                  │
│ • Scope      │ • Subdomain  │ • Laya decide │ • Packager       │
│ • Policy     │   enum       │ • LLM reason  │ • Chain Detect   │
│ • Safety     │ • Live hosts │ • Hypothesis  │ • CVSS + PoC     │
│   Gate       │ • Parallel   │ • Experiment  │ • Validation     │
│ • HITL Gate  │   probe      │   Planner    │ • Report Gen     │
│              │ • App Model  │ • Next Best   │ • Metrics Persist│
│              │              │   Action     │                  │
├──────────────┴──────────────┴──────────────┴───────────────────┤
│         ActionGateway → Scope Check → Safety → HITL → Execute  │
│         ToolManager → subfinder/httpx/nuclei/ffuf/katana/nmap   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

### 1. Clone & Install

```bash
git clone https://github.com/akheeltester/Demogorgon.git
cd Demogorgon
python -m venv venv
source venv/bin/activate
pip install -e .
```

### 2. Configure LLM Provider

```bash
cp .env.example .env
# Edit .env with your API key
```

**Supported providers:**

| Provider | Model Example | Base URL |
|----------|--------------|----------|
| OpenAI | `gpt-4o-mini` | `https://api.openai.com/v1` |
| OpenRouter | `nvidia/llama-3.1-nemotron-70b-instruct:free` | `https://openrouter.ai/api/v1` |
| Anthropic | `claude-sonnet-4-20250514` | (auto) |
| DeepSeek | `deepseek-chat` | `https://api.deepseek.com/v1` |
| Ollama | `llama3.1` | `http://localhost:11434/v1` |

```env
# .env
DEMOGORGON_LLM_PROVIDER=openai
DEMOGORGON_API_KEY=sk-your-key-here
DEMOGORGON_MODEL=gpt-4o-mini
```

### 3. Diagnose + Install Tools

```bash
# Environment + LLM diagnostics
python -m demogorgon doctor

# List security tools (subfinder, httpx, nuclei, ffuf, nmap, …)
python -m demogorgon tools

# Install any missing tools (go / apt / brew)
python -m demogorgon tools install
python -m demogorgon tools install subfinder
```

Checks: Python version, installed tools, LLM connectivity, latency, structured output.

### 4. Hunt

```bash
# Interactive menu
python -m demogorgon

# Quick scan against a target
python -m demogorgon https://example.com

# Paste a HackerOne/Bugcrowd program policy
python -m demogorgon --program

# Resume a previous engagement
python -m demogorgon resume

# Show last hunt metrics (rates, severity breakdown)
python -m demogorgon metrics
```

### 5. Web Interface (Cyber-Command Center)

```bash
# Start the web control center
python -m demogorgon web

# Open http://localhost:8000 in your browser
```

The web UI provides:
- **Setup page** — Configure LLM providers (OpenAI, OpenRouter, Anthropic, DeepSeek, Gemini, Ollama) with **dual-model** (fast + reasoning) support
- **New Hunt** — Create engagements with target, program policy, budget meters, and tips
- **Dashboard** — Live research monitoring with WebSocket event stream (auto-reconnect), findings, scope management
- **Hunts** — KPI strip, filter pills, running/paused/completed engagement cards
- **Findings** — Search, severity filters, sort, detail modal, Copy as Markdown

### 6. Test with Juice Shop (safe, local target)

```bash
docker run -d -p 3000:3000 bkimminich/juice-shop
python -m demogorgon http://localhost:3000
```

---

## CLI Commands

```
python -m demogorgon [target] [command]

Commands:
  (no args)          Interactive menu
  <target_url>       Start research against a target
  --program          Paste a program policy (HackerOne, Bugcrowd, etc.)
  resume             Resume a paused/stopped engagement
  status             Show engagement status
  findings           List confirmed findings
  report             Generate JSON + Markdown report (CVSS + PoC)
  setup              Configuration wizard
  doctor             Diagnose environment + LLM connectivity
  web                Launch web control center
  tools              List installed / missing security tools
  tools install [x]  Install missing tools (or a specific tool)
  metrics [path]     Show hunt metrics (default: hunt_output/metrics.json)
```

---

## New in P2 (this release)

| Feature | Module | Usage |
|---|---|---|
| **Laya decision engine** | `demogorgon/laya/` | Strategy / continue-stop / triage during hunt |
| **Dual-model LLM** | `llm/manager.py` | Fast model + reasoning model via provider setup |
| **ToolManager** | `tools/manager.py` | Structured adapters: subfinder, amass, httpx, nuclei, ffuf, katana, nmap |
| **Parallel execution** | `tools/parallel.py` | Concurrent endpoint probing + race-condition replay |
| **Tool installer** | `tools/installer.py` | `demogorgon tools install` via go/apt/brew |
| **Subdomain enum** | Phase 1 recon | crt.sh + subfinder + DNS brute + parallel live probe |
| **SSRF / Upload executors** | `executors/` | Auto-invoked when vuln_class matches |
| **CVSS 3.1 scoring** | `core/cvss.py` | Base score + vector on every finding |
| **PoC generation** | `core/poc.py` | curl + HTTP transcript + steps |
| **Hunt metrics** | `core/metrics.py` | Saved to `hunt_output/metrics.json` |
| **Report quality** | `tools/reporter.py` | Remediation + HackerOne/Bugcrowd templates |

### External tools (auto-detected)

| Tool | Purpose |
|------|---------|
| subfinder / amass | Passive subdomain enumeration |
| httpx | Live host probing |
| nuclei | Template vulnerability scanning |
| ffuf | Directory / parameter fuzzing |
| katana | Web crawling |
| nmap / naabu | Port scanning |
| sqlmap | SQL injection |
| dnsx | DNS toolkit |

Install all missing: `python -m demogorgon tools install`

---

## Program Policy Format

Demogorgon accepts scope from any bug bounty platform. Paste the raw policy text and it auto-detects the platform:

```
Platform: HackerOne
Program: example-program
Scope:
  *.example.com - Web Application
  api.example.com - API
Exclusions:
  admin.example.com
  staging.example.com
```

**Auto-detected platforms:** HackerOne, Bugcrowd, Intigriti, Immunefi, GitHub, custom/manual.

---

## Module Structure

```
demogorgon/
├── core/
│   ├── engagement/          Engagement + ProgramPolicy + ScopeAsset
│   ├── scope/               ScopeParser + ScopeMatcher + SafetyGate
│   ├── auth/                Session management + auth strategies
│   ├── hitl/                Human-in-the-loop gate + pause controller
│   ├── brain/               LLMReasoner + Planner + Validator + ResearchBrain
│   ├── research_loop/       ResearchLoop + PlanExecutor + EvidenceCollector
│   ├── evidence/            EvidencePackager + types
│   ├── validation/          ValidationPipeline (FP/TP detection)
│   ├── chains/              BugChainDetector (8 known patterns)
│   ├── state/               StateManager (crash resume)
│   ├── reporting/           ReportGenerator (JSON + Markdown)
│   ├── cvss.py              CVSS 3.1 base score calculator
│   ├── poc.py               PoC generation (curl + HTTP transcript)
│   ├── metrics.py           HuntMetrics + MetricsCollector (JSON persist)
│   ├── decision_trace.py    Laya decision audit trail
│   ├── gateway.py           ActionGateway (scope + safety + HITL)
│   ├── runner.py            AutonomousRunner (end-to-end orchestrator)
│   ├── context_builder.py   ResearchContextBuilder (bounded LLM context)
│   ├── decision.py          ResearchDecision (Pydantic schema)
│   └── interfaces.py        Core ABCs + ActionType enum
│
├── laya/
│   ├── engine.py            LayaEngine (strategy / stop / triage / prioritize)
│   └── fallback.py          Deterministic fallbacks when LLM unavailable
│
├── llm/
│   ├── manager.py           AIProviderManager (dual-model, retry, health)
│   ├── base.py              LLMProvider ABC + LLMResponse
│   └── providers/           openai.py, anthropic.py, gemini.py
│
├── recon/
│   └── engine.py            ReconEngine (8 stages)
│
├── tools/
│   ├── manager.py           ToolManager (scope-aware adapter host)
│   ├── parallel.py          ParallelExecutor (batches + race replay)
│   ├── installer.py         ToolInstaller (go/apt/brew recipes)
│   ├── reporter.py          Reporter (CVSS, PoC, remediation, H1/Bugcrowd)
│   ├── registry.py          ToolRegistry
│   ├── executor.py          ToolExecutor
│   └── adapters/            subfinder, amass, httpx, nuclei, ffuf, katana, nmap
│
├── auth/
│   ├── bridge.py            AuthManager (multi-session)
│   └── authcore/            IDOR tester, role tester, object inventory, session store
│
├── web/
│   ├── app.py               FastAPI web control center (Cyber-Command Center UI)
│   ├── ws_bridge.py         WebSocket event bridge (auto-reconnect)
│   └── models.py            Pydantic request/response models
│
├── executors/               16 deterministic security testers (incl. SSRF, upload)
├── are/                     Adaptive Research Engine (knowledge base, chain finder, etc.)
├── controller/              Executive controller, tool selection, self-evaluator
├── cli/
│   ├── theme.py             Shared banner, severity styles, tables
│   ├── setup.py             Themed setup wizard
│   └── __init__.py          CLI entry (argparse): hunt, tools, metrics, …
│
├── main.py                  Legacy entry point
├── researcher.py            V2 researcher
├── researcher_v3.py         V3 researcher (recommended)
├── research_loop.py         Main brain (Laya + executors + metrics)
├── memory.py                Working memory + persistence
├── app_model.py             Application model
├── detectors.py             Deterministic vulnerability detection patterns
└── reasoning_trace.py       Decision logging
```

---

## What Demogorgon Tests

| Vulnerability Class | Detection Method |
|---|---|
| IDOR | Sequential ID enumeration, cross-user access |
| XSS | Reflected, stored, DOM-based injection |
| SQLi | Error-based, blind, time-based |
| CSRF | Missing tokens, cross-origin requests |
| Auth Bypass | Session fixation, role escalation |
| Open Redirect | Redirect chain manipulation |
| File Upload | Unrestricted upload, path traversal, webshell content |
| Race Conditions | Concurrent request abuse (parallel replay) |
| SSRF | Internal URL fetch, cloud metadata, file:// (deterministic executor) |
| CORS | Misconfigured origin reflection |
| SSTI | Template injection payloads |
| XXE | XML external entity injection |
| JWT Weakness | Algorithm confusion, key leakage |
| Business Logic | Price manipulation, workflow bypass |
| Information Disclosure | Verbose errors, debug endpoints |

Findings are scored with **CVSS 3.1**, packaged with **automated PoC** (curl + transcript),
and enriched with **remediation** guidance + HackerOne/Bugcrowd-ready templates.

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run full unit tests (420+ tests)
pytest demogorgon/ -q

# Verbose
pytest demogorgon/ -v

# P2 feature suite (parallel, CVSS, PoC, metrics, installer, reporter)
pytest demogorgon/core/tests/test_p2_features.py -v

# Lint
ruff check demogorgon/
```

### Test Structure

| Suite | Description |
|-------|-------------|
| `test_phase3.py` | Recon engine + asset intelligence |
| `test_phase4.py` | Crawler + app model + attack surface |
| `test_phase5.py` | LLM brain + reasoner + planner |
| `test_phase6.py` | Research loop + executor + evidence |
| `test_phase7.py` | Auth + HITL |
| `test_phase8.py` | Evidence packaging + validation |
| `test_phase9.py` | State persistence + reporting |
| `test_phase10.py` | Integration (gateway, runner, CLI) |
| `test_phase10_1.py` | LLM provider + decision schema + loop |
| `test_laya_engine.py` | Laya decision engine |
| `test_tool_manager.py` | ToolManager + adapters |
| `test_pipeline_integration.py` | Scope → Safety → Laya → Tool → Trace |
| `test_persistence_ws.py` | Checkpoint + WebSocket bridge |
| `test_p2_features.py` | Parallel, CVSS, PoC, metrics, installer, reporter |
| `test_integration.py` | Full pipeline E2E (standalone) |

---

## Safety

- **Scope enforcement** — Every action passes through `SafetyGate` + `ScopeMatcher` before execution
- **Human-in-the-loop** — Configurable approval levels (NONE, AUTOMATIC, REQUIRED, CRITICAL)
- **Rate limiting** — Built-in request throttling with configurable delay
- **ActionGateway** — LLM proposes actions, deterministic code validates and executes
- **Crash resume** — State persists to disk; resume from last checkpoint
- **Decision trace** — Every Laya decision is audited (strategy, confidence, outcome)

---

## Requirements

- **Python** 3.11+
- **LLM API key** (OpenAI, OpenRouter, Anthropic, or DeepSeek) — dual-model recommended
- **Security tools** (optional): install via `python -m demogorgon tools install`
  - subfinder, httpx, nuclei, ffuf, katana, nmap, amass, dnsx, naabu, sqlmap

---

## License

[MIT](LICENSE)

---

<div align="center">

**Happy Hunting! Remember: Can an attacker do this RIGHT NOW against a real user? If no, STOP.**

</div>
