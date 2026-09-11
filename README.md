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
[![Status](https://img.shields.io/badge/Status-Phase_10.1-brightred)](https://github.com/akheeltester/Demogorgon)

---

**Demogorgon** is a general-purpose autonomous security research agent. Give it any authorized bug bounty target and it will:
- Parse scope from any platform (HackerOne, Bugcrowd, Intigriti, Immunefi, custom)
- Enumerate subdomains and discover live assets
- Crawl endpoints, build an application model, and map the attack surface
- Use LLM reasoning to form hypotheses, design experiments, and select next actions
- Execute tests safely through an ActionGateway with scope enforcement + human-in-the-loop
- Collect evidence, validate findings, detect bug chains, and generate reports

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
│ • Scope      │ • Subdomain  │ • LLM Reason  │ • Packager       │
│ • Policy     │   enum       │ • Hypothesis  │ • Chain Detect   │
│ • Safety     │ • Live hosts │ • Experiment  │ • Validation     │
│   Gate       │ • Crawl      │   Planner    │ • Report Gen     │
│ • HITL Gate  │ • App Model  │ • Next Best   │ • State Persist  │
│              │              │   Action     │                  │
├──────────────┴──────────────┴──────────────┴───────────────────┤
│         ActionGateway → Scope Check → Safety → HITL → Execute  │
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

### 3. Diagnose

```bash
python -m demogorgon doctor
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
```

### 5. Test with Juice Shop (safe, local target)

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
  report             Generate JSON + Markdown report
  setup              Configuration wizard
  doctor             Diagnose environment + LLM connectivity
```

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
│   ├── gateway.py           ActionGateway (scope + safety + HITL)
│   ├── runner.py            AutonomousRunner (end-to-end orchestrator)
│   ├── context_builder.py   ResearchContextBuilder (bounded LLM context)
│   ├── decision.py          ResearchDecision (Pydantic schema)
│   └── interfaces.py        Core ABCs + ActionType enum
│
├── llm/
│   ├── manager.py           LLMManager (retry, fallback, health check)
│   ├── base.py              LLMProvider ABC + LLMResponse
│   └── providers/           openai.py, anthropic.py
│
├── recon/
│   └── engine.py            ReconEngine (8 stages)
│
├── tools/
│   ├── registry.py          ToolRegistry
│   ├── executor.py          ToolExecutor
│   └── adapters/            subfinder, httpx, katana, ffuf, nuclei, etc.
│
├── cli/
│   └── __init__.py          CLI entry point (argparse)
│
├── main.py                  Legacy entry point
├── researcher.py            Legacy researcher
└── app_model.py             ApplicationModel
```

---

## What Demogorgon Tests

| Vulnerability Class | Detection Method |
|---|---|
| IDOR | Sequential ID enumeration, cross-user access |
| XSS | Reflected, stored, DOM-based injection |
| SSRF | Internal URL fetch, cloud metadata |
| SQLi | Error-based, blind, time-based |
| CSRF | Missing tokens, cross-origin requests |
| Auth Bypass | Session fixation, role escalation |
| Open Redirect | Redirect chain manipulation |
| File Upload | Unrestricted upload, path traversal |
| Race Conditions | Concurrent request abuse |
| CORS | Misconfigured origin reflection |
| SSTI | Template injection payloads |
| XXE | XML external entity injection |
| JWT Weakness | Algorithm confusion, key leakage |
| Business Logic | Price manipulation, workflow bypass |
| Information Disclosure | Verbose errors, debug endpoints |

---

## Development

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run unit tests (360+ tests)
pytest demogorgon/core/tests/ -v

# Run integration tests (standalone)
python test_integration.py

# Run Phase 10.1 tests (LLM + research loop)
pytest demogorgon/core/tests/test_phase10_1.py -v

# Lint
ruff check demogorgon/
```

### Test Structure

| Suite | Tests | Description |
|-------|-------|-------------|
| `test_phase3.py` | 32 | Recon engine + asset intelligence |
| `test_phase4.py` | 25 | Crawler + app model + attack surface |
| `test_phase5.py` | 34 | LLM brain + reasoner + planner |
| `test_phase6.py` | 29 | Research loop + executor + evidence |
| `test_phase7.py` | 48 | Auth + HITL |
| `test_phase8.py` | 26 | Evidence packaging + validation |
| `test_phase9.py` | 20 | State persistence + reporting |
| `test_phase10.py` | 27 | Integration (gateway, runner, CLI) |
| `test_phase10_1.py` | 49 | LLM provider + decision schema + loop |
| `test_integration.py` | 39 | Full pipeline E2E (standalone) |

---

## Safety

- **Scope enforcement** — Every action passes through `SafetyGate` + `ScopeMatcher` before execution
- **Human-in-the-loop** — Configurable approval levels (NONE, AUTOMATIC, REQUIRED, CRITICAL)
- **Rate limiting** — Built-in request throttling with configurable delay
- **ActionGateway** — LLM proposes actions, deterministic code validates and executes
- **Crash resume** — State persists to disk; resume from last checkpoint

---

## Requirements

- **Python** 3.11+
- **LLM API key** (OpenAI, OpenRouter, Anthropic, or DeepSeek)
- **Security tools** (optional, auto-detected): subfinder, httpx, katana, ffuf, nuclei, naabu, dalfox

---

## License

[MIT](LICENSE)

---

<div align="center">

**Happy Hunting! Remember: Can an attacker do this RIGHT NOW against a real user? If no, STOP.**

</div>
