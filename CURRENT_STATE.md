# Demogorgon — Current State & User Guide

## What is Demogorgon

Demogorgon is an autonomous bug bounty hunting tool. You give it a target URL, and it:

1. **Discovers** the attack surface (endpoints, parameters, tech stack)
2. **Hypothesizes** what vulnerabilities might exist (LLM-driven reasoning)
3. **Tests** each hypothesis with deterministic security executors
4. **Scores** every finding on 5 dimensions (evidence, impact, reproducibility, business value, exploitability)
5. **Reports** only high-confidence findings (>=85%) with full evidence chains

It does NOT do magic. Every decision is logged. Every finding has a reasoning trace.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLI (main.py)                        │
│         python -m demogorgon <target> --v3                  │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                    ResearcherV3                              │
│            Initializes all components                       │
│            Creates ResearchLoop                             │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│                      ResearchLoop                            │
│                                                              │
│  Phase 1: UNDERSTAND  ─── HTTP probe, tech stack detection   │
│  Phase 2: MODEL       ─── Build application model            │
│  Phase 3: REASON → EXPERIMENT → OBSERVE → ADAPT (loop)      │
│                                                              │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐   │
│  │ LLM decides  │  │ Deterministic│  │ Confidence Engine │   │
│  │ WHAT & WHY   │  │ Executors    │  │ scores 5 dims     │   │
│  │              │  │ test HOW     │  │                    │   │
│  └─────────────┘  └──────────────┘  └──────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### Key Components

| Component | Purpose |
|-----------|---------|
| `ResearchLoop` | Main brain — orchestrates the entire hunt |
| `ExecutiveController` | Selects which executor to run based on hypothesis |
| `ExecutionGraph` | Tracks the hypothesis → experiment → finding chain |
| `ExploitConfidenceEngine` | 5-dimension scoring (evidence, impact, reproducibility, business value, exploitability) |
| `ChainFinder` | Discovers multi-step attack chains |
| `AttackGraph` | Tracks endpoint relationships and attack paths |
| `KnowledgeBase` | Tech stack detection → common vulnerability patterns |
| `MutationIntelligence` | Smart payload mutations (IDOR, JWT, etc.) |
| `Checkpoint` | Crash recovery — saves state every 10 experiments |
| `ScopeValidator` | Ensures all requests stay in scope |

---

## Installation

```bash
cd bugbounty-tool
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Environment Variables

```bash
# Required for V2 mode (default)
export OPENROUTER_API_KEY="your-key-here"

# V3 mode uses LLMManager which auto-detects providers
# Set any of: OPENROUTER_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY
```

---

## Usage

### Basic Hunt (V3 — Recommended)

```bash
python -m demogorgon https://target.com --v3
```

### With Proxy (Burp Suite)

```bash
python -m demogorgon https://target.com --v3 --proxy http://127.0.0.1:8080
```

### Custom Settings

```bash
python -m demogorgon https://target.com --v3 \
    --max-iterations 100 \
    --rate-limit 0.5 \
    --output my_hunt \
    --no-headless
```

### V2 Mode (Legacy)

```bash
python -m demogorgon https://target.com
```

### Benchmark Mode

```bash
python -m demogorgon https://target.com --benchmark
```

---

## CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `target` | (required) | Target URL to hunt |
| `--v3` | False | Use V3 autonomous researcher (recommended) |
| `--headless` | True | Run browser in headless mode |
| `--no-headless` | - | Run browser with GUI (for debugging) |
| `--proxy URL` | None | Route traffic through a proxy |
| `--rate-limit SECS` | 1.0 | Delay between requests (seconds) |
| `--max-iterations N` | 50 | Maximum reasoning iterations |
| `--output DIR` | hunt_output | Output directory |
| `--benchmark` | False | Run benchmark mode against target |

---

## How It Works — Step by Step

### Phase 1: Understand

The tool makes an initial HTTP request to the target and:

- Detects tech stack (Next.js, Django, Express, Shopify, Keycloak, etc.)
- Identifies server headers, powered-by headers
- Seeds initial endpoints from the KnowledgeBase attack plan
- Creates scope validator from target URL

### Phase 2: Model

Builds an application model:

- Discovers endpoints via HTTP crawling
- Identifies business objects (users, orders, payments)
- Maps trust boundaries (user → admin, anonymous → authenticated)
- Tracks workflows (login, checkout, settings)

### Phase 3: Reason → Experiment → Observe → Adapt

This is the main loop that runs until max iterations:

1. **Reason**: LLM analyzes current context and decides what to test next
2. **Experiment**: ExecutiveController selects the appropriate executor
3. **Observe**: Results feed back into the model
4. **Adapt**: Strategy shifts based on findings (explore → validate → exploit → pivot)

#### Auto-Save Checkpoint

Every 10 experiments, state is saved for crash recovery. If the tool crashes or is interrupted (Ctrl+C), it resumes from the last checkpoint on next run.

---

## Available Executors (16 vulnerability classes)

| Executor | Vuln Class | What It Tests |
|----------|------------|---------------|
| `idor_tester` | IDOR | Sequential/predictable IDs for unauthorized access |
| `xss_detector` | XSS | Reflected/stored XSS via payload mutation |
| `sqli_detector` | SQLi | Time-based, boolean, error-based SQL injection |
| `ssrf_tester` | SSRF | Server-side request forgery via internal URLs |
| `auth_bypass_tester` | Auth Bypass | No auth, expired token, modified token |
| `jwt_attacker` | JWT | alg:none, role manipulation, exp bypass, key confusion |
| `cors_detector` | CORS | Misconfigured CORS headers |
| `csrf_tester` | CSRF | Missing CSRF tokens on state-changing endpoints |
| `race_detector` | Race Condition | Concurrent requests to state-changing endpoints |
| `ssti_detector` | SSTI | Server-side template injection |
| `xxe_detector` | XXE | XML external entity injection |
| `redirect_tester` | Open Redirect | Redirect parameter manipulation |
| `info_disclosure_detector` | Info Disclosure | Error messages, headers, verbose responses |
| `upload_tester` | File Upload | Unrestricted file types, path traversal, webshell |
| `logic_tester` | Business Logic | Negative quantities, price manipulation, step skipping |
| `privesc_tester` | Privilege Escalation | Role manipulation, parameter injection |

---

## Finding Scoring (5 Dimensions)

Every finding is scored by the `ExploitConfidenceEngine`:

| Dimension | Weight | What It Measures |
|-----------|--------|------------------|
| **Evidence** | 25% | Number of evidence items, status codes, screenshots, request/response pairs |
| **Impact** | 30% | Severity × vulnerability class × business context (payment/PII gets boost) |
| **Reproducibility** | 20% | Multiple evidence items, HTTP methods, consistent results |
| **Business Value** | 15% | Endpoint sensitivity (admin, payment, profile, health) |
| **Exploitability** | 10% | How easy to exploit (IDOR=0.9, RCE=0.4, Chain=0.3) |

**Final confidence = weighted sum of all 5 dimensions**

Only findings with **confidence >= 85%** are marked as reportable.

---

## Auth Integration

Demogorgon supports multi-role authentication testing:

### Role Sessions

```python
# The tool can create multiple auth sessions (admin, user, anonymous)
# and test each endpoint with different roles
```

### Auth Types Supported

- Cookie-based sessions
- Bearer tokens (JWT)
- API keys
- Basic auth
- Custom headers

### How It Works

1. During Phase 1, the tool discovers auth requirements
2. Role sessions are created via `AuthManager`
3. Each executor receives the appropriate auth context
4. Replay requests inject active session headers

---

## Report Output

### Console Output

During the hunt, the tool prints:

```
[GREEN] Research Loop started on https://target.com [END]
[Cyan] LM: openrouter/anthropic/claude-3.5-sonnet [END]

[CYAN] Phase 1: Understand [END]
[GREEN] Detected stack: ['nextjs', 'express'] [END]

[CYAN] Phase 3: Reason → Experiment → Observe → Adapt [END]

[BLUE] === Experiment 1/50 === [END]
[Cyan] Hypothesis: Test for IDOR on /api/users/{id} [END]
[Cyan] Tool: idor_tester | Endpoint: /api/users/1 [END]
[GREEN] [200] GET https://target.com/api/users/1 -> 200 (0.12s, 1024 bytes) [END]

[RED] FINDING #1 [REPORTABLE]: IDOR in /api/users/{id} (91%) [END]
...
```

### Final Report

A `REPORT.md` is generated in the output directory with:

- **Executive Summary**: Target, runtime, findings count
- **Application Model**: Tech stack, roles, business objects, trust boundaries
- **Findings** (sorted by severity):
  - Title, endpoint, vuln class
  - Confidence score with 5-dimension breakdown
  - Why it was investigated (reasoning)
  - What security boundary was crossed
  - How to reproduce (step-by-step)
  - Impact assessment
  - Evidence (request/response)

### JSON Output

`findings.json` contains all findings with:

```json
{
  "title": "IDOR in /api/users/{id}",
  "severity": "high",
  "vuln_class": "idor",
  "endpoint": "/api/users/123",
  "method": "GET",
  "confidence": 0.91,
  "evidence": [...],
  "reproduction": ["Step 1: ...", "Step 2: ..."],
  "impact": "Attacker can access any user's data"
}
```

### Scored Findings

`scored_findings` array in the report JSON contains every finding with its 5-dimension scores:

```json
{
  "finding_id": "f1",
  "title": "IDOR in /api/users/{id}",
  "severity": "high",
  "vuln_class": "idor",
  "endpoint": "/api/users/123",
  "evidence_score": 0.70,
  "impact_score": 1.00,
  "reproducibility_score": 0.80,
  "business_value_score": 0.50,
  "exploitability_score": 1.00,
  "final_confidence": 0.91,
  "should_report": true,
  "reasoning": "Strong evidence collected. High impact vulnerability. Highly reproducible. CONFIDENT: 91% — recommend reporting"
}
```

---

## Crash Recovery

The tool saves state to `.demogorgon/checkpoints/<target>/`:

- Every 10 experiments
- On Ctrl+C (SIGINT)
- On completion

On next run, if a checkpoint exists, the tool restores:

- Experiment count
- Finding count
- Strategy state
- Tested actions (to avoid duplicates)
- Finding scores

```bash
# Resume a crashed hunt
python -m demogorgon https://target.com --v3
# Output: "Restored from checkpoint: 20 experiments, 3 findings"
```

---

## Configuration

### ResearchConfig (core/config.py)

```python
@dataclass
class ResearchConfig:
    target_url: str = ""
    headless: bool = True
    proxy: str | None = None
    rate_limit_delay: float = 1.0      # seconds between requests
    max_experiments: int = 50           # max reasoning iterations
    output_dir: str = "hunt_output"
    use_v3: bool = False                # use V3 researcher
    benchmark: bool = False
    self_eval_interval: int = 20        # self-evaluate every N experiments
    stagnation_threshold: int = 5       # pivot after N failed experiments
    max_duplicate_actions: int = 3
    max_same_endpoint: int = 5
    max_same_vuln_class: int = 3
    context_window_limit: int = 8000
    extra_scopes: list[str] = []
    excluded_hosts: list[str] = []
```

### LoopConfig (research_loop.py)

```python
@dataclass
class LoopConfig:
    max_experiments: int = 50
    self_eval_interval: int = 20
    rate_limit_delay: float = 1.0
    stagnation_threshold: int = 5
    max_duplicate_actions: int = 3
    max_same_endpoint: int = 5
    max_same_vuln_class: int = 3
    context_window_limit: int = 8000
```

---

## Test Coverage

```
216 tests passing
├── auth/authcore/tests/    — 155 tests (sessions, store, persistence)
├── core/tests/test_core.py —  61 tests (ScopeValidator, ResearchConfig,
│                              models, ContextBuilder, ExploitConfidenceEngine,
│                              Memory persistence, Checkpoint, ARE modules, CLI)
```

---

## File Structure

```
bugbounty-tool/
├── demogorgon/
│   ├── main.py                 # CLI entry point
│   ├── researcher.py           # V2 researcher
│   ├── researcher_v3.py        # V3 researcher (recommended)
│   ├── research_loop.py        # Main brain (1500+ lines)
│   ├── memory.py               # Working memory + persistence
│   ├── app_model.py            # Application model
│   ├── detectors.py            # Auto-detection (headers, errors, etc.)
│   ├── evidence_validator.py   # 7-Question Gate
│   ├── self_eval.py            # Self-evaluation
│   ├── reasoning_trace.py      # Decision logging
│   │
│   ├── core/                   # Canonical domain
│   │   ├── config.py           # ResearchConfig
│   │   ├── scope.py            # ScopeValidator
│   │   ├── models.py           # Finding, Hypothesis, Endpoint, etc.
│   │   └── context.py          # ContextBuilder
│   │
│   ├── controller/             # Executive control
│   │   ├── executive.py        # ExecutiveController
│   │   ├── execution_graph.py  # ExecutionGraph
│   │   ├── self_evaluator.py   # SelfEvaluator
│   │   └── tool_selection.py   # Executor registry (16 tools)
│   │
│   ├── are/                    # Adaptive Research Engine
│   │   ├── knowledge_base.py   # Tech stack detection + attack plans
│   │   ├── chain_finder.py     # Multi-step attack chain discovery
│   │   ├── attack_graph.py     # Endpoint relationship tracking
│   │   ├── mutation_intelligence.py  # Smart payload mutations
│   │   ├── exploit_confidence.py     # 5-dimension scoring
│   │   ├── trust_boundary.py   # Trust boundary mapping
│   │   ├── research_memory.py  # Persistent research state
│   │   └── engine.py           # Standalone ARE engine
│   │
│   ├── executors/              # 16 deterministic security testers
│   │   ├── idor_tester.py
│   │   ├── xss_detector.py
│   │   ├── sqli_detector.py
│   │   ├── ssrf_tester.py
│   │   ├── jwt_attacker.py
│   │   ├── cors_detector.py
│   │   ├── csrf_tester.py
│   │   ├── race_detector.py
│   │   ├── ssti_detector.py
│   │   ├── xxe_detector.py
│   │   ├── redirect_tester.py
│   │   ├── info_disclosure_detector.py
│   │   ├── upload_tester.py
│   │   ├── logic_tester.py
│   │   ├── auth_bypass_tester.py
│   │   └── privesc_tester.py
│   │
│   ├── auth/                   # Authentication
│   │   ├── bridge.py           # AuthManager
│   │   └── authcore/           # 155 tests — sessions, store, persistence
│   │
│   ├── tools/                  # Infrastructure
│   │   ├── http_client.py      # HTTP with rate limiting, scope guard
│   │   ├── browser.py          # Playwright browser automation
│   │   ├── reporter.py         # Markdown/JSON report generation
│   │   ├── checkpoint.py       # Crash recovery
│   │   ├── nuclei_bridge.py    # Nuclei integration
│   │   └── notifier.py         # Discord/Telegram notifications
│   │
│   └── llm/                    # LLM integration
│       └── manager.py          # Multi-provider LLM manager
│
├── requirements.txt
├── pyproject.toml
└── tests/
```

---

## Quick Reference

```bash
# Install
pip install -r requirements.txt

# Basic hunt
python -m demogorgon https://target.com --v3

# With Burp proxy
python -m demogorgon https://target.com --v3 --proxy http://127.0.0.1:8080

# Aggressive (fast rate, many iterations)
python -m demogorgon https://target.com --v3 --rate-limit 0.1 --max-iterations 200

# Debug mode (visible browser)
python -m demogorgon https://target.com --v3 --no-headless

# Check test suite
python -m pytest demogorgon/ -q

# Resume crashed hunt
python -m demogorgon https://target.com --v3
# (auto-detects checkpoint and resumes)
```
