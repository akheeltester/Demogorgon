# DEMOGORGON Agent Mode

Interactive autonomous security research agent — Claude Code/Codex-style terminal experience.

## Quick Start

```bash
# Interactive mode (prompts for target, provider, model, budget)
python -m demogorgon agent

# Quick mode (auto-detects provider from env)
python -m demogorgon agent https://target.com

# Legacy CLI mode (still works)
python -m demogorgon https://target.com
```

## Architecture

The agent layer sits on top of the existing core (`demogorgon.core`) without modifying it.

```
┌─────────────────────────────────────────────────┐
│                  Agent Layer                     │
│  (demogorgon/agent/)                             │
│                                                  │
│  AgentSession ──┬── EventBus                     │
│                 ├── TokenTracker                 │
│                 ├── BudgetController             │
│                 ├── ResearchTrace                │
│                 ├── StrategyEngine               │
│                 ├── CommandProcessor             │
│                 └── TerminalUI                   │
│                                                  │
│  AgentMain ──────── MCPManager                   │
│                 (Burp, custom tools)             │
└─────────────────────┬───────────────────────────┘
                      │ delegates to
┌─────────────────────▼───────────────────────────┐
│                  Core Layer                      │
│  (demogorgon/core/)                              │
│                                                  │
│  AutonomousRunner ── ResearchLoop                │
│       ├── ResearchBrain (LLM reasoning)          │
│       ├── PlanExecutor (HTTP, browser, tools)    │
│       ├── EvidenceCollector                      │
│       └── ResearchCase (persistent state)        │
│                                                  │
│  ActionGateway ── Safety → HITL → Rate Limit     │
│  ScopeMatcher ── In-scope / Out-of-scope         │
│  StateManager ── Crash recovery                  │
│  ValidationPipeline ── FP/TP detection           │
│  BugChainDetector ── Multi-step attacks          │
└─────────────────────────────────────────────────┘
```

## Components

### EventBus (`events.py`)
Decoupled event system. The brain emits events; the UI subscribes. No coupling.

```python
from demogorgon.agent.events import EventBus, EventType

bus = EventBus()
bus.on(EventType.FINDING, my_handler)
await bus.emit(EventType.FINDING, {"title": "XSS", "severity": "high"})
```

**Event types:** SESSION_START, SESSION_END, PROGRESS_UPDATE, STRATEGY_CHANGE, DECISION_START, DECISION_COMPLETE, TOOL_EXECUTE, TOOL_RESULT, FINDING, EVIDENCE_COLLECTED, SAFETY_BLOCK, HITL_REQUEST, LLM_REQUEST, LLM_RESPONSE, BUDGET_WARNING, BUDGET_EXCEEDED, ERROR, WARNING

### TokenTracker (`tokens.py`)
Tracks token usage and cost across all LLM calls.

```python
tracker = TokenTracker()
tracker.record_call("openai", "gpt-4o-mini", 100, 50)
print(tracker.live_display)  # "Tokens: 150 | Cost: $0.0001 | Calls: 1"
```

Cost table covers: OpenAI, Anthropic, Gemini, DeepSeek, OpenRouter, Ollama.

### BudgetController (`budget.py`)
User-defined limits on cycles, cost, requests, tokens, findings, duration.

```python
from demogorgon.agent.budget import BudgetController, BudgetLimits

budget = BudgetController(BudgetLimits(max_cycles=50, max_cost_usd=2.00))
budget.record_cycle()
status = budget.check()
if status.exceeded:
    # Pause agent, notify user
```

### ResearchTrace (`trace.py`)
Structured decision history for the agent. Queryable, LLM-summarizable.

```python
trace = ResearchTrace()
trace.add(TraceEntryType.OBSERVATION, "Found /api/users")
trace.add(TraceEntryType.DECISION, "Testing IDOR")
summary = trace.get_llm_summary()  # For context window
is_loop, pattern = trace.check_for_loops()  # Anti-loop detection
```

### StrategyEngine (`strategies.py`)
Dynamic strategy selection replacing the fixed explore→validate→exploit cycle.

```python
engine = StrategyEngine()
state = engine.evaluate({
    "endpoints_discovered": 10,
    "findings": 3,
    "consecutive_failures": 0,
})
# state.strategy = AgentStrategy.EXPLORE
```

**Strategies:** RECON → EXPLORE → FOCUSED → VALIDATE → EXPLOIT → CHAIN → RECOVERY → ADAPT

### CommandProcessor (`commands.py`)
Processes `/`-prefixed user commands in the terminal.

**Commands:** `/help`, `/status`, `/findings`, `/chains`, `/evidence`, `/pause`, `/resume`, `/stop`, `/strategy <s>`, `/focus <class>`, `/budget`, `/cost`, `/trace`, `/report`, `/skip`, `/quit`

Natural language input is also supported (passed as user instruction to the brain).

### MCP Client (`mcp.py`)
Generic Model Context Protocol client for external tools (Burp Suite, custom tools).

```python
from demogorgon.agent.mcp import MCPClient, MCPServerConfig

client = MCPClient("burp", command=["python", "mcp_burp_server.py"])
await client.start()
tools = await client.list_tools()
result = await client.call_tool("burp_scan", {"url": "https://target.com"})
```

### TerminalUI (`ui.py`)
Rich-based live terminal display. Subscribes to EventBus, renders in real time.

### Interactive Startup (`startup.py`)
Rich-based provider/model selection wizard.

### AgentSession (`session.py`)
Canonical session state. Owns all subsystems. Coordinates with Engagement/StateManager.

### AgentMain (`main.py`)
Main orchestrator. Bridges agent layer with existing core components.

## Agent Commands

| Command | Description |
|---------|-------------|
| `/help` | Show all commands |
| `/status` | Show agent status, strategy, budget, tokens |
| `/findings` | List current findings |
| `/chains` | List attack chains |
| `/evidence` | Show evidence collected |
| `/targets` | Show discovered targets |
| `/pause` | Pause the agent loop |
| `/resume` | Resume the agent loop |
| `/stop` | Stop the agent completely |
| `/strategy <s>` | Force strategy (recon, explore, focused, validate, exploit, chain) |
| `/focus <class>` | Focus on a specific vuln class (idor, xss, sqli, etc.) |
| `/budget` | Show budget usage |
| `/cost` | Show token/cost breakdown |
| `/trace` | Show recent decision trace |
| `/history` | Show command history |
| `/report` | Generate findings report |
| `/skip` | Skip current action |
| `/log [n]` | Show last N log entries |
| `/quit` | Exit the agent |

## Configuration

### Environment Variables

```bash
# LLM Provider (auto-detected from env)
DEMOGORGON_LLM_PROVIDER=openrouter
DEMOGORGON_API_KEY=sk-or-...
DEMOGORGON_MODEL=nvidia/nemotron-3-super-120b-a12b:free

# Or provider-specific
OPENROUTER_API_KEY=sk-or-...
ANTHROPIC_API_KEY=sk-ant-...
GEMINI_API_KEY=...
OPENAI_API_KEY=sk-...
DEEPSEEK_API_KEY=...

# Budget (optional, defaults in SessionConfig)
DEMOGORGON_MAX_CYCLES=50
DEMOGORGON_MAX_COST=2.00
DEMOGORGON_MAX_REQUESTS=200
```

### .env File

```bash
# Copy from .env.example
cp .env.example .env

# Edit with your API key
OPENROUTER_API_KEY=sk-or-your-key-here
```

## Testing

```bash
# Run all agent tests (112 tests)
python -m pytest demogorgon/agent/tests.py -v

# Run all tests (472 tests)
python -m pytest demogorgon/ -v --ignore=demogorgon/are --ignore=demogorgon/auth --ignore=demogorgon/benchmark --ignore=demogorgon/examples --ignore=demogorgon/executors
```

## File Structure

```
demogorgon/agent/
├── __init__.py           # Module exports
├── session.py            # AgentSession — canonical session state
├── events.py             # EventBus — decoupled event system
├── tokens.py             # TokenTracker — live token/cost tracking
├── budget.py             # BudgetController — user-defined limits
├── trace.py              # ResearchTrace — structured decision history
├── strategies.py         # StrategyEngine — dynamic strategy selection
├── commands.py           # CommandProcessor — user commands
├── capabilities.py       # CapabilityRegistry — capability-based tool abstraction
├── natural_language.py   # NLParser — user instructions → agent context
├── memory.py             # ResearchMemory — persistent cross-session knowledge
├── live_display.py       # LiveDisplay — Rich Live terminal display
├── startup.py            # Interactive startup wizard
├── ui.py                 # TerminalUI — event-driven Rich display
├── mcp.py                # MCPClient/Manager — generic MCP layer
├── main.py               # AgentMain — main orchestrator
└── tests.py              # 112 tests
```

## Capability Registry

Tools are registered by what they CAN DO, not by name. The LLM discovers capabilities and selects the best tool.

```python
from demogorgon.agent.capabilities import CapabilityRegistry, CapabilityRequest

registry = CapabilityRegistry()
registry.register_tool("subfinder", capabilities=["subdomain_enum"], reliability=0.9)
registry.register_tool("amass", capabilities=["subdomain_enum", "dns_recon"])

# Find best tool for a capability
best = registry.find_best_tool(CapabilityRequest(capability="subdomain_enum"))
# Returns subfinder (higher reliability)

# Get all available capabilities
caps = registry.get_available_capabilities()
# ["subdomain_enum", "dns_recon"]
```

## Natural Language Interface

User instructions are parsed into structured agent context.

```python
from demogorgon.agent.natural_language import NaturalLanguageParser, InstructionProcessor

parser = NaturalLanguageParser()
instruction = parser.parse("focus on XSS in /search endpoint")
# ParsedInstruction(type=FOCUS, vuln_class="xss", endpoint="/search")

processor = InstructionProcessor()
context_update = processor.process(instruction)
# {"focus_vuln_class": "xss", "focus_endpoint": "/search", "priority_boost": 0.3}
```

**Supported instructions:**
- "focus on XSS/IDOR/SQLi..." → Focus on vulnerability class
- "scan for SQL injection on /api" → Direct action
- "ignore xss for now" → Exclude from testing
- "slow down, be careful" → Rate limit constraint
- "passive only" → No active testing
- "use nuclei" → Tool preference
- "what findings do we have" → Query

## Research Memory

Persistent cross-session knowledge.

```python
from demogorgon.agent.memory import ResearchMemory

memory = ResearchMemory("/path/to/workspace")

# Store learned knowledge
memory.store("xss_works_on_search", "vuln_pattern",
             "XSS payloads work on /search?q= parameter",
             data={"endpoint": "/search", "param": "q"})

# Retrieve relevant memories
entries = memory.retrieve(query="xss")

# Get context for LLM
context = memory.get_llm_context(target="https://example.com")
```

## What's Next (Phase 11 remaining)

- [ ] Phase 11.1-11.13 per spec sections (integration with research loop, Burp MCP, etc.)
