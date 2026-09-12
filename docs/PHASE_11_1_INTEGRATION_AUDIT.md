# Phase 11.1 Integration Audit

## Current Runtime Path

```
AgentMain.start()
  → AgentSession.initialize()
  → _create_runner() → AutonomousRunner
  → AutonomousRunner.run()
    → ResearchLoop.run()
      → ResearchBrain.reason_next_action()
        → LLMReasoner.reason(context)
        → Decision(action, target, reason, confidence)
      → ResearchBrain.plan_experiment(hypothesis)
        → LLMExperimentPlanner.plan(hypothesis, context)
        → plan dict (steps, preconditions, safety_checks)
      → PlanExecutor.execute(plan)
        → _execute_step() → HTTP/Browser/Tool
        → observations, evidence
      → ResearchBrain.validate_finding(evidence)
        → LLMValidator.validate(evidence)
        → validation result (is_finding, severity, etc.)
    → BugChainDetector.detect_chains()
    → ReportGenerator.generate()
```

## What IS Connected

| Connection | Status |
|------------|--------|
| AgentMain → AgentSession | Connected (creates session) |
| AgentSession → AutonomousRunner | Connected (_create_runner) |
| AutonomousRunner → ResearchLoop | Connected (_run_research) |
| ResearchLoop → ResearchBrain | Connected (brain.reason_next_action) |
| ResearchBrain → LLMReasoner | Connected (reasoner.reason) |
| ResearchBrain → LLMExperimentPlanner | Connected (planner.plan) |
| PlanExecutor → HTTP requests | Connected (_execute_http_request) |
| PlanExecutor → Browser | Connected (_execute_browser_*) |
| PlanExecutor → Tool calls | Connected (_execute_tool_call) |
| ResearchLoop → EvidenceCollector | Connected (evidence.add_evidence) |
| ResearchLoop → LLMValidator | Connected (brain.validate_finding) |
| ResearchLoop → StateManager | Connected (checkpoint) |
| ActionGateway → SafetyGate | Connected (validate) |
| ActionGateway → HITLGate | Connected (validate) |

## What IS DISCONNECTED

| Connection | Status | Impact |
|------------|--------|--------|
| EventBus → research engine | DISCONNECTED | No live events from loop |
| EventBus → LiveDisplay | DISCONNECTED | No real-time UI updates |
| CapabilityRegistry → PlanExecutor | DISCONNECTED | Tool selection is hardcoded |
| NaturalLanguageParser → AgentSession | DISCONNECTED | User NL instructions ignored |
| ResearchMemory → ResearchBrain | DISCONNECTED | No cross-session learning |
| ResearchTrace → research cycle | DISCONNECTED | No structured trace recording |
| StrategyEngine → ResearchBrain | DISCONNECTED | Strategy changes ignored |
| AgentSession ↔ ResearchLoop | DISCONNECTED | Session doesn't control loop |
| MCP → CapabilityRegistry | DISCONNECTED | MCP tools not in capability system |
| ApplicationModel → ResearchBrain | DISCONNECTED | App model not in LLM context |
| Auth context → PlanExecutor | DISCONNECTED | No auth_context_id support |

## Duplicate Responsibilities

| Responsibility | Agent | Core | Resolution |
|----------------|-------|------|------------|
| Strategy selection | StrategyEngine | ResearchLoop._strategy | Use StrategyEngine, remove loop's |
| Budget tracking | BudgetController | RunnerConfig.max_* | Use BudgetController, expose to loop |
| Decision tracing | ResearchTrace | ResearchCase | Extend ResearchCase with trace |
| Token tracking | TokenTracker | (none) | Keep in agent, emit via events |
| Finding storage | AgentSession.findings | ResearchCase.findings | Use ResearchCase as source of truth |

## Current Entry Points

1. `python -m demogorgon agent` → AgentMain.start() → full agent loop
2. `python -m demogorgon https://target` → CLI → AutonomousRunner.run() → ResearchLoop
3. `AgentSession._run_cycle()` → currently delegates to runner (stub)

## Current Data Models

- `Decision` (interfaces.py): action, target, reason, confidence, priority, params, tool_hint
- `NextBestAction` (case.py): action, target, reason, confidence, priority, hypothesis_id, tool_hint
- `ToolCapabilityBinding` (capabilities.py): tool_name, capability, reliability, speed, cost
- `ParsedInstruction` (natural_language.py): type, vuln_class, endpoint, constraint
- `MemoryEntry` (memory.py): key, category, content, data, confidence
- `AgentEvent` (events.py): type, data, timestamp, source
- `TraceEntry` (trace.py): type, content, data, iteration, cycle_id

## Required Changes

### 1. EventBus integration
- ResearchLoop emits events on every significant state change
- AgentMain wires EventBus to ResearchLoop
- LiveDisplay subscribes to EventBus

### 2. CapabilityRegistry → PlanExecutor
- PlanExecutor queries CapabilityRegistry for best tool
- LLM proposes capability, not specific tool
- CapabilityRegistry resolves to available implementation

### 3. NaturalLanguageParser → AgentSession
- AgentSession parses user NL input
- Updates context (focus, constraints, hints)
- Context flows to ResearchBrain via ResearchLoop

### 4. ResearchMemory → ResearchBrain
- Before each reasoning cycle, retrieve relevant memories
- Add to context for LLM
- After finding, store new memory

### 5. ResearchTrace → research cycle
- Every cycle records: observation, decision, action, result, validation
- Trace provides recent history to LLM context

### 6. AgentSession ↔ ResearchLoop
- AgentSession creates and owns ResearchLoop
- AgentSession.start() runs the loop
- User commands pause/resume/stop the loop

### 7. ApplicationModel → ResearchBrain
- Observations update ApplicationModel
- ApplicationModel state flows to LLM context
