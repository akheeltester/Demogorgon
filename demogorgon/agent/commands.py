"""Command Processor — user commands in the agent terminal.

Processes /-prefixed commands typed by the user in the agent terminal.
Commands control the agent without breaking the autonomous loop.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


class CommandType(Enum):
    """Agent command types."""
    HELP = "help"
    STATUS = "status"
    FINDINGS = "findings"
    PAUSE = "pause"
    RESUME = "resume"
    STOP = "stop"
    STRATEGY = "strategy"
    BUDGET = "budget"
    TRACE = "trace"
    REPORT = "report"
    CHAINS = "chains"
    EVIDENCE = "evidence"
    TARGETS = "targets"
    FOCUS = "focus"
    HISTORY = "history"
    COST = "cost"
    TIMEOUT = "timeout"
    LOG = "log"
    SKIP = "skip"
    OVERRIDE = "override"
    EXPLORE = "explore"
    VALIDATE = "validate"
    EXPLOIT = "exploit"
    CHAIN = "chain"
    QUIT = "quit"
    MODEL = "model"
    PROVIDER = "provider"
    SCOPE = "scope"
    TOOLS = "tools"
    MCP = "mcp"
    SCOPE_ADD = "scope-add"
    SCOPE_REMOVE = "scope-remove"


@dataclass
class CommandResult:
    """Result of processing a command."""
    success: bool
    message: str
    data: dict[str, Any] | None = None
    action: str = ""  # what the agent should do next: "continue", "pause", "stop", "resume"

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "message": self.message,
            "data": self.data,
            "action": self.action,
        }


COMMAND_HELP = """
╔══════════════════════════════════════════════════════════════╗
║                    DEMOGORGON COMMANDS                       ║
╠══════════════════════════════════════════════════════════════╣
║ /help          Show this help message                        ║
║ /status        Show agent status and stats                   ║
║ /findings      List current findings                         ║
║ /chains        List attack chains                            ║
║ /evidence      Show evidence collected                       ║
║ /targets       Show discovered targets                       ║
║ /scope         Show current scope                            ║
║ /scope-add     Add asset to scope                            ║
║ /scope-remove  Remove asset from scope                       ║
║ /tools         Show available tool capabilities              ║
║ /mcp           Show MCP server status                        ║
║ /model         Show/change current model                     ║
║ /provider      Show/change current provider                  ║
║ /pause         Pause the agent loop                          ║
║ /resume        Resume the agent loop                         ║
║ /stop          Stop the agent completely                     ║
║ /strategy <s>  Force strategy (recon|explore|focused|        ║
║                validate|exploit|chain)                       ║
║ /focus <class> Focus on a specific vuln class                ║
║ /budget        Show budget usage                             ║
║ /cost          Show token/cost breakdown                     ║
║ /trace         Show recent decision trace                    ║
║ /history       Show full command history                     ║
║ /report        Generate findings report                      ║
║ /skip          Skip current action                           ║
║ /override      Override safety (requires auth)               ║
║ /log [n]       Show last N log entries                       ║
║ /quit          Exit the agent                                ║
╚══════════════════════════════════════════════════════════════╝

Natural language also works — just type what you want:
  focus on XSS in /search
  scan for IDOR on API endpoints
  slow down, passive only
  show findings
  stop
"""


class CommandProcessor:
    """Processes user commands in the agent terminal.

    Usage:
        processor = CommandProcessor()
        result = await processor.process("/status", agent_state)
        print(result.message)
    """

    def __init__(self):
        self._history: list[tuple[str, CommandResult, float]] = []
        self._pending_instruction: str | None = None

    async def process(self, command_str: str, state: dict[str, Any]) -> CommandResult:
        """Process a command string.

        state should contain:
            - session: AgentSession
            - budget: BudgetController
            - trace: ResearchTrace
            - strategy: StrategyEngine
            - token_tracker: TokenTracker
        """
        command_str = command_str.strip()
        if not command_str.startswith("/"):
            # Treat as natural language instruction
            return await self._handle_instruction(command_str, state)

        parts = command_str.split(maxsplit=1)
        cmd = parts[0].lower().lstrip("/")
        args = parts[1] if len(parts) > 1 else ""

        # Map command to handler
        handlers = {
            "help": self._cmd_help,
            "status": self._cmd_status,
            "findings": self._cmd_findings,
            "chains": self._cmd_chains,
            "evidence": self._cmd_evidence,
            "targets": self._cmd_targets,
            "scope": self._cmd_scope,
            "scope-add": self._cmd_scope_add,
            "scope-remove": self._cmd_scope_remove,
            "tools": self._cmd_tools,
            "mcp": self._cmd_mcp,
            "model": self._cmd_model,
            "provider": self._cmd_provider,
            "pause": self._cmd_pause,
            "resume": self._cmd_resume,
            "stop": self._cmd_stop,
            "strategy": self._cmd_strategy,
            "focus": self._cmd_focus,
            "budget": self._cmd_budget,
            "cost": self._cmd_cost,
            "trace": self._cmd_trace,
            "history": self._cmd_history,
            "report": self._cmd_report,
            "skip": self._cmd_skip,
            "override": self._cmd_override,
            "log": self._cmd_log,
            "quit": self._cmd_quit,
            # Strategy shortcuts
            "explore": lambda a, s: self._cmd_strategy("explore", s),
            "validate": lambda a, s: self._cmd_strategy("validate", s),
            "exploit": lambda a, s: self._cmd_strategy("exploit", s),
            "chain": lambda a, s: self._cmd_strategy("chain", s),
        }

        handler = handlers.get(cmd)
        if handler:
            result = await handler(args, state)
        else:
            result = CommandResult(
                success=False,
                message=f"Unknown command: /{cmd}. Type /help for available commands.",
            )

        # Record in history
        self._history.append((command_str, result, time.time()))

        return result

    async def _handle_instruction(self, text: str, state: dict[str, Any]) -> CommandResult:
        """Handle a natural language instruction from the user."""
        from .natural_language import NaturalLanguageParser, InstructionProcessor, InstructionType

        parser = NaturalLanguageParser()
        processor = InstructionProcessor()
        parsed = parser.parse(text)
        context_update = processor.process(parsed)

        # Route based on parsed type
        session = state.get("session")
        trace = state.get("trace")

        if parsed.type == InstructionType.QUERY:
            # Queries — route to existing handlers
            lower = text.lower()
            if any(w in lower for w in ["finding", "findings"]):
                return await self._cmd_findings("", state)
            elif any(w in lower for w in ["status", "state"]):
                return await self._cmd_status("", state)
            elif any(w in lower for w in ["evidence"]):
                return await self._cmd_evidence("", state)
            elif any(w in lower for w in ["chain", "chains"]):
                return await self._cmd_chains("", state)
            elif any(w in lower for w in ["scope"]):
                return await self._cmd_scope("", state)
            elif any(w in lower for w in ["budget", "cost"]):
                return await self._cmd_budget("", state)
            elif any(w in lower for w in ["tool", "tools", "capability", "capabilities"]):
                return await self._cmd_tools("", state)
            elif any(w in lower for w in ["trace", "log", "history"]):
                return await self._cmd_trace("", state)
            elif any(w in lower for w in ["help"]):
                return await self._cmd_help("", state)
            else:
                return CommandResult(
                    success=True,
                    message=f"Query: \"{text}\"\nTry /status, /findings, /evidence, /scope, /tools, or /help",
                )

        elif parsed.type == InstructionType.DIRECT:
            lower = text.lower()
            if any(w in lower for w in ["stop", "halt", "quit", "exit"]):
                return await self._cmd_stop("", state)
            elif any(w in lower for w in ["pause", "wait"]):
                return await self._cmd_pause("", state)
            elif any(w in lower for w in ["resume", "continue", "start"]):
                return await self._cmd_resume("", state)
            elif any(w in lower for w in ["report"]):
                return await self._cmd_report("", state)
            else:
                self._pending_instruction = text
                return CommandResult(
                    success=True,
                    message=f"Instruction: \"{text}\"\nConfidence: {parsed.confidence:.0%}",
                    data={"instruction": text, "parsed": context_update},
                    action="continue",
                )

        elif parsed.type == InstructionType.FOCUS:
            if session and trace:
                from .trace import TraceEntryType
                trace.add(
                    TraceEntryType.USER_INSTRUCTION,
                    f"Focus: {parsed.vuln_class or 'general'}",
                )
            parts = [f"Focusing on: {parsed.vuln_class or 'general research'}"]
            if parsed.endpoint:
                parts.append(f"Endpoint: {parsed.endpoint}")
            return CommandResult(
                success=True,
                message="\n".join(parts),
                data={"parsed": context_update},
                action="continue",
            )

        elif parsed.type == InstructionType.IGNORE:
            return CommandResult(
                success=True,
                message=f"Ignoring: {parsed.vuln_class or parsed.raw_text}",
                data={"parsed": context_update},
                action="continue",
            )

        elif parsed.type == InstructionType.CONSTRAINT:
            constraint_desc = {
                "rate_limit": "Rate limiting enabled — slowing down requests",
                "no_active": "Passive mode — no active exploitation",
                "scope_only": "Strict scope — testing only declared assets",
                "auth_only": "Authenticated testing mode",
            }.get(parsed.constraint, parsed.constraint)
            return CommandResult(
                success=True,
                message=f"Constraint applied: {constraint_desc}",
                data={"parsed": context_update},
                action="continue",
            )

        elif parsed.type == InstructionType.HINT:
            self._pending_instruction = text
            return CommandResult(
                success=True,
                message=f"Hint noted: \"{text}\"",
                data={"parsed": context_update},
                action="continue",
            )

        else:
            self._pending_instruction = text
            return CommandResult(
                success=True,
                message=f"Instruction received: \"{text}\"",
                data={"parsed": context_update},
                action="continue",
            )

    def get_pending_instruction(self) -> str | None:
        """Get and clear any pending user instruction."""
        inst = self._pending_instruction
        self._pending_instruction = None
        return inst

    async def _cmd_help(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(success=True, message=COMMAND_HELP)

    async def _cmd_status(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        budget = state.get("budget")
        strategy = state.get("strategy")
        tokens = state.get("token_tracker")

        lines = ["Agent Status:"]
        if session:
            lines.append(f"  Target: {session.target or 'Not set'}")
            lines.append(f"  Running: {session.is_running}")
            lines.append(f"  Paused: {session.is_paused}")
        if strategy:
            s = strategy.state
            lines.append(f"  Strategy: {s.strategy.value} ({s.cycles_in_strategy} cycles)")
            lines.append(f"  Reason: {s.reason}")
        if budget:
            lines.append(f"  Budget: {budget.get_usage_display()}")
        if tokens:
            lines.append(f"  {tokens.live_display}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_findings(self, args: str, state: dict[str, Any]) -> CommandResult:
        trace = state.get("trace")
        if not trace:
            return CommandResult(success=True, message="No trace available.")

        from .trace import TraceEntryType
        findings = trace.get_by_type(TraceEntryType.FINDING, limit=20)
        if not findings:
            return CommandResult(success=True, message="No findings yet.")

        lines = [f"Findings ({len(findings)}):"]
        for i, f in enumerate(findings, 1):
            lines.append(f"  {i}. {f.content[:80]}")
            if f.data.get("severity"):
                lines.append(f"     Severity: {f.data['severity']}")
            if f.data.get("endpoint"):
                lines.append(f"     Endpoint: {f.data['endpoint']}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_chains(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        chains = state.get("chains", [])
        if not chains:
            return CommandResult(success=True, message="No attack chains found.")

        lines = [f"Attack Chains ({len(chains)}):"]
        for i, chain in enumerate(chains, 1):
            if isinstance(chain, dict):
                lines.append(f"  {i}. {chain.get('name', 'Unnamed')}")
            else:
                lines.append(f"  {i}. {str(chain)[:80]}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_evidence(self, args: str, state: dict[str, Any]) -> CommandResult:
        trace = state.get("trace")
        if not trace:
            return CommandResult(success=True, message="No trace available.")

        from .trace import TraceEntryType
        evidence = trace.get_by_type(TraceEntryType.EVIDENCE, limit=10)
        if not evidence:
            return CommandResult(success=True, message="No evidence collected yet.")

        lines = [f"Evidence ({len(evidence)}):"]
        for i, e in enumerate(evidence, 1):
            lines.append(f"  {i}. {e.content[:100]}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_targets(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        return CommandResult(
            success=True,
            message=f"Target: {session.target}\nScope: {len(session.scope_assets)} assets",
        )

    async def _cmd_pause(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_paused = True
        return CommandResult(
            success=True,
            message="Agent paused. Type /resume to continue.",
            action="pause",
        )

    async def _cmd_resume(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_paused = False
        return CommandResult(
            success=True,
            message="Agent resuming...",
            action="resume",
        )

    async def _cmd_stop(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_running = False
            session.is_paused = False
        return CommandResult(
            success=True,
            message="Agent stopping...",
            action="stop",
        )

    async def _cmd_strategy(self, args: str, state: dict[str, Any]) -> CommandResult:
        strategy = state.get("strategy")
        if not strategy:
            return CommandResult(success=False, message="No strategy engine available.")

        from .strategies import AgentStrategy
        try:
            new_strategy = AgentStrategy(args.strip())
        except ValueError:
            valid = [s.value for s in AgentStrategy]
            return CommandResult(
                success=False,
                message=f"Invalid strategy: {args}. Valid: {', '.join(valid)}",
            )

        strategy.force_strategy(new_strategy, reason="User override")
        return CommandResult(
            success=True,
            message=f"Strategy changed to: {new_strategy.value}",
        )

    async def _cmd_focus(self, args: str, state: dict[str, Any]) -> CommandResult:
        if not args.strip():
            return CommandResult(
                success=False,
                message="Usage: /focus <vuln_class> (e.g., /focus idor, /focus xss)",
            )

        vuln_class = args.strip().lower()
        trace = state.get("trace")
        if trace:
            from .trace import TraceEntryType
            trace.add(
                TraceEntryType.USER_INSTRUCTION,
                f"Focus on vulnerability class: {vuln_class}",
            )

        return CommandResult(
            success=True,
            message=f"Focusing on vulnerability class: {vuln_class}",
            data={"focus_vuln_class": vuln_class},
        )

    async def _cmd_budget(self, args: str, state: dict[str, Any]) -> CommandResult:
        budget = state.get("budget")
        if not budget:
            return CommandResult(success=True, message="No budget controller available.")

        status = budget.check()
        lines = ["Budget Status:"]
        lines.append(f"  {budget.get_usage_display()}")

        if status.warnings:
            lines.append("\nWarnings:")
            for w in status.warnings:
                lines.append(f"  ⚠ {w}")

        if status.exceeded:
            lines.append("\nExceeded:")
            for e in status.exceeded:
                lines.append(f"  ✗ {e}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_cost(self, args: str, state: dict[str, Any]) -> CommandResult:
        tokens = state.get("token_tracker")
        if not tokens:
            return CommandResult(success=True, message="No token tracker available.")

        by_provider = tokens.get_by_provider()
        lines = [tokens.totals_display]

        if by_provider:
            lines.append("\nBy Provider:")
            for provider, stats in by_provider.items():
                lines.append(
                    f"  {provider}: {stats['calls']} calls, "
                    f"{stats['tokens']:,} tokens, ${stats['cost']:.4f}"
                )

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_trace(self, args: str, state: dict[str, Any]) -> CommandResult:
        trace = state.get("trace")
        if not trace:
            return CommandResult(success=True, message="No trace available.")

        n = 15
        if args.strip().isdigit():
            n = int(args.strip())

        summary = trace.get_llm_summary(max_entries=n)
        return CommandResult(
            success=True,
            message=f"Recent Trace ({len(trace)} total):\n{summary}",
        )

    async def _cmd_history(self, args: str, state: dict[str, Any]) -> CommandResult:
        if not self._history:
            return CommandResult(success=True, message="No command history.")

        lines = ["Command History:"]
        for cmd, result, ts in self._history[-20:]:
            time_str = time.strftime("%H:%M:%S", time.localtime(ts))
            status = "✓" if result.success else "✗"
            lines.append(f"  {time_str} {status} {cmd}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_report(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(
            success=True,
            message="Generating report...",
            action="continue",
            data={"generate_report": True},
        )

    async def _cmd_skip(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(
            success=True,
            message="Skipping current action.",
            action="skip",
        )

    async def _cmd_override(self, args: str, state: dict[str, Any]) -> CommandResult:
        return CommandResult(
            success=False,
            message="Safety override requires explicit authorization. Use /override --confirm.",
        )

    async def _cmd_log(self, args: str, state: dict[str, Any]) -> CommandResult:
        n = 10
        if args.strip().isdigit():
            n = int(args.strip())

        trace = state.get("trace")
        if trace:
            entries = trace.get_recent(n)
            lines = [f"Last {len(entries)} entries:"]
            for e in entries:
                ts = time.strftime("%H:%M:%S", time.localtime(e.timestamp))
                lines.append(f"  {ts} [{e.type.value}] {e.content[:80]}")
            return CommandResult(success=True, message="\n".join(lines))

        return CommandResult(success=True, message="No log entries.")

    async def _cmd_quit(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if session:
            session.is_running = False
            session.is_paused = False
        return CommandResult(
            success=True,
            message="Quitting agent...",
            action="stop",
        )

    async def _cmd_scope(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        lines = [f"Target: {session.target}"]
        if session.scope_assets:
            lines.append(f"\nIn-Scope Assets ({len(session.scope_assets)}):")
            for asset in session.scope_assets[:20]:
                if isinstance(asset, dict):
                    lines.append(f"  + {asset.get('pattern', asset.get('asset', ''))} ({asset.get('asset_type', 'domain')})")
                else:
                    lines.append(f"  + {asset}")
        else:
            lines.append("\nNo scope assets defined — testing target only.")

        if session.out_of_scope:
            lines.append(f"\nOut-of-Scope ({len(session.out_of_scope)}):")
            for asset in session.out_of_scope[:10]:
                if isinstance(asset, dict):
                    lines.append(f"  - {asset.get('pattern', asset.get('asset', ''))}")
                else:
                    lines.append(f"  - {asset}")

        if session.restrictions:
            lines.append(f"\nRestrictions ({len(session.restrictions)}):")
            for r in session.restrictions[:10]:
                if isinstance(r, dict):
                    lines.append(f"  ! {r.get('description', r.get('category', ''))}")
                else:
                    lines.append(f"  ! {r}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_scope_add(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=False, message="No session active.")
        if not args.strip():
            return CommandResult(success=False, message="Usage: /scope-add <pattern> [type]\n  e.g., /scope-add api.example.com api\n  e.g., /scope-add *.example.com domain")

        parts = args.strip().split()
        pattern = parts[0]
        asset_type = parts[1] if len(parts) > 1 else "domain"

        session.scope_assets.append({
            "pattern": pattern,
            "asset_type": asset_type,
        })
        return CommandResult(success=True, message=f"Added to scope: {pattern} ({asset_type})")

    async def _cmd_scope_remove(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=False, message="No session active.")
        if not args.strip():
            return CommandResult(success=False, message="Usage: /scope-remove <pattern>")

        pattern = args.strip()
        original = len(session.scope_assets)
        session.scope_assets = [
            a for a in session.scope_assets
            if (a.get("pattern", a) if isinstance(a, dict) else a) != pattern
        ]
        removed = original - len(session.scope_assets)
        if removed:
            return CommandResult(success=True, message=f"Removed {removed} asset(s) matching: {pattern}")
        return CommandResult(success=False, message=f"No assets matching: {pattern}")

    async def _cmd_tools(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        caps = session.capability_registry.get_available_capabilities()
        if not caps:
            return CommandResult(success=True, message="No tools registered.\nTools are auto-discovered when security tools are installed.")

        lines = [f"Available Capabilities ({len(caps)}):"]
        for cap in sorted(caps):
            info = session.capability_registry.get_capability_info(cap)
            tools = info.get("tools", [])
            desc = info.get("description", "")
            lines.append(f"  {cap}: {desc}")
            lines.append(f"    Tools: {', '.join(tools)}")

        status = session.capability_registry.get_status()
        lines.append(f"\nTotal tools: {status['total_tools']}")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_mcp(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        mcp_manager = getattr(session, '_mcp_manager', None)
        if not mcp_manager:
            return CommandResult(success=True, message="MCP not initialized.\nConfigure MCP servers in ~/.demogorgon/config.json.")

        server_status = mcp_manager.get_server_status()
        if not server_status:
            return CommandResult(success=True, message="No MCP servers configured.")

        lines = ["MCP Servers:"]
        for name, info in server_status.items():
            connected = "✓ connected" if info.get("connected") else "✗ disconnected"
            tools = info.get("tools", 0)
            lines.append(f"  {name}: {connected} ({tools} tools)")

        return CommandResult(success=True, message="\n".join(lines))

    async def _cmd_model(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        if args.strip():
            # Change model
            new_model = args.strip()
            session.config.model = new_model
            # Reconfigure LLM manager
            try:
                from demogorgon.llm.manager import LLMManager
                llm = LLMManager()
                llm.configure_from_params(
                    provider=session.config.provider,
                    api_key=session.config.api_key,
                    base_url=session.config.base_url,
                    model=new_model,
                )
                return CommandResult(success=True, message=f"Model changed to: {new_model}")
            except Exception as e:
                return CommandResult(success=False, message=f"Failed to change model: {e}")

        # Show current model
        return CommandResult(
            success=True,
            message=f"Provider: {session.config.provider}\nModel: {session.config.model}\nBase URL: {session.config.base_url}",
        )

    async def _cmd_provider(self, args: str, state: dict[str, Any]) -> CommandResult:
        session = state.get("session")
        if not session:
            return CommandResult(success=True, message="No session active.")

        if args.strip():
            # Change provider
            new_provider = args.strip()
            try:
                from demogorgon.config.provider_config import ProviderConfigManager
                mgr = ProviderConfigManager()
                profile = mgr.get_profile(new_provider)
                if not profile:
                    return CommandResult(success=False, message=f"Provider '{new_provider}' not configured.\nRun: python -m demogorgon setup")

                session.config.provider = new_provider
                session.config.api_key = profile.api_key
                session.config.base_url = profile.base_url
                session.config.model = profile.selected_model
                mgr.load_into_environment(new_provider)
                return CommandResult(success=True, message=f"Provider changed to: {new_provider}\nModel: {profile.selected_model}")
            except Exception as e:
                return CommandResult(success=False, message=f"Failed to change provider: {e}")

        # Show current provider
        from demogorgon.config.provider_config import ProviderConfigManager
        mgr = ProviderConfigManager()
        active = mgr.get_active_profile()
        if active:
            return CommandResult(
                success=True,
                message=f"Active: {active.provider}\nModel: {active.selected_model}\nKey: {active.masked_key}",
            )
        return CommandResult(success=True, message="No provider configured.")

    def get_history(self) -> list[tuple[str, CommandResult, float]]:
        return list(self._history)
