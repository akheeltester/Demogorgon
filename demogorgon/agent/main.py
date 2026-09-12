"""Agent main — orchestrator that ties everything together.

The agent main loop:
1. User types a command (or nothing)
2. If command: process it, update UI, continue
3. If no command: LLM reasons, proposes action, gateway validates, executor runs
4. Evidence collected, findings validated, trace updated
5. UI refreshed
6. Repeat

This is the bridge between the new agent layer and existing core components.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from .session import AgentSession, SessionConfig, SessionStatus
from .events import EventBus, EventType
from .tokens import TokenTracker
from .budget import BudgetController, BudgetLimits
from .trace import ResearchTrace, TraceEntryType
from .strategies import StrategyEngine, AgentStrategy
from .commands import CommandProcessor
from .ui import TerminalUI
from .startup import interactive_startup, quick_startup

logger = logging.getLogger(__name__)


class AgentMain:
    """Main agent orchestrator.

    Bridges the new agent layer (session, events, UI, commands)
    with existing core components (ResearchLoop, ActionGateway, etc.).

    Usage:
        agent = AgentMain()
        await agent.start()  # interactive
        # or
        await agent.start(target="https://example.com")  # quick
    """

    def __init__(self):
        self.session: AgentSession | None = None
        self.ui: TerminalUI | None = None
        self._runner = None
        self._input_task = None

    async def start(
        self,
        target: str = "",
        interactive: bool = True,
        config: SessionConfig | None = None,
    ) -> dict[str, Any]:
        """Start the agent.

        Args:
            target: Target URL (if not interactive)
            interactive: Run interactive startup
            config: Pre-built config (skip startup)
        """
        # 1. Get config
        if config:
            session_config = config
        elif interactive and not target:
            session_config = await interactive_startup()
        else:
            session_config = await quick_startup(target)

        # 2. Create session
        self.session = AgentSession(config=session_config)
        await self.session.initialize()

        # 3. Create UI
        self.ui = TerminalUI(
            event_bus=self.session.events,
            token_tracker=self.session.token_tracker,
            budget=self.session.budget,
            trace=self.session.trace,
            strategy=self.session.strategy,
            commands=self.session.commands,
            session=self.session,
        )
        self.ui.print_banner()

        # 4. Wire up LLM callback
        llm_generate = self._create_llm_callback()

        # 5. Create the runner (existing core)
        await self._create_runner(llm_generate)

        # 6. Start UI
        await self.ui.start()

        # 7. Start input listener
        self._input_task = asyncio.create_task(self._input_loop())

        # 8. Run the research loop
        try:
            result = await self._run_research_loop()
        except KeyboardInterrupt:
            await self.session.events.emit(
                EventType.SESSION_END, {"reason": "user_interrupt"}, source="agent"
            )
            result = {"status": "interrupted"}
        finally:
            # Cleanup
            if self._input_task:
                self._input_task.cancel()
            if self.ui:
                await self.ui.stop()

            # Save state
            state_path = self.session.save_state()
            if state_path:
                logger.info(f"Session state saved to {state_path}")

        return result

    async def resume(self, workspace_dir: str) -> dict[str, Any]:
        """Resume a previously crashed/stopped session."""
        try:
            self.session = AgentSession.load_state(workspace_dir)
        except FileNotFoundError:
            return {"error": "No saved state found"}

        self.session.is_running = True
        self.session.is_paused = False
        self.session.status = SessionStatus.RUNNING

        # Create UI
        self.ui = TerminalUI(
            event_bus=self.session.events,
            token_tracker=self.session.token_tracker,
            budget=self.session.budget,
            trace=self.session.trace,
            strategy=self.session.strategy,
            commands=self.session.commands,
            session=self.session,
        )
        self.ui.print_banner()
        console_print = __import__("rich.console", fromlist=["Console"]).Console()
        console_print.print(f"[green]Resumed from {workspace_dir}[/green]")

        await self.ui.start()
        self._input_task = asyncio.create_task(self._input_loop())

        try:
            result = await self._run_research_loop()
        except KeyboardInterrupt:
            result = {"status": "interrupted"}
        finally:
            if self._input_task:
                self._input_task.cancel()
            if self.ui:
                await self.ui.stop()
            self.session.save_state()

        return result

    def _create_llm_callback(self):
        """Create an LLM callback that tracks tokens and emits events."""
        from demogorgon.llm.manager import LLMManager

        manager = LLMManager()
        manager.configure()

        async def llm_generate(
            messages: list[dict[str, str]],
            model: str | None = None,
            temperature: float = 0.1,
            max_tokens: int = 4096,
            response_format: dict | None = None,
        ) -> dict[str, Any]:
            """LLM generate with token tracking and event emission."""
            start = time.time()

            await self.session.events.emit(
                EventType.LLM_REQUEST,
                {"model": model or manager._active_model, "messages_count": len(messages)},
                source="llm",
            )

            try:
                response = await manager.generate(
                    messages, model, temperature, max_tokens, response_format
                )
                latency_ms = (time.time() - start) * 1000

                if response.error:
                    await self.session.events.emit(
                        EventType.LLM_ERROR, {"error": response.error}, source="llm"
                    )
                    return {"error": response.error}

                # Track tokens (estimate if not provided)
                prompt_tokens = sum(len(m.get("content", "")) // 4 for m in messages)
                completion_tokens = len(response.content) // 4

                self.session.record_llm_call(
                    provider=manager._active_provider,
                    model=manager._active_model,
                    prompt_tokens=prompt_tokens,
                    completion_tokens=completion_tokens,
                    latency_ms=latency_ms,
                )

                await self.session.events.emit(
                    EventType.LLM_RESPONSE,
                    {
                        "model": manager._active_model,
                        "latency_ms": latency_ms,
                        "tokens": prompt_tokens + completion_tokens,
                    },
                    source="llm",
                )

                # Parse response as JSON
                import json
                try:
                    return json.loads(response.content)
                except (json.JSONDecodeError, TypeError):
                    return {"content": response.content}

            except Exception as e:
                await self.session.events.emit(
                    EventType.LLM_ERROR, {"error": str(e)}, source="llm"
                )
                return {"error": str(e)}

        return llm_generate

    async def _create_runner(self, llm_generate):
        """Create the AutonomousRunner from existing core."""
        try:
            from demogorgon.core.runner import AutonomousRunner, RunnerConfig
            from demogorgon.core.engagement import Engagement, AuthorizationStatus, EngagementStatus
            from demogorgon.core.hitl.gate import ApprovalLevel

            # Create a minimal engagement
            engagement = Engagement(
                id=f"agent_{int(time.time())}",
                name=f"Agent scan: {self.session.target}",
                target_url=self.session.target,
                status=EngagementStatus.ACTIVE,
                authorization_status=AuthorizationStatus.CONFIRMED,
            )

            approval = ApprovalLevel.NONE
            if self.session.config.approval_level == "required":
                approval = ApprovalLevel.REQUIRED
            elif self.session.config.approval_level == "for_exploits":
                approval = ApprovalLevel.FOR_EXPLOITS

            self._runner = AutonomousRunner(
                engagement=engagement,
                config=RunnerConfig(
                    max_iterations=self.session.config.max_cycles,
                    rate_limit=self.session.config.rate_limit,
                    max_requests=self.session.config.max_requests,
                    approval_level=approval,
                    checkpoint_interval=self.session.config.checkpoint_interval,
                    workspace_dir=self.session.workspace_dir,
                ),
                llm_generate=llm_generate,
                workspace_dir=self.session.workspace_dir,
                # Phase 11.1 — pass agent subsystems through to ResearchLoop
                event_bus=self.session.events,
                capability_registry=self.session.capability_registry,
                research_memory=self.session.research_memory,
                research_trace=self.session.trace,
                strategy_engine=self.session.strategy,
                application_model=self.session.application_model,
            )

        except ImportError as e:
            logger.warning(f"Could not create runner: {e}")
            self._runner = None

    async def _run_research_loop(self) -> dict[str, Any]:
        """Run the research loop with agent integration."""
        if not self._runner:
            return {"error": "No runner available"}

        # Override approval level for CLI
        from demogorgon.core.hitl.gate import ApprovalLevel
        self._runner.hitl_gate.approval_level = ApprovalLevel.NONE

        try:
            result = await self._runner.run()

            # Transfer findings to session
            for finding in result.get("findings", []):
                if isinstance(finding, dict):
                    self.session.record_finding(finding)

            return result

        except Exception as e:
            logger.error(f"Research loop failed: {e}")
            await self.session.events.emit(
                EventType.ERROR, {"error": str(e)}, source="runner"
            )
            return {"error": str(e)}

    async def _input_loop(self):
        """Listen for user input in the background."""
        loop = asyncio.get_event_loop()

        while self.session and self.session.is_running:
            try:
                # Run input() in a thread to not block the event loop
                line = await loop.run_in_executor(None, lambda: input("\n> "))

                if not line.strip():
                    continue

                # Process command
                state = self.session.get_state()
                result = await self.session.commands.process(line.strip(), state)

                # Print result
                from rich.console import Console
                console = Console()
                if result.success:
                    console.print(result.message, style="green")
                else:
                    console.print(result.message, style="red")

                # Handle actions
                if result.action == "stop":
                    await self.session.stop()
                    break
                elif result.action == "pause":
                    await self.session.pause()
                elif result.action == "resume":
                    await self.session.resume()

                # Handle special data
                if result.data and result.data.get("generate_report"):
                    await self._generate_report()

            except (EOFError, KeyboardInterrupt):
                break
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Input error: {e}")

    async def _generate_report(self):
        """Generate a findings report."""
        if not self.session:
            return

        from rich.console import Console
        console = Console()

        if not self.session.findings:
            console.print("[yellow]No findings to report.[/yellow]")
            return

        try:
            from demogorgon.core.reporting.generator import ReportGenerator, Finding

            gen = ReportGenerator(workspace_dir=self.session.workspace_dir)
            findings = []
            for f in self.session.findings:
                findings.append(Finding(
                    title=f.get("title", "Untitled"),
                    severity=f.get("severity", "unknown"),
                    vuln_class=f.get("vuln_class", ""),
                    endpoint=f.get("endpoint", ""),
                    description=f.get("description", ""),
                    impact=f.get("impact", ""),
                    remediation=f.get("remediation", ""),
                    reproduction_steps=f.get("steps_to_reproduce", []),
                ))

            report = gen.generate(
                findings=findings,
                target=self.session.target,
            )
            md_path = gen.save_markdown(report)
            console.print(f"[green]Report saved: {md_path}[/green]")

        except Exception as e:
            console.print(f"[red]Report generation failed: {e}[/red]")
