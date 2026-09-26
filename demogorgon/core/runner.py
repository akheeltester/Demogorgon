"""AutonomousRunner — end-to-end engagement orchestrator.

Chains: Engagement → Scope → Recon → Crawl → Research → Validate → Report.

This is the single entry point for autonomous bug bounty research.
It composes existing components without reimplementing them.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from .engagement_context import EngagementContext
from .engagement import Engagement, EngagementStatus, AuthorizationStatus
from .engagement.manager import EngagementManager
from .scope.matcher import ScopeMatcher
from .scope.safety import SafetyGate
from .gateway import ActionGateway
from .research_loop.loop import ResearchLoop, LoopConfig
from .research_loop.evidence import EvidenceCollector
from .research_loop.case import ResearchCase
from .validation.pipeline import ValidationPipeline
from .chains.detector import BugChainDetector
from .evidence.packager import EvidencePackager
from .state.manager import StateManager, EngagementState
from .reporting.generator import ReportGenerator, Finding
from .hitl.gate import HITLGate, ApprovalLevel
from .hitl.controller import PauseController, PauseReason
from .auth.manager import AuthManager

logger = logging.getLogger(__name__)


@dataclass
class RunnerConfig:
    """Configuration for the autonomous runner."""
    max_iterations: int = 100
    rate_limit: float = 2.0
    max_requests: int = 5000
    approval_level: ApprovalLevel = ApprovalLevel.REQUIRED
    checkpoint_interval: int = 10
    auto_report: bool = True
    workspace_dir: str = ""


class AutonomousRunner:
    """End-to-end autonomous engagement runner.

    Orchestrates the complete lifecycle:
    1. Load/create engagement
    2. Establish scope
    3. Discover tools
    4. Execute recon
    5. Crawl application
    6. Build application model
    7. Start research loop
    8. Validate evidence
    9. Detect chains
    10. Generate report

    This class composes existing components rather than reimplementing them.
    """

    def __init__(
        self,
        engagement: Engagement,
        config: RunnerConfig | None = None,
        llm_generate: Callable[..., Awaitable[dict[str, Any]]] | None = None,
        http_client: Any = None,
        tool_registry: Any = None,
        workspace_dir: str = "",
        # Phase 11.1 agent integration
        event_bus: Any = None,
        capability_registry: Any = None,
        research_memory: Any = None,
        research_trace: Any = None,
        strategy_engine: Any = None,
        application_model: Any = None,
    ):
        self.engagement = engagement
        self.config = config or RunnerConfig()
        self.llm_generate = llm_generate
        self.http_client = http_client
        self.tool_registry = tool_registry
        self.workspace_dir = workspace_dir or self.config.workspace_dir

        # Agent subsystems (optional, passed through to ResearchLoop)
        self._event_bus = event_bus
        self._capability_registry = capability_registry
        self._research_memory = research_memory
        self._research_trace = research_trace
        self._strategy_engine = strategy_engine
        self._application_model = application_model

        # Phase 9: honest status tracking
        self._capability_notes: list[str] = []
        self._cancelled = False
        self._tool_executor: Any = None
        # Phase 11: cooperative cancellation — runner.cancel() stops the
        # research loop after the current iteration, saves a checkpoint and
        # marks the run cancelled (resumable).
        self._cancel_event: asyncio.Event = asyncio.Event()
        self._cancel_requested = False

        if not self.workspace_dir:
            self.workspace_dir = os.path.join(
                os.getcwd(), "engagements", engagement.id
            )

        # Initialize subsystems
        self._init_subsystems()

    def _init_subsystems(self):
        """Initialize all subsystems from the engagement."""
        # Scope
        scope_assets = self.engagement.policy.in_scope if self.engagement.policy else []
        out_of_scope = self.engagement.policy.out_of_scope if self.engagement.policy else []
        restrictions = self.engagement.policy.restrictions if self.engagement.policy else []

        self.scope_matcher = ScopeMatcher(scope_assets, out_of_scope)
        self.safety_gate = SafetyGate(
            in_scope_assets=scope_assets,
            out_of_scope_assets=out_of_scope,
            restrictions=restrictions,
            rate_limit=self.config.rate_limit,
            max_requests=self.config.max_requests,
        )

        # HITL
        self.hitl_gate = HITLGate(
            approval_level=self.config.approval_level,
        )
        self.pause_controller = PauseController()

        # Action gateway
        self.action_gateway = ActionGateway(
            safety_gate=self.safety_gate,
            hitl_gate=self.hitl_gate,
        )

        # State
        self.state_manager = StateManager(self.workspace_dir)
        os.makedirs(self.workspace_dir, exist_ok=True)

        # Auth
        self.auth_manager = AuthManager(workspace_dir=self.workspace_dir)

        # Evidence / validation
        self.evidence_collector = EvidenceCollector(workspace_dir=self.workspace_dir)
        self.validation_pipeline = ValidationPipeline(min_confidence=0.4)
        self.chain_detector = BugChainDetector()
        self.evidence_packager = EvidencePackager(workspace_dir=self.workspace_dir)

        # Reporting
        self.report_generator = ReportGenerator(workspace_dir=self.workspace_dir)

        # Build engagement context
        self.context = EngagementContext(
            engagement_id=self.engagement.id,
            target=self.engagement.target_url,
            program=self.engagement.policy.program_name if self.engagement.policy else "",
            workspace_dir=self.workspace_dir,
            engagement=self.engagement,
            policy=self.engagement.policy,
            auth_manager=self.auth_manager,
            hitl_gate=self.hitl_gate,
            safety_gate=self.safety_gate,
            action_gateway=self.action_gateway,
            tool_registry=self.tool_registry,
            state_manager=self.state_manager,
            llm_generate=self.llm_generate,
        )

    async def run(self) -> dict[str, Any]:
        """Run the complete autonomous engagement.

        Returns a summary dict with findings, stats, report path, and an
        honest ``status``: completed | degraded | partial | failed | blocked
        | cancelled — never a blanket "completed".

        Phase 9/16: exceptions are captured into the summary instead of
        being swallowed; CancellationError marks the run cancelled.
        """
        start_time = time.time()
        logger.info(f"Starting autonomous engagement: {self.engagement.id}")
        logger.info(f"Target: {self.engagement.target_url}")

        # Fresh run (or resume) → clear any stale cancel flag from a
        # previous cancellation of this same runner instance.
        self._cancelled = False
        self._cancel_requested = False
        try:
            self._cancel_event.clear()
        except RuntimeError:
            pass
        self._capability_notes = []

        state = None
        recon_results: dict[str, Any] | None = None
        crawl_results: dict[str, Any] | None = None
        research_report: dict[str, Any] = {"iterations": 0, "findings": []}
        chains: list = []
        report_path = ""
        tools_available = 0
        failure: str | None = None
        diagnostics: Any = None
        run_status = "completed"

        try:
            # 1. Persist initial state
            state = self.state_manager.initialize(
                engagement_id=self.engagement.id,
                target=self.engagement.target_url,
            )
            state.status = "initializing"
            self.state_manager.save_state(state)

            # 2. Check authorization
            if self.engagement.authorization_status != AuthorizationStatus.CONFIRMED:
                logger.warning("Authorization not confirmed — pausing for confirmation")
                self.pause_controller.pause(
                    PauseReason.HUMAN_REQUEST,
                    "Authorization not confirmed. Please confirm before active testing.",
                )
                await self.pause_controller.wait_for_resume()

            # 3. Discover tools first so the capability probe sees the registry
            tools_available = await self._discover_tools()
            state.data["tools_discovered"] = tools_available

            # 2b. Environment capability probe (Phase 4) — decides degraded/blocked
            diagnostics = self._probe_capabilities()

            state.status = "recon"
            self.state_manager.save_state(state)

            # 4. Execute recon (if not already done)
            recon_results = await self._run_recon(state)
            state.data["recon_complete"] = True
            self.state_manager.save_state(state)

            # 5. Crawl application
            crawl_results = await self._run_crawl(state, recon_results)
            state.data["crawl_complete"] = True
            self.state_manager.save_state(state)

            # 6. Run research loop
            state.status = "researching"
            self.state_manager.save_state(state)
            research_report = await self._run_research(state)
            # A provider can fail for the first time only during research
            # (missing SDK, 401, …), opening its circuit AFTER the probe at
            # step 2b already reported AVAILABLE. Re-check so a run whose LLM
            # calls all failed cannot be summarised as COMPLETED.
            self._note_llm_circuits()
            if research_report.get("error") and not research_report.get("findings"):
                failure = str(research_report["error"])
            if research_report.get("cancelled") or self._cancelled:
                # Phase 11: graceful cancel — stop the pipeline here, keep
                # whatever we have, save state for resume.
                run_status = "cancelled"
                self._cancelled = True
                logger.warning(
                    "Engagement cancelled — saving state for resume"
                )
                self._cancel_event.set()
                chains = self._detect_chains(research_report)
                if self.config.auto_report:
                    try:
                        report_path = self._generate_report(research_report, chains)
                    except Exception as e:  # noqa: BLE001
                        logger.warning(f"Report on cancel failed: {e}")
                duration = time.time() - start_time
                if state is not None:
                    state.status = "cancelled"
                    state.findings_count = len(research_report.get("findings", []))
                    try:
                        self.state_manager.save_state(state)
                    except Exception as e:  # noqa: BLE001
                        logger.warning(f"Could not persist cancelled state: {e}")
                summary = self._build_summary(
                    run_status, research_report, chains, report_path,
                    tools_available, recon_results, crawl_results,
                    duration, failure,
                )
                summary["resume_hint"] = "demogorgon resume"
                logger.warning(
                    f"Engagement cancelled: {summary['findings_count']} findings "
                    f"preserved after {duration:.1f}s"
                )
                return summary

            # 7. Detect attack chains
            chains = self._detect_chains(research_report)

            # 8. Generate report
            if self.config.auto_report:
                report_path = self._generate_report(research_report, chains)

        except asyncio.CancelledError:
            self._cancelled = True
            run_status = "cancelled"
            logger.warning("Engagement cancelled — state saved for resume")
            raise
        except Exception as e:
            failure = str(e)
            run_status = "failed"
            logger.exception(f"Engagement failed: {e}")
        finally:
            # 9. Final state — derive status honestly, never blanket "completed"
            # Re-check circuits too: a run that raised mid-research may have
            # opened a provider circuit that the t=0 probe never saw.
            self._note_llm_circuits()
            duration = time.time() - start_time
            if state is not None:
                if run_status == "cancelled":
                    state.status = "cancelled"
                elif run_status == "failed":
                    state.status = "failed"
                else:
                    run_status = self._derive_status(
                        run_status, research_report, failure, diagnostics
                    )
                    state.status = run_status
                state.findings_count = len(research_report.get("findings", []))
                state.evidence_count = research_report.get("evidence", {}).get("total_items", 0)
                try:
                    self.state_manager.save_state(state)
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"Could not persist final state: {e}")

            summary = self._build_summary(
                run_status, research_report, chains, report_path,
                tools_available, recon_results, crawl_results,
                duration, failure,
            )

            if run_status == "cancelled":
                summary["resume_hint"] = "demogorgon resume"

        logger.info(
            f"Engagement {run_status}: {summary['findings_count']} findings, "
            f"{summary['chains_count']} chains in {duration:.1f}s"
            + (f" — {failure}" if failure else "")
        )
        return summary

    @staticmethod
    def _dedupe_notes(notes: list[str]) -> list[str]:
        """Collapse notes that describe the same capability.

        The probe records "recon: unavailable" and the stage runner then adds
        "recon: unavailable (<reason>)". Keep the most specific (longest) note
        per capability prefix so users see one line, not two.
        """
        best: dict[str, str] = {}
        order: list[str] = []
        for note in notes:
            key = note.split(":", 1)[0].strip() if ":" in note else note
            if key not in best:
                best[key] = note
                order.append(key)
            elif len(note) > len(best[key]):
                best[key] = note
        return [best[k] for k in order]

    def _build_summary(
        self,
        run_status: str,
        research_report: dict[str, Any],
        chains: list,
        report_path: str,
        tools_available: int,
        recon_results: dict[str, Any] | None,
        crawl_results: dict[str, Any] | None,
        duration: float,
        failure: str | None,
    ) -> dict[str, Any]:
        """Assemble the run summary + coverage (Phase 9/10)."""
        summary = {
            "engagement_id": self.engagement.id,
            "target": self.engagement.target_url,
            "status": run_status,
            "status_notes": self._dedupe_notes(self._capability_notes),
            "error": failure,
            "duration": duration,
            "iterations": research_report.get("iterations", 0),
            "findings": research_report.get("findings", []),
            "findings_count": len(research_report.get("findings", [])),
            "chains": [c.to_dict() for c in chains],
            "chains_count": len(chains),
            "report_path": report_path,
            "stats": {
                "tools_discovered": tools_available,
                "recon": recon_results.get("stats", {}) if recon_results else {},
                "crawl": crawl_results or {},
                "research": research_report.get("stats", {}),
            },
        }

        # Phase 10: canonical result object + honest coverage metrics
        try:
            from .hunt_result import HuntResult
            scope_assets = (
                self.engagement.policy.in_scope
                if self.engagement.policy else []
            )
            hunt = HuntResult.from_summary(
                summary,
                scope_assets=scope_assets,
                llm_used=bool(self.llm_generate),
            )
            summary["coverage"] = hunt.coverage.to_dict()
            summary["coverage_summary"] = hunt.coverage.describe()
        except Exception as e:  # noqa: BLE001 — coverage must never kill a run
            logger.debug(f"Coverage computation failed: {e}")

        return summary

    def _probe_capabilities(self) -> Any:
        """Probe environment capabilities and record notes for the summary."""
        try:
            from .capabilities import build_environment_registry

            registry = build_environment_registry(
                llm_generate=self.llm_generate,
                tool_registry=self.tool_registry,
                target=self.engagement.target_url,
            )
            diag = registry.probe_all()
            if diag.missing_required:
                self._capability_notes.append(
                    "missing required capability: " + ", ".join(diag.missing_required)
                )
            for name in diag.unavailable:
                self._capability_notes.append(f"{name}: unavailable")
            for name in diag.degraded:
                self._capability_notes.append(f"{name}: degraded")
            self._capability_diag = diag
            return diag
        except Exception as e:  # noqa: BLE001 — diagnostics must never kill a run
            logger.debug(f"Capability probe failed: {e}")
            self._capability_notes.append(f"capability probe failed: {e}")
            return None

    def _note_llm_circuits(self) -> None:
        """Record LLM circuit-breaker state as capability notes (Phase 16).

        ``_probe_capabilities`` runs before research, so it can only see the
        state at t=0. This re-reads the manager's circuits and appends a note;
        ``_derive_status`` then downgrades COMPLETED to DEGRADED, which is the
        truth when the reasoning engine never actually answered.
        """
        try:
            from .capabilities import llm_circuit_state

            circuits = llm_circuit_state(self.llm_generate)
        except Exception as e:  # noqa: BLE001 — never fail a run over a note
            logger.debug(f"LLM circuit check failed: {e}")
            return
        opened = circuits.get("open") or {}
        if not opened and not circuits.get("exhausted"):
            return
        detail = "; ".join(f"{k}: {v}" for k, v in opened.items()) or "unknown"
        if circuits.get("exhausted"):
            self._capability_notes.append(
                f"llm: unavailable (all providers circuit-open — {detail})"
            )
        else:
            self._capability_notes.append(
                f"llm: degraded (circuit open — {detail})"
            )

    def _derive_status(
        self,
        current: str,
        research_report: dict[str, Any],
        failure: str | None,
        diagnostics: Any,
    ) -> str:
        """Derive the honest terminal status for this run (Phase 9).

        Rules (agreed spec):
        - exception → failed (handled by caller)
        - cancelled  → cancelled (handled by caller)
        - no research engine could run (no LLM AND deterministic backbone
          unavailable) → blocked
        - research errored without findings → failed
        - capability unavailable/degraded notes present → degraded
        - research stopped early / partial results → partial
        - else → completed
        """
        no_llm = not self.llm_generate
        # "blocked" = neither engine could run. Use the capability probe
        # (authoritative) and only fall back to notes when there is no diag.
        det_missing = False
        if diagnostics is not None:
            det_missing = any(
                "deterministic" in n for n in getattr(diagnostics, "missing_required", [])
            ) or any(
                n == "deterministic_research"
                for n in getattr(diagnostics, "unavailable", [])
            )
        else:
            # No probe available — interpret notes conservatively: only a
            # note that is *about* the deterministic engine being absent
            # counts (e.g. "llm: unavailable (deterministic backbone
            # running)" must NOT be mistaken for a missing backbone).
            det_missing = any(
                (n.startswith("deterministic") or "missing required capability" in n)
                and ("unavailable" in n or "missing" in n)
                for n in self._capability_notes
            )
        if no_llm and det_missing:
            # neither LLM nor deterministic backbone could run
            return "blocked"

        if failure:
            # research loop hard-failed with no output
            if not research_report.get("findings") and research_report.get("error"):
                return "failed"

        if research_report.get("partial"):
            return "partial"

        if self._capability_notes:
            # ran, but something was degraded (recon failures, no LLM, …)
            if no_llm or any("failed" in n or "degraded" in n or "unavailable" in n
                             for n in self._capability_notes):
                return "degraded"

        if research_report.get("error") and not research_report.get("findings"):
            return "failed"

        return current

    async def resume(self) -> dict[str, Any]:
        """Resume a previously paused/interrupted engagement."""
        state = self.state_manager.load_state()
        if not state:
            logger.error("No saved state found for resume")
            return {"error": "No saved state found"}

        logger.info(f"Resuming engagement from iteration {state.iteration}")

        # Resume the research loop from checkpoint
        return await self.run()

    async def _discover_tools(self) -> int:
        """Discover available security tools (Phase 5: real registry, awaited)."""
        if not self.tool_registry:
            # Build the default registry — CLI never passed one (root cause of
            # "0 recon stages silently skipped").
            try:
                from ..tools.registry import create_default_registry
                self.tool_registry = create_default_registry()
                self.context.tool_registry = self.tool_registry
            except Exception as e:
                logger.warning(f"Could not build tool registry: {e}")
                return 0

        try:
            if hasattr(self.tool_registry, 'discover_all'):
                result = self.tool_registry.discover_all()
                if asyncio.iscoroutine(result):
                    await result
            available = (
                self.tool_registry.get_available_tools()
                if hasattr(self.tool_registry, 'get_available_tools') else []
            )
            self.context.available_tools = [
                t.name if hasattr(t, 'name') else str(t) for t in available
            ]
            logger.info(f"Discovered {len(self.context.available_tools)} tools")
            return len(self.context.available_tools)
        except Exception as e:
            logger.warning(f"Tool discovery failed: {e}")
            return 0

    async def _run_recon(self, state: EngagementState) -> dict[str, Any] | None:
        """Execute reconnaissance phase (Phase 5: correct registry/executor).

        ReconEngine takes (registry, executor) — the executor must be a
        ToolExecutor wrapping the registry, not the registry itself.
        Stage failures are surfaced in the returned stats, never swallowed.
        """
        if state.data.get("recon_complete"):
            logger.info("Recon already complete — skipping")
            return None

        logger.info("Starting reconnaissance...")

        try:
            from ..recon.engine import ReconEngine
        except ImportError as e:
            logger.warning(f"ReconEngine not available — skipping recon: {e}")
            self._capability_notes.append(f"recon: unavailable ({e})")
            return None

        if self.tool_registry is None:
            logger.warning("No tool registry — recon skipped")
            self._capability_notes.append("recon: no tool registry")
            return None

        try:
            from ..tools.executor import ToolExecutor

            executor = getattr(self, "_tool_executor", None)
            if executor is None:
                executor = ToolExecutor(self.tool_registry)
                self._tool_executor = executor

            engine = ReconEngine(
                registry=self.tool_registry,
                executor=executor,
                scope_matcher=self.scope_matcher,
            )
            result = await engine.run(self.engagement.target_url)
            stage_errors = {
                s.name: s.error for s in engine._stages if s.error
            }
            stats = {
                "subdomains": len(result.subdomains),
                "live_hosts": len(result.live_hosts),
                "endpoints": len(result.endpoints),
                "ports": len(result.ports),
                "technologies": len(result.technologies),
                "stages_completed": result.stages_completed,
                "stages_total": result.stages_total,
                "stages_skipped": result.stages_skipped,
                "stage_errors": stage_errors,
            }
            # Per-stage failures are target-specific (unreachable domain,
            # rate-limited API) — they belong in stats, not in the run's
            # capability notes. Only engine-level breakage degrades the run.
            if stage_errors:
                logger.info(
                    f"Recon: {len(stage_errors)} stage(s) reported errors "
                    f"({', '.join(stage_errors)})"
                )
            if result.stages_total and result.stages_completed == 0:
                logger.warning("Recon ran but completed 0 stages")
                self._capability_notes.append(
                    "recon: 0 stages completed (engine could not run)"
                )
            logger.info(
                f"Recon complete: {stats['subdomains']} subdomains, "
                f"{stats['live_hosts']} live hosts "
                f"({result.stages_completed}/{result.stages_total} stages, "
                f"{result.stages_skipped} skipped)"
            )
            return {"stats": stats, "stage_errors": stage_errors}
        except Exception as e:
            logger.error(f"Recon failed: {e}")
            self._capability_notes.append(f"recon: failed ({e})")
            return {"stats": {}, "stage_errors": {"_engine": str(e)}}

    async def _run_crawl(
        self,
        state: EngagementState,
        recon_results: dict[str, Any] | None,
    ) -> dict[str, Any] | None:
        """Execute crawl phase."""
        if state.data.get("crawl_complete"):
            logger.info("Crawl already complete — skipping")
            return None

        logger.info("Crawling application...")

        try:
            from ..core.crawl.pipeline import CrawlerPipeline
            from ..app_model import ApplicationModel

            app_model = ApplicationModel(target_url=self.engagement.target_url)
            pipeline = CrawlerPipeline(app_model=app_model)

            # Ingest URLs from recon if available
            # The pipeline will also discover endpoints from katana/crawler

            return {"endpoints": len(pipeline.get_endpoints())}
        except Exception as e:
            logger.warning(f"Crawl failed or unavailable: {e}")
            return None

    async def _run_research(self, state: EngagementState) -> dict[str, Any]:
        """Execute the autonomous research loop."""
        logger.info("Starting research loop...")

        if not self.llm_generate:
            # Phase 6: no LLM is a *degraded* mode, not a dead end — the
            # deterministic safe-GET backbone still runs the loop.
            logger.warning(
                "No LLM provider configured — running deterministic backbone"
            )
            # The capability probe already recorded a bare "llm: unavailable"
            # note; enrich it in place rather than emitting a near-duplicate.
            for i, note in enumerate(self._capability_notes):
                if note.startswith("llm:"):
                    self._capability_notes[i] = (
                        "llm: unavailable (deterministic backbone running)"
                    )
                    break
            else:
                self._capability_notes.append(
                    "llm: unavailable (deterministic backbone running)"
                )

        loop_config = LoopConfig(
            max_iterations=self.config.max_iterations,
            rate_limit_delay=1.0 / self.config.rate_limit if self.config.rate_limit > 0 else 1.0,
            checkpoint_interval=self.config.checkpoint_interval,
        )

        research_loop = ResearchLoop(
            target=self.engagement.target_url,
            llm_generate=self.llm_generate,
            http_client=self.http_client,
            tools=self.context.available_tools,
            config=loop_config,
            workspace_dir=self.workspace_dir,
            engagement_id=self.engagement.id,
            state_manager=self.state_manager,
            validation_pipeline=self.validation_pipeline,
            # Phase 11.1 agent subsystems
            event_bus=self._event_bus,
            capability_registry=self._capability_registry,
            research_memory=self._research_memory,
            research_trace=self._research_trace,
            strategy_engine=self._strategy_engine,
            application_model=self._application_model,
            # Phase 11: cooperative cancellation
            cancel_event=self._cancel_event,
        )

        await research_loop.initialize()

        # Check for existing checkpoint
        checkpoint = self.state_manager.get_latest_checkpoint()
        if checkpoint:
            iteration, data = checkpoint
            logger.info(f"Resuming from checkpoint at iteration {iteration}")

        try:
            report = await research_loop.run()
            if report.get("cancelled"):
                self._cancelled = True
            return report
        except asyncio.CancelledError:
            # Hard cancel (task cancelled externally) — mark and propagate
            self._cancelled = True
            raise
        except Exception as e:
            logger.error(f"Research loop failed: {e}")
            return {"iterations": 0, "findings": [], "error": str(e)}

    def cancel(self) -> None:
        """Request a graceful cancel of the running engagement (Phase 11).

        The research loop finishes its current iteration, checkpoints, and
        the run ends with status="cancelled" (resumable via `demogorgon resume`).
        Safe to call from a signal handler or another task.
        """
        self._cancelled = True
        self._cancel_requested = True
        try:
            self._cancel_event.set()
        except RuntimeError:
            # No running loop yet — the flag alone is enough
            pass
        logger.info("Cancel requested — stopping after current iteration")

    @property
    def cancel_requested(self) -> bool:
        return self._cancel_requested or self._cancel_event.is_set()

    def _detect_chains(self, research_report: dict[str, Any]) -> list:
        """Detect attack chains from findings."""
        findings = research_report.get("findings", [])
        if not findings:
            return []

        observations = []
        for f in findings:
            if isinstance(f, dict):
                observations.append({
                    "vuln_class": f.get("vuln_class", f.get("type", "")),
                    "endpoint": f.get("endpoint", ""),
                    "description": f.get("description", ""),
                    "confidence": f.get("confidence", 0.5),
                })

        chains = self.chain_detector.detect_chains(observations)
        if chains:
            logger.info(f"Detected {len(chains)} attack chain(s)")
        return chains

    def _generate_report(
        self,
        research_report: dict[str, Any],
        chains: list,
    ) -> str:
        """Generate the final report."""
        findings_data = research_report.get("findings", [])
        findings = []
        for f in findings_data:
            if isinstance(f, dict):
                findings.append(Finding(
                    title=f.get("title", f.get("vuln_class", "Unknown")),
                    severity=f.get("severity", "unknown"),
                    vuln_class=f.get("vuln_class", f.get("type", "")),
                    endpoint=f.get("endpoint", ""),
                    method=f.get("method", ""),
                    description=f.get("description", ""),
                    impact=f.get("impact", ""),
                    remediation=f.get("remediation", ""),
                    reproduction_steps=f.get("reproduction_steps", []),
                    request_response_pairs=f.get("request_response_pairs", []),
                ))

        report = self.report_generator.generate(
            findings=findings,
            target=self.engagement.target_url,
            program=self.engagement.policy.program_name if self.engagement.policy else "",
            stats=research_report.get("stats", {}),
            metadata={"chains": [c.to_dict() for c in chains]},
        )

        try:
            json_path = self.report_generator.save_json(report)
            md_path = self.report_generator.save_markdown(report)
            logger.info(f"Report saved: {json_path}, {md_path}")
            return md_path
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return ""

    def get_status(self) -> dict[str, Any]:
        """Get current runner status."""
        state = self.state_manager.load_state()
        return {
            "engagement_id": self.engagement.id,
            "target": self.engagement.target_url,
            "workspace": self.workspace_dir,
            "state": state.to_dict() if state else None,
            "gateway_stats": self.action_gateway.get_stats(),
            "safety_stats": self.safety_gate.get_stats(),
        }
