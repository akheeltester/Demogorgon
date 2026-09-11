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
    ):
        self.engagement = engagement
        self.config = config or RunnerConfig()
        self.llm_generate = llm_generate
        self.http_client = http_client
        self.tool_registry = tool_registry
        self.workspace_dir = workspace_dir or self.config.workspace_dir

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

        Returns a summary dict with findings, stats, and report path.
        """
        start_time = time.time()
        logger.info(f"Starting autonomous engagement: {self.engagement.id}")
        logger.info(f"Target: {self.engagement.target_url}")

        # 1. Persist initial state
        state = self.state_manager.initialize(
            engagement_id=self.engagement.id,
            target=self.engagement.target_url,
        )

        # 2. Check authorization
        if self.engagement.authorization_status != AuthorizationStatus.CONFIRMED:
            logger.warning("Authorization not confirmed — pausing for confirmation")
            self.pause_controller.pause(
                PauseReason.HUMAN_REQUEST,
                "Authorization not confirmed. Please confirm before active testing.",
            )
            await self.pause_controller.wait_for_resume()

        # 3. Discover tools
        tools_available = await self._discover_tools()
        state.data["tools_discovered"] = tools_available
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
        research_report = await self._run_research(state)

        # 7. Detect attack chains
        chains = self._detect_chains(research_report)

        # 8. Generate report
        report_path = ""
        if self.config.auto_report:
            report_path = self._generate_report(research_report, chains)

        # 9. Final state
        state.status = "completed"
        state.findings_count = len(research_report.get("findings", []))
        state.evidence_count = research_report.get("evidence", {}).get("total_items", 0)
        self.state_manager.save_state(state)

        duration = time.time() - start_time

        summary = {
            "engagement_id": self.engagement.id,
            "target": self.engagement.target_url,
            "status": "completed",
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
                "research": research_report.get("stats", {}),
            },
        }

        logger.info(f"Engagement complete: {summary['findings_count']} findings, "
                     f"{summary['chains_count']} chains in {duration:.1f}s")

        return summary

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
        """Discover available security tools."""
        if not self.tool_registry:
            logger.info("No tool registry — skipping tool discovery")
            return 0

        try:
            if hasattr(self.tool_registry, 'discover_all'):
                self.tool_registry.discover_all()
            available = self.tool_registry.get_available_tools() if hasattr(self.tool_registry, 'get_available_tools') else []
            self.context.available_tools = [t.name if hasattr(t, 'name') else str(t) for t in available]
            logger.info(f"Discovered {len(self.context.available_tools)} tools")
            return len(self.context.available_tools)
        except Exception as e:
            logger.warning(f"Tool discovery failed: {e}")
            return 0

    async def _run_recon(self, state: EngagementState) -> dict[str, Any] | None:
        """Execute reconnaissance phase."""
        if state.data.get("recon_complete"):
            logger.info("Recon already complete — skipping")
            return None

        logger.info("Starting reconnaissance...")

        try:
            from ..recon.engine import ReconEngine
            engine = ReconEngine(
                registry=self.tool_registry,
                executor=self.tool_registry,
            )
            result = await engine.run(self.engagement.target_url)
            stats = {
                "subdomains": len(result.subdomains),
                "live_hosts": len(result.live_hosts),
                "endpoints": len(result.endpoints),
                "ports": len(result.ports),
                "technologies": len(result.technologies),
                "stages_completed": result.stages_completed,
            }
            logger.info(f"Recon complete: {stats['subdomains']} subdomains, {stats['live_hosts']} live hosts")
            return {"stats": stats}
        except ImportError:
            logger.warning("ReconEngine not available — skipping recon")
            return None
        except Exception as e:
            logger.error(f"Recon failed: {e}")
            return None

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
            logger.error("No LLM provider configured — cannot run research")
            return {"iterations": 0, "findings": [], "error": "No LLM provider"}

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
        )

        await research_loop.initialize()

        # Check for existing checkpoint
        checkpoint = self.state_manager.get_latest_checkpoint()
        if checkpoint:
            iteration, data = checkpoint
            logger.info(f"Resuming from checkpoint at iteration {iteration}")

        try:
            report = await research_loop.run()
            return report
        except Exception as e:
            logger.error(f"Research loop failed: {e}")
            return {"iterations": 0, "findings": [], "error": str(e)}

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
