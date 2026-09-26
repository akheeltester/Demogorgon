"""Recon Engine — orchestrates reconnaissance in stages.

The engine:
1. Discovers assets through multiple sources
2. Normalizes and stores assets in the asset database
3. Classifies assets by type and risk
4. Builds relationships between assets
5. Reports findings to the research brain

The LLM decides which recon stage provides the highest value
based on what has already been discovered.
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

from ..tools.registry import ToolRegistry
from ..tools.executor import ToolExecutor, ActionResult
from ..core.scope.matcher import ScopeMatcher
from ..core.engagement import Engagement


@dataclass
class ReconStage:
    """A single reconnaissance stage."""
    name: str
    description: str
    depends_on: list[str] = field(default_factory=list)  # stage names
    tool_hint: str = ""  # suggested tool
    priority: int = 0  # higher = run first
    completed: bool = False
    result: dict[str, Any] = field(default_factory=dict)
    duration: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "depends_on": self.depends_on,
            "completed": self.completed,
            "duration": self.duration,
            "error": self.error,
            "result_summary": {
                k: v for k, v in self.result.items()
                if k in ("total", "subdomains", "live_hosts", "endpoints", "ports")
            },
        }


@dataclass
class ReconResult:
    """Result of a complete recon operation."""
    domain: str
    stages_completed: int = 0
    stages_total: int = 0
    stages_skipped: int = 0
    subdomains: list[str] = field(default_factory=list)
    live_hosts: list[dict[str, Any]] = field(default_factory=list)
    endpoints: list[dict[str, Any]] = field(default_factory=list)
    ports: list[dict[str, Any]] = field(default_factory=list)
    technologies: list[str] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "domain": self.domain,
            "stages_completed": self.stages_completed,
            "stages_total": self.stages_total,
            "stages_skipped": self.stages_skipped,
            "subdomains_count": len(self.subdomains),
            "live_hosts_count": len(self.live_hosts),
            "endpoints_count": len(self.endpoints),
            "ports_count": len(self.ports),
            "technologies": self.technologies,
            "duration": self.duration,
        }


class ReconEngine:
    """Autonomous reconnaissance engine.

    Orchestrates recon in stages, using the tool registry for execution.
    The LLM can influence which stages are prioritized.

    Usage:
        engine = ReconEngine(registry, executor, scope_matcher)
        result = await engine.run("example.com")
    """

    def __init__(
        self,
        registry: ToolRegistry,
        executor: ToolExecutor,
        scope_matcher: ScopeMatcher | None = None,
        stage_timeout: float | None = None,
    ):
        self._registry = registry
        self._executor = executor
        self._scope_matcher = scope_matcher
        # Phase 5: never let one stage hang the whole engagement. External
        # binaries (nmap, subfinder) can block indefinitely on a dead target.
        # Override with DEMOGORGON_RECON_TIMEOUT (seconds, 0 disables).
        if stage_timeout is None:
            stage_timeout = float(os.environ.get("DEMOGORGON_RECON_TIMEOUT", "60"))
        self._stage_timeout = stage_timeout
        self._stages = self._build_stages()
        self._results: dict[str, Any] = {}

    def _build_stages(self) -> list[ReconStage]:
        """Build the default recon stages."""
        return [
            ReconStage(
                name="subdomain_enum",
                description="Discover subdomains through passive sources",
                depends_on=[],
                tool_hint="subfinder",
                priority=10,
            ),
            ReconStage(
                name="cert_transparency",
                description="Discover subdomains through certificate transparency logs",
                depends_on=[],
                tool_hint="crtsh",
                priority=9,
            ),
            ReconStage(
                name="dns_resolution",
                description="Resolve subdomains to IP addresses",
                depends_on=["subdomain_enum"],
                tool_hint="dnsx",
                priority=8,
            ),
            ReconStage(
                name="http_probe",
                description="Probe for live HTTP services",
                depends_on=["subdomain_enum"],
                tool_hint="httpx",
                priority=7,
            ),
            ReconStage(
                name="port_scan",
                description="Scan for open ports and services",
                depends_on=["dns_resolution"],
                tool_hint="nmap",
                priority=6,
            ),
            ReconStage(
                name="tech_fingerprint",
                description="Identify technologies and frameworks",
                depends_on=["http_probe"],
                tool_hint="httpx",
                priority=5,
            ),
            ReconStage(
                name="web_crawl",
                description="Crawl web applications for endpoints",
                depends_on=["http_probe"],
                tool_hint="katana",
                priority=4,
            ),
            ReconStage(
                name="url_harvest",
                description="Harvest URLs from historical sources",
                depends_on=[],
                tool_hint="gau",
                priority=3,
            ),
        ]

    async def run(
        self,
        domain: str,
        stages: list[str] | None = None,
        priority_stages: list[str] | None = None,
    ) -> ReconResult:
        """Run reconnaissance on a domain.

        Args:
            domain: Target domain to recon
            stages: Specific stages to run (None = all)
            priority_stages: Stages to prioritize

        Returns:
            ReconResult with all discovered assets
        """
        start = time.time()
        result = ReconResult(domain=domain)

        # Filter stages if specific ones requested
        active_stages = self._stages
        if stages:
            active_stages = [s for s in self._stages if s.name in stages]

        # Sort by priority (higher first), with priority_stages boosted
        if priority_stages:
            for stage in active_stages:
                if stage.name in priority_stages:
                    stage.priority += 100
        active_stages.sort(key=lambda s: s.priority, reverse=True)

        result.stages_total = len(active_stages)

        # Run stages
        for stage in active_stages:
            # Check dependencies
            deps_met = all(
                any(s.name == dep and s.completed for s in active_stages)
                for dep in stage.depends_on
            )
            if not deps_met:
                # A stage whose dependency failed/timed out never runs —
                # count it so "completed/total" is honest (Phase 5).
                result.stages_skipped += 1
                stage.error = stage.error or "skipped: dependency not met"
                continue

            # Run the stage
            await self._run_stage(stage, domain)

            # Collect results
            if stage.completed:
                result.stages_completed += 1
                self._collect_results(stage, result)

        result.duration = time.time() - start
        return result

    async def _run_stage(self, stage: ReconStage, domain: str) -> None:
        """Run a single recon stage (bounded by ``stage_timeout``)."""
        start = time.time()

        try:
            coro = self._dispatch_stage(stage, domain)
            if self._stage_timeout and self._stage_timeout > 0:
                try:
                    stage.result = await asyncio.wait_for(
                        coro, timeout=self._stage_timeout
                    )
                except asyncio.TimeoutError:
                    stage.error = f"stage timed out after {self._stage_timeout}s"
                    stage.duration = time.time() - start
                    logger.warning(
                        f"Recon stage {stage.name} timed out after "
                        f"{self._stage_timeout}s"
                    )
                    return
            else:
                stage.result = await coro

            stage.completed = True
        except Exception as e:
            stage.error = str(e)

        stage.duration = time.time() - start

    async def _dispatch_stage(self, stage: ReconStage, domain: str) -> Any:
        """Route a stage to its handler (Phase 5: explicit, testable)."""
        if stage.name == "subdomain_enum":
            return await self._stage_subdomain_enum(domain)
        if stage.name == "cert_transparency":
            return await self._stage_cert_transparency(domain)
        if stage.name == "dns_resolution":
            return await self._stage_dns_resolution(domain)
        if stage.name == "http_probe":
            return await self._stage_http_probe(domain)
        if stage.name == "port_scan":
            return await self._stage_port_scan(domain)
        if stage.name == "tech_fingerprint":
            return await self._stage_tech_fingerprint(domain)
        if stage.name == "web_crawl":
            return await self._stage_web_crawl(domain)
        if stage.name == "url_harvest":
            return await self._stage_url_harvest(domain)
        raise ValueError(f"Unknown stage: {stage.name}")

    async def _stage_subdomain_enum(self, domain: str) -> dict[str, Any]:
        """Enumerate subdomains."""
        result = await self._executor.execute_recon("subdomain_enum", {"domain": domain})
        return result.data

    async def _stage_cert_transparency(self, domain: str) -> dict[str, Any]:
        """Certificate transparency lookup."""
        result = await self._executor.execute_recon("cert_transparency", {"domain": domain})
        return result.data

    async def _stage_dns_resolution(self, domain: str) -> dict[str, Any]:
        """Resolve subdomains to IPs."""
        # Get subdomains from previous stages
        subdomains = self._results.get("subdomains", [])
        if not subdomains:
            return {"error": "No subdomains to resolve"}

        result = await self._executor.execute_recon("dns_enum", {"domain": domain})
        return result.data

    async def _stage_http_probe(self, domain: str) -> dict[str, Any]:
        """Probe for live HTTP services."""
        subdomains = self._results.get("subdomains", [])
        if not subdomains:
            # Use the domain itself
            subdomains = [domain]

        # Format as URLs
        targets = []
        for sub in subdomains[:100]:  # Limit to 100
            if not sub.startswith("http"):
                targets.append(f"https://{sub}")
            else:
                targets.append(sub)

        result = await self._executor.execute_recon("http_probe", {"targets": targets})
        return result.data

    async def _stage_port_scan(self, domain: str) -> dict[str, Any]:
        """Scan for open ports."""
        result = await self._executor.execute_recon("port_scan", {
            "target": domain,
            "ports": "1-1000",
        })
        return result.data

    async def _stage_tech_fingerprint(self, domain: str) -> dict[str, Any]:
        """Identify technologies."""
        # Technologies are already captured in http_probe
        live_hosts = self._results.get("live_hosts", [])
        technologies = set()
        for host in live_hosts:
            for tech in host.get("tech", []):
                technologies.add(tech)
        return {"technologies": sorted(technologies), "total": len(technologies)}

    async def _stage_web_crawl(self, domain: str) -> dict[str, Any]:
        """Crawl web applications."""
        live_hosts = self._results.get("live_hosts", [])
        if not live_hosts:
            return {"endpoints": [], "total": 0}

        all_endpoints = []
        for host in live_hosts[:5]:  # Limit to 5 hosts
            url = host.get("url", "")
            if url:
                result = await self._executor.execute_recon("web_crawl", {
                    "url": url,
                    "depth": 2,
                })
                if result.success:
                    all_endpoints.extend(result.data.get("endpoints", []))

        return {"endpoints": all_endpoints, "total": len(all_endpoints)}

    async def _stage_url_harvest(self, domain: str) -> dict[str, Any]:
        """Harvest URLs from historical sources."""
        result = await self._executor.execute_recon("url_harvest", {"domain": domain})
        return result.data

    def _collect_results(self, stage: ReconStage, result: ReconResult) -> None:
        """Collect results from a completed stage into the result object."""
        data = stage.result

        if stage.name in ("subdomain_enum", "cert_transparency"):
            subs = data.get("subdomains", [])
            self._results.setdefault("subdomains", []).extend(subs)
            result.subdomains = list(set(self._results["subdomains"]))

        elif stage.name == "http_probe":
            hosts = data.get("live_hosts", [])
            self._results.setdefault("live_hosts", []).extend(hosts)
            result.live_hosts = self._results["live_hosts"]

        elif stage.name == "web_crawl":
            endpoints = data.get("endpoints", [])
            self._results.setdefault("endpoints", []).extend(endpoints)
            result.endpoints = self._results["endpoints"]

        elif stage.name == "port_scan":
            ports = data.get("ports", [])
            self._results.setdefault("ports", []).extend(ports)
            result.ports = self._results["ports"]

        elif stage.name == "tech_fingerprint":
            techs = data.get("technologies", [])
            result.technologies = techs

    def get_stage_status(self) -> list[dict[str, Any]]:
        """Get status of all stages."""
        return [stage.to_dict() for stage in self._stages]

    def get_results(self) -> dict[str, Any]:
        """Get accumulated results."""
        return {
            "subdomains": list(set(self._results.get("subdomains", []))),
            "live_hosts": self._results.get("live_hosts", []),
            "endpoints": self._results.get("endpoints", []),
            "ports": self._results.get("ports", []),
        }
