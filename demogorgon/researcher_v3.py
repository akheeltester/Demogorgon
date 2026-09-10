"""Researcher V3 — autonomous security researcher using research loop.

The researcher NEVER directly executes HTTP requests, browser actions,
mutations, or replay logic. Instead it:

1. Observes the application
2. Thinks about what to test
3. Chooses an objective
4. Selects a deterministic tool
5. Executes the tool
6. Evaluates the evidence
7. Updates strategy
8. Repeats
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from rich.console import Console

from demogorgon.controller.executive import ExecutiveController, Hypothesis
from demogorgon.controller.execution_graph import ExecutionGraph
from demogorgon.controller.self_evaluator import SelfEvaluator
from demogorgon.controller.tool_selection import get_executor_spec
from demogorgon.llm.manager import LLMManager
from demogorgon.tools.http_client import HTTPClient
from demogorgon.tools.browser import BrowserTool
from demogorgon.memory import Memory
from demogorgon.research_loop import ResearchLoop, LoopConfig

console = Console()


class ResearcherV3:
    """Autonomous security researcher using research loop."""

    def __init__(
        self,
        target_url: str,
        headless: bool = True,
        proxy: str | None = None,
        rate_limit: float = 1.0,
        max_experiments: int = 50,
        output_dir: str = "hunt_output_v3",
    ):
        self.target_url = target_url
        self.headless = headless
        self.proxy = proxy
        self.rate_limit = rate_limit
        self.max_experiments = max_experiments
        self.output_dir = output_dir

        self.controller = ExecutiveController()
        self.graph = ExecutionGraph()
        self.evaluator = SelfEvaluator()
        self.llm_manager = LLMManager()
        self.http = HTTPClient(proxy=proxy)
        self.memory = Memory(target_url, output_dir)
        self.browser: BrowserTool | None = None

        self._executors: dict[str, Any] = {}
        self._experiment_count = 0
        self._loop: ResearchLoop | None = None

    async def start(self) -> dict[str, Any]:
        console.print(f"\n[bold green]Demogorgon — Autonomous Hunt on {self.target_url}[/bold green]\n")

        self.llm_manager.configure()
        console.print(f"[cyan]LLM: {self.llm_manager._active_provider}/{self.llm_manager._active_model}[/cyan]")

        self.browser = BrowserTool(headless=self.headless, proxy=self.proxy)
        await self.browser.launch()

        # Create research loop
        config = LoopConfig(
            max_experiments=self.max_experiments,
            self_eval_interval=20,
            rate_limit_delay=self.rate_limit,
        )

        self._loop = ResearchLoop(
            target_url=self.target_url,
            llm_complete=self._llm_complete,
            http_client=self.http,
            browser_tool=self.browser,
            auth_manager=self._create_auth_manager(),
            config=config,
        )

        # Run the research loop
        result = await self._loop.run()

        await self._cleanup()
        return self._generate_report()

    async def _llm_complete(self, messages: list[dict], **kwargs) -> str:
        """Wrapper for LLM completion."""
        resp = await self.llm_manager.generate(messages, **kwargs)
        if resp.error:
            raise Exception(resp.error)
        return resp.content

    def _create_auth_manager(self):
        """Create a basic auth manager."""
        from demogorgon.auth.bridge import AuthManager
        from urllib.parse import urlparse
        domain = urlparse(self.target_url).hostname or ""
        return AuthManager(target_domain=domain)

    async def _cleanup(self) -> None:
        if self.browser:
            await self.browser.close()
        await self.http.close()

    def _generate_report(self) -> dict[str, Any]:
        if self._loop:
            findings = self._loop.memory.findings
            return {
                "target": self.target_url,
                "iterations": self._loop.state.experiment_count,
                "findings": len(findings),
                "finding_details": [
                    {
                        "title": f.title,
                        "severity": f.severity.value,
                        "vuln_class": f.vuln_class,
                        "endpoint": f.endpoint,
                    }
                    for f in findings
                ],
                "coverage": self._loop.evaluator.get_progress_summary(),
                "evaluator": self._loop.evaluator.get_progress_summary(),
                "graph": {"nodes": 0, "edges": 0},
            }

        return {
            "target": self.target_url,
            "iterations": 0,
            "findings": 0,
            "finding_details": [],
            "coverage": {},
            "evaluator": {},
            "graph": {},
        }
