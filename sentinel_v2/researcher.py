"""Researcher — the brain of Sentinel V2.

One researcher. Many tools. No fake intelligence.

The researcher initializes all components and delegates to the ResearchLoop.
The LLM decides WHAT to test and WHY.
Deterministic executors decide HOW to test.
Every decision is explainable.
"""

from __future__ import annotations

import time
from typing import Any

from rich.console import Console

from sentinel_v2.memory import Memory
from sentinel_v2.app_model import ApplicationModel
from sentinel_v2.tools.http_client import HTTPClient
from sentinel_v2.auth.bridge import AuthManager
from sentinel_v2.tools.tool_bus import ToolBus
from sentinel_v2.tools.recon import Recon
from sentinel_v2.reasoning_trace import ReasoningTrace
from sentinel_v2.evidence_validator import EvidenceValidator
from sentinel_v2.research_loop import ResearchLoop, LoopConfig

console = Console()


class Researcher:
    """The autonomous security researcher.

    This is the entry point. It:
    1. Initializes all components (browser, HTTP, auth, LLM)
    2. Delegates to ResearchLoop for the actual hunting
    3. Provides the cleanup and reporting interface
    """

    def __init__(
        self,
        target_url: str,
        llm_client: Any,
        headless: bool = True,
        proxy: str | None = None,
        rate_limit: float = 1.0,
        max_iterations: int = 50,
        output_dir: str = "hunt_output",
    ):
        self.target_url = target_url
        self.llm = llm_client
        self.max_iterations = max_iterations
        self.output_dir = output_dir

        self._headless = headless
        self._proxy = proxy
        self.browser = None
        self.http = HTTPClient(proxy=proxy, rps=rate_limit)

        target_domain = ""
        try:
            from urllib.parse import urlparse as _parse
            target_domain = _parse(target_url).hostname or ""
        except Exception:
            pass
        self.auth = AuthManager(target_domain=target_domain)

        # Infrastructure
        self.tool_bus = ToolBus()
        self.recon = Recon(self.http, self.tool_bus)
        self.reasoning = ReasoningTrace()
        self.evidence_validator = EvidenceValidator()

        self.memory = Memory(target_url, output_dir)
        self.app_model = ApplicationModel(target_url)

        self._loop: ResearchLoop | None = None

    async def start(self) -> Memory:
        """Begin the autonomous hunt."""
        from sentinel_v2.tools.browser import BrowserTool

        console.print(f"\n[bold green]Starting Sentinel V2 hunt on {self.target_url}[/bold green]\n")

        # Launch browser
        console.print("[cyan]Launching browser...[/cyan]")
        self.browser = BrowserTool(headless=self._headless, proxy=self._proxy)
        await self.browser.launch()
        console.print("[cyan]Browser ready[/cyan]")

        # Create research loop
        config = LoopConfig(
            max_experiments=self.max_iterations,
            self_eval_interval=20,
            rate_limit_delay=1.0,
        )

        self._loop = ResearchLoop(
            target_url=self.target_url,
            llm_complete=self.llm.complete,
            http_client=self.http,
            browser_tool=self.browser,
            auth_manager=self.auth,
            config=config,
        )

        # Run the research loop
        result = await self._loop.run()

        # Save results
        self._loop.app_model.save(f"{self.output_dir}/app_model.json")
        self._loop.memory.save()

        # Print summary
        console.print(f"\n[bold green]Hunt complete![/bold green]")
        console.print(self._loop.app_model.get_summary())

        await self._cleanup()
        return self._loop.memory

    async def _cleanup(self):
        """Cleanup all resources."""
        if self.browser:
            await self.browser.close()
        await self.http.close()
