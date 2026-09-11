"""Researcher — the brain of Demogorgon.

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

from demogorgon.core.config import ResearchConfig
from demogorgon.core.scope_legacy import ScopeValidator
from demogorgon.memory import Memory
from demogorgon.app_model import ApplicationModel
from demogorgon.tools.http_client import HTTPClient
from demogorgon.auth.bridge import AuthManager
from demogorgon.tools.tool_bus import ToolBus
from demogorgon.tools.recon import Recon
from demogorgon.reasoning_trace import ReasoningTrace
from demogorgon.evidence_validator import EvidenceValidator
from demogorgon.research_loop import ResearchLoop, LoopConfig

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
        config: ResearchConfig,
        llm_client: Any,
    ):
        self.config = config
        self.target_url = config.target_url
        self.llm = llm_client
        self.max_iterations = config.max_experiments
        self.output_dir = config.output_dir

        self._headless = config.headless
        self._proxy = config.proxy
        self._rate_limit = config.rate_limit_delay
        self.browser = None
        rps = config.requests_per_second
        self.http = HTTPClient(proxy=config.proxy, rps=rps)

        target_domain = ""
        try:
            from urllib.parse import urlparse as _parse
            target_domain = _parse(self.target_url).hostname or ""
        except Exception:
            pass
        self.auth = AuthManager(target_domain=target_domain)

        # Infrastructure
        self.tool_bus = ToolBus()
        self.recon = Recon(self.http, self.tool_bus)
        self.reasoning = ReasoningTrace()
        self.evidence_validator = EvidenceValidator()

        self.memory = Memory(self.target_url, self.output_dir)
        self.app_model = ApplicationModel(self.target_url)
        self.scope = ScopeValidator(
            self.target_url,
            extra_scopes=config.extra_scopes,
            excluded_hosts=config.excluded_hosts,
        )

        self._loop: ResearchLoop | None = None

    async def start(self) -> Memory:
        """Begin the autonomous hunt."""
        from demogorgon.tools.browser import BrowserTool

        console.print(f"\n[bold green]Starting Demogorgon hunt on {self.target_url}[/bold green]\n")

        # Launch browser
        console.print("[cyan]Launching browser...[/cyan]")
        self.browser = BrowserTool(headless=self._headless, proxy=self._proxy)
        await self.browser.launch()
        console.print("[cyan]Browser ready[/cyan]")

        # Create research loop from canonical config
        config = LoopConfig(
            max_experiments=self.config.max_experiments,
            self_eval_interval=self.config.self_eval_interval,
            rate_limit_delay=self.config.rate_limit_delay,
            stagnation_threshold=self.config.stagnation_threshold,
            max_duplicate_actions=self.config.max_duplicate_actions,
            max_same_endpoint=self.config.max_same_endpoint,
            max_same_vuln_class=self.config.max_same_vuln_class,
            context_window_limit=self.config.context_window_limit,
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
