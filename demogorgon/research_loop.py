"""Research Loop — the core brain of Demogorgon.

Every action follows the cycle:
  Understand → Model → Reason → Experiment → Observe → Adapt → Validate → Report

The LLM decides WHAT to test and WHY.
Deterministic executors decide HOW to test.
No fake intelligence. No random fuzzing. Every decision is explainable.
"""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass, field
from typing import Any

from rich.console import Console

from demogorgon.app_model import (
    ApplicationModel, BusinessObject, AttackOpportunity,
    TrustBoundary, WorkflowStep, ProductType,
)
from demogorgon.memory import Memory, Finding, Hypothesis, Severity
from demogorgon.reasoning_trace import ReasoningTrace
from demogorgon.controller.self_evaluator import SelfEvaluator
from demogorgon.core.metrics import MetricsCollector
from demogorgon.core.cvss import score_finding_cvss
from demogorgon.core.poc import generate_poc_from_finding, render_poc_markdown

console = Console()


# ============================================================
# Research Loop Configuration
# ============================================================

@dataclass
class LoopConfig:
    """Configuration for the research loop."""
    max_experiments: int = 50
    self_eval_interval: int = 20
    stagnation_threshold: int = 5
    max_duplicate_actions: int = 3
    max_same_endpoint: int = 5
    max_same_vuln_class: int = 3
    rate_limit_delay: float = 1.0
    context_window_limit: int = 8000  # chars for LLM context


@dataclass
class ExperimentResult:
    """Result of a single experiment."""
    experiment_id: str
    hypothesis_id: str
    executor: str
    endpoint: str
    method: str
    findings: list[dict[str, Any]]
    evidence: list[dict[str, Any]]
    new_observations: list[dict[str, Any]]
    new_business_objects: list[dict[str, Any]]
    is_finding: bool
    duration: float
    error: str | None = None


@dataclass
class LoopState:
    """Current state of the research loop."""
    experiment_count: int = 0
    finding_count: int = 0
    observation_count: int = 0
    hypothesis_count: int = 0
    duplicate_streak: int = 0
    stagnation_count: int = 0
    strategy: str = "explore"  # explore, validate, exploit, pivot
    start_time: float = field(default_factory=time.time)
    last_finding_at: int = 0
    tested_actions: set[str] = field(default_factory=set)
    failed_hypotheses: set[str] = field(default_factory=set)

    @property
    def should_stop(self) -> bool:
        return False  # Controlled externally

    @property
    def should_self_eval(self) -> bool:
        return (
            self.experiment_count > 0
            and self.experiment_count % 20 == 0
        )

    @property
    def runtime_seconds(self) -> float:
        return time.time() - self.start_time


# ============================================================
# Research Loop
# ============================================================

class ResearchLoop:
    """The core research loop that drives autonomous hunting.

    This is the brain. It:
    1. Builds context from the application model
    2. Asks the LLM what to test next and why
    3. Executes tests deterministically
    4. Observes results and updates the model
    5. Adapts strategy based on progress
    6. Validates findings before reporting
    """

    def __init__(
        self,
        target_url: str,
        llm_complete,  # async callable: (messages, **kwargs) -> str
        http_client,
        browser_tool,
        auth_manager,
        config: LoopConfig | None = None,
        hunt_config: Any | None = None,
        laya: Any | None = None,
        decision_trace: Any | None = None,
        tool_manager: Any | None = None,
    ):
        self.target_url = target_url
        self.llm_complete = llm_complete
        self.http = http_client
        self.browser = browser_tool
        self.auth = auth_manager
        self.config = config or LoopConfig()

        # Core components
        self.app_model = ApplicationModel(target_url)
        self.memory = Memory(target_url)
        self.reasoning = ReasoningTrace()
        self.evaluator = SelfEvaluator()
        self.state = LoopState()

        # DemogorgonConfig (Laya, AI, Safety, Tools) — single source of truth
        from demogorgon.core.config import DemogorgonConfig
        if hunt_config is not None:
            self.hunt_config = hunt_config
        else:
            self.hunt_config = DemogorgonConfig(
                target_url=target_url,
                max_experiments=self.config.max_experiments,
                rate_limit_delay=self.config.rate_limit_delay,
                self_eval_interval=self.config.self_eval_interval,
                stagnation_threshold=self.config.stagnation_threshold,
                max_duplicate_actions=self.config.max_duplicate_actions,
                max_same_endpoint=self.config.max_same_endpoint,
                max_same_vuln_class=self.config.max_same_vuln_class,
                context_window_limit=self.config.context_window_limit,
            )

        # Decision trace + Laya decision engine
        from demogorgon.core.decision_trace import DecisionTrace
        from demogorgon.laya.engine import LayaEngine

        self.decision_trace = decision_trace or DecisionTrace()
        if laya is not None:
            self.laya = laya
        else:
            try:
                from demogorgon.llm.manager import AIProviderManager
                ai_manager = AIProviderManager()
                ai_manager.configure()
                self.laya = LayaEngine(
                    llm_manager=ai_manager,
                    config=self.hunt_config.laya,
                    trace=self.decision_trace,
                )
            except Exception as e:
                console.print(f"[yellow]Laya engine unavailable ({e}) — using deterministic fallbacks[/yellow]")
                self.laya = None

        # Tool manager (structured security tool adapters)
        from demogorgon.tools.manager import create_default_tool_manager
        if tool_manager is not None:
            self.tool_manager = tool_manager
        else:
            self.tool_manager = create_default_tool_manager()

        # V3 controller components
        from demogorgon.controller.executive import ExecutiveController
        from demogorgon.controller.execution_graph import ExecutionGraph
        self.controller = ExecutiveController()
        self.graph = ExecutionGraph()

        # ARE (Adaptive Research Engine) components
        from demogorgon.are.knowledge_base import KnowledgeBase
        from demogorgon.are.mutation_intelligence import MutationIntelligence
        from demogorgon.are.chain_finder import ChainFinder
        from demogorgon.are.trust_boundary import TrustBoundaryMapper
        from demogorgon.are.attack_graph import AttackGraph
        from demogorgon.are.exploit_confidence import ExploitConfidenceEngine
        self.knowledge_base = KnowledgeBase()
        self.mutations = MutationIntelligence()
        self.chain_finder = ChainFinder()
        self.trust_mapper = TrustBoundaryMapper()
        self.attack_graph = AttackGraph()
        self.confidence_engine = ExploitConfidenceEngine()

        # Authcore components for IDOR and role testing
        from demogorgon.auth.authcore import ObjectInventoryDB, CrossUserIDORTester, RoleTester
        self.inventory = ObjectInventoryDB()
        self.idor_tester = CrossUserIDORTester(self.inventory)
        self.role_tester = RoleTester(self.inventory)
        self._idor_discovery_done = False

        # Finding scores — tracks all scored findings for report
        self._finding_scores: list[dict[str, Any]] = []

        # Metrics collector (discovery/testing/findings rates)
        self.metrics = MetricsCollector(target=target_url)

        # Parallel executor (concurrent request batches)
        from demogorgon.tools.parallel import ParallelExecutor
        self.parallel = ParallelExecutor(max_concurrency=10)

        # Canonical scope validator
        from demogorgon.core.scope_legacy import ScopeValidator
        self._scope_validator = ScopeValidator(target_url)

        # Checkpoint for crash recovery
        from demogorgon.tools.checkpoint import Checkpoint
        self.checkpoint = Checkpoint(checkpoint_dir=f".demogorgon/checkpoints/{target_url}")

        # Deterministic executors (lazy loaded)
        self._executors: dict[str, Any] = {}

        # Laya decision bookkeeping
        self._last_decision_id: str = ""
        self._laya_stop_requested: bool = False

    # ============================================================
    # Main Loop
    # ============================================================

    async def run(self) -> dict[str, Any]:
        """Run the full research loop."""
        console.print(f"\n[bold green]Research Loop started on {self.target_url}[/bold green]")
        console.print(f"[cyan]Max experiments: {self.config.max_experiments}[/cyan]")

        # Attempt to restore from checkpoint
        restored = self._load_checkpoint()

        # Initialize ExecutionGraph with a primary goal
        self.graph.add_goal(
            description=f"Find vulnerabilities in {self.target_url}",
            priority=1.0,
        )

        try:
            # Phase 1: Understand & Discover
            await self._phase_understand()

            # Phase 2: Model
            await self._phase_model()

            # Phase 3: Laya Prioritize -> Hypothesize -> Execute -> Observe -> Validate -> Adapt
            await self._phase_reason_experiment_cycle()

            # Final: Chain and Report
            self._save_checkpoint()
            return self._generate_report()

        except KeyboardInterrupt:
            console.print("\n[yellow]Research loop interrupted[/yellow]")
            self._save_checkpoint()
            return self._generate_report()
        except Exception as e:
            console.print(f"\n[red]Research loop error: {e}[/red]")
            return self._generate_report()

    # ============================================================
    # Phase 1: Understand
    # ============================================================

    async def _phase_understand(self):
        """Navigate the target and extract everything we can observe."""
        console.print("\n[bold cyan]Phase 1: Understand[/bold cyan]")
        self.reasoning.begin(
            action="Understand target application",
            reasoning="Before testing anything, I must understand what this application does, who uses it, and where the valuable assets are.",
            hypothesis="Understanding the product will reveal attack surfaces",
            confidence=0.8,
        )

        # Navigate to target
        nav = await self.browser.navigate(self.target_url)
        title = nav.get("title", "unknown")
        console.print(f"[green]Loaded: {title}[/green]")

        await self.browser.screenshot("initial_page")

        # Extract everything from the browser
        content = await self.browser.get_text()
        links = await self.browser.get_all_links()
        forms = await self.browser.get_all_forms()
        tokens = await self.browser.get_tokens()

        # Extract JS endpoints
        js_endpoints = await self.browser.extract_endpoints_from_js()
        api_endpoints = await self.browser.extract_api_from_network_entries()
        form_endpoints = await self.browser.extract_form_endpoints()

        # Extract Next.js data and discover admin paths
        try:
            next_data = await self.browser.extract_next_data()
            if next_data and next_data.get("routes"):
                for route in next_data["routes"]:
                    if route.startswith("http"):
                        full_url = route
                    else:
                        full_url = f"{self.target_url.rstrip('/')}/{route.lstrip('/')}"
                    if self._in_scope(full_url):
                        self.memory.add_endpoint(full_url)
        except Exception:
            pass

        # Discover and parse OpenAPI/Swagger specs
        await self._discover_openapi_specs()

        # Enumerate subdomains (scope-aware) and probe live hosts
        await self._enumerate_subdomains()

        try:
            admin_paths = await self.browser.discover_admin_paths(self.target_url)
            for ap in admin_paths:
                path_url = ap.get("final_url") or f"{self.target_url.rstrip('/')}{ap['path']}"
                if self._in_scope(path_url):
                    self.memory.add_endpoint(path_url)
        except Exception:
            pass

        # Register all discovered endpoints
        for link in links:
            if self._in_scope(link):
                self.memory.add_endpoint(link)

        for form in forms:
            action = form.get("action", "")
            if action and self._in_scope(action):
                self.memory.add_endpoint(action, method=form.get("method", "GET").upper())

        for ep in js_endpoints:
            url = ep.get("url", "")
            if url and self._in_scope(url):
                self.memory.add_endpoint(url, method=ep.get("method", "GET"))

        for ep in api_endpoints:
            url = ep.get("url", "")
            if url and self._in_scope(url):
                self.memory.add_endpoint(url, method=ep.get("method", "GET"))

        for ep in form_endpoints:
            url = ep.get("url", "")
            if url and self._in_scope(url):
                self.memory.add_endpoint(url, method=ep.get("method", "GET"))

        # Capture tokens
        if tokens.cookies:
            self.auth.import_cookies("browser", [
                {"name": k, "value": v, "domain": self.target_url}
                for k, v in tokens.cookies.items()
            ], self.target_url)
            # Apply the imported session to HTTP client for auth injection
            self.auth.apply_active_to_http(self.http)

        # Detect tech stack via KnowledgeBase
        try:
            resp = await self.http.request("GET", self.target_url)
            if not resp.get("error"):
                stack = self.knowledge_base.detect_stack(
                    headers=resp.get("headers", {}),
                    body=resp.get("body", ""),
                    url=self.target_url,
                )
                if stack:
                    self.memory.tech_stack = stack
                    self.app_model.tech_stack = stack
                    console.print(f"[cyan]Detected stack: {', '.join(stack)}[/cyan]")

                    # Get attack plan from KnowledgeBase
                    plan = self.knowledge_base.get_attack_plan(stack)
                    if plan.get("endpoints_to_check"):
                        for ep in plan["endpoints_to_check"]:
                            full_url = f"{self.target_url.rstrip('/')}{ep}"
                            if self._in_scope(full_url):
                                self.memory.add_endpoint(full_url)
                    if plan.get("common_vulns"):
                        console.print(f"[cyan]Common vulns: {', '.join(plan['common_vulns'][:5])}[/cyan]")
        except Exception as e:
            console.print(f"[yellow]Stack detection failed: {e}[/yellow]")

        # Build initial context for LLM
        self._update_app_model_from_observations()

        self.reasoning.complete(
            result=f"Discovered {len(self.memory.endpoints)} endpoints, {len(forms)} forms, {len(tokens.jwt_tokens)} JWT tokens",
            observation=f"Title: {title}, Links: {len(links)}, Forms: {len(forms)}",
        )

        console.print(f"[green]Discovered {len(self.memory.endpoints)} endpoints[/green]")
        console.print(f"[green]Found {len(forms)} forms, {len(tokens.jwt_tokens)} JWT tokens[/green]")

        # Run IDOR object discovery if we have multiple auth sessions
        await self._discover_idor_objects()

    async def _enumerate_subdomains(self):
        """Enumerate subdomains for the target domain and add in-scope live hosts."""
        from urllib.parse import urlparse
        domain = urlparse(self.target_url).hostname or ""
        # Extract registrable-ish base (strip port, take last 2 labels for simple domains)
        if not domain or domain.count(".") < 1:
            return
        # Prefer the rightmost two labels as base domain (example.com)
        parts = domain.split(".")
        base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain

        console.print(f"[cyan]Enumerating subdomains for {base_domain}...[/cyan]")
        try:
            from demogorgon.tools.tool_bus import ToolBus
            from demogorgon.tools.recon import Recon
            bus = ToolBus()
            recon = Recon(self.http, bus)
            result = await recon.discover_subdomains(base_domain)
        except Exception as e:
            console.print(f"[yellow]Subdomain enumeration failed: {e}[/yellow]")
            return

        subs = result.get("subdomains", [])
        self.metrics.metrics.subdomains_discovered = len(subs)
        if not subs:
            console.print("[dim]No subdomains found[/dim]")
            return

        # Scope filter + add as endpoints
        added = 0
        for sub in subs:
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                if self._in_scope(url):
                    self.memory.add_endpoint(url, method="GET")
                    added += 1

        # Probe live hosts in parallel
        if subs:
            probe_urls = []
            for sub in subs[:50]:
                probe_urls.append(f"https://{sub}")
            try:
                batch = await self.parallel.probe_endpoints(
                    self.http, probe_urls, timeout=30.0,
                )
                self.metrics.record_parallel(len(probe_urls))
                live = 0
                for r in batch.results:
                    data = r.get("data") or {}
                    status = data.get("status_code", 0)
                    url = data.get("url") or ""
                    if status and self._in_scope(url):
                        self.memory.add_endpoint(
                            url, method="GET",
                            status_code=status,
                            response_length=len(data.get("body", "")),
                        )
                        live += 1
                self.metrics.metrics.live_hosts = live
                console.print(
                    f"[green]Subdomains: {len(subs)} found, "
                    f"{live} live, {added} endpoints added[/green]"
                )
            except Exception as e:
                console.print(f"[yellow]Live host probe failed: {e}[/yellow]")
        else:
            console.print(f"[green]Subdomains: {len(subs)} found, {added} endpoints added[/green]")

    async def _discover_idor_objects(self):
        """Discover objects for IDOR testing using authcore."""
        if self._idor_discovery_done:
            return
        self._idor_discovery_done = True

        sessions = list(self.auth.sessions.values())
        if len(sessions) < 2:
            return

        console.print(f"[cyan]Running IDOR object discovery with {len(sessions)} sessions...[/cyan]")
        try:
            endpoint_urls = list(self.memory.endpoints.keys())
            for session in sessions[:3]:  # Limit to 3 sessions for discovery
                count = await self.idor_tester.discover_objects(
                    endpoints=endpoint_urls,
                    session=session,
                    max_pages=10,
                )
                if count:
                    console.print(f"[green]Discovered {count} objects via session '{session.label}'[/green]")

            # Report IDOR candidates
            candidates = self.inventory.get_idor_candidates()
            if candidates:
                console.print(f"[bold yellow]Found {len(candidates)} IDOR candidate object types[/bold yellow]")
        except Exception as e:
            console.print(f"[yellow]IDOR discovery failed: {e}[/yellow]")

        # Run ffuf directory fuzzing for additional endpoint discovery
        await self._fuzz_directories()

    async def _fuzz_directories(self):
        """Run ffuf directory fuzzing to discover additional endpoints."""
        try:
            from demogorgon.tools.ffuf_bridge import FfufBridge
            from demogorgon.tools.tool_bus import ToolBus
            bus = ToolBus()
            if not bus.is_available("ffuf"):
                return

            ffuf = FfufBridge(bus)
            console.print("[cyan]Running directory fuzzing...[/cyan]")
            result = await ffuf.fuzz_directories(
                self.target_url,
                wordlist="/usr/share/wordlists/dirb/common.txt",
                extensions="php,html,js,txt,bak,old,zip",
                threads=30,
                timeout=120,
            )

            if result.get("error"):
                console.print(f"[yellow]Fuzzing error: {result['error']}[/yellow]")
                return

            discovered = 0
            for f in result.get("findings", []):
                url = f.get("url", "")
                if url and self._in_scope(url):
                    self.memory.add_endpoint(
                        url,
                        method="GET",
                        status_code=f.get("status", 0),
                        response_length=f.get("length", 0),
                    )
                    discovered += 1

            if discovered:
                console.print(f"[green]Fuzzing discovered {discovered} additional endpoints[/green]")
        except Exception as e:
            console.print(f"[yellow]Fuzzing skipped: {e}[/yellow]")

    async def _discover_openapi_specs(self):
        """Discover and parse OpenAPI/Swagger specs from common URLs."""
        import json as json_mod

        spec_paths = [
            "/swagger.json", "/swagger/v1/swagger.json",
            "/openapi.json", "/openapi/v1.json",
            "/api-docs", "/api/docs", "/api/swagger.json",
            "/v1/swagger.json", "/v2/swagger.json", "/v3/swagger.json",
            "/v1/openapi.json", "/v2/openapi.json", "/v3/openapi.json",
            "/docs/openapi.json", "/api/openapi.json",
            "/swagger-ui.json", "/swagger-docs",
        ]

        console.print("[cyan]Checking for OpenAPI/Swagger specs...[/cyan]")
        found_spec = None
        for path in spec_paths:
            url = f"{self.target_url.rstrip('/')}{path}"
            try:
                resp = await self.http.request("GET", url)
                if resp.get("status_code") == 200 and not resp.get("error"):
                    body = resp.get("body", "")
                    # Validate it looks like JSON
                    if body.strip().startswith(("{", "[")):
                        try:
                            spec = json_mod.loads(body)
                            # Check for OpenAPI/Swagger version fields
                            if spec.get("openapi") or spec.get("swagger"):
                                found_spec = spec
                                console.print(f"[green]Found OpenAPI spec at {path}[/green]")
                                break
                        except json_mod.JSONDecodeError:
                            continue
            except Exception:
                continue

        if not found_spec:
            # Try extracting from page source
            try:
                page_content = await self.browser.get_content()
                for marker in ["swagger.json", "openapi.json", "api-docs"]:
                    import re
                    matches = re.findall(rf'["\']([^"\']*{marker}[^"\']*)["\']', page_content, re.I)
                    for match in matches:
                        if match.startswith("http"):
                            spec_url = match
                        else:
                            spec_url = f"{self.target_url.rstrip('/')}{match}"
                        try:
                            resp = await self.http.request("GET", spec_url)
                            if resp.get("status_code") == 200:
                                spec = json_mod.loads(resp.get("body", ""))
                                if spec.get("openapi") or spec.get("swagger"):
                                    found_spec = spec
                                    console.print(f"[green]Found OpenAPI spec from page source: {match}[/green]")
                                    break
                        except Exception:
                            continue
                    if found_spec:
                        break
            except Exception:
                pass

        if not found_spec:
            return

        # Parse endpoints from spec
        base_path = found_spec.get("basePath", "")
        paths = found_spec.get("paths", {})
        endpoints_found = 0

        for path, methods in paths.items():
            full_path = f"{base_path}{path}"
            for method in methods:
                if method.lower() in ("get", "post", "put", "delete", "patch", "options", "head"):
                    full_url = f"{self.target_url.rstrip('/')}{full_path}"
                    if self._in_scope(full_url):
                        # Extract parameters for IDOR testing
                        params = methods[method].get("parameters", [])
                        param_names = [p.get("name") for p in params if p.get("in") in ("path", "query")]

                        self.memory.add_endpoint(
                            full_url,
                            method=method.upper(),
                        )
                        endpoints_found += 1

                        # Store parameter info for IDOR testing
                        if param_names:
                            ep = self.memory.endpoints.get(full_url)
                            if ep:
                                ep.params = {p: "" for p in param_names}

        if endpoints_found:
            console.print(f"[green]OpenAPI spec yielded {endpoints_found} endpoints[/green]")

    # ============================================================
    # Phase 2: Model
    # ============================================================

    async def _phase_model(self):
        """Build the application model using LLM reasoning."""
        console.print("\n[bold cyan]Phase 2: Model[/bold cyan]")

        # Step 1: Product Understanding
        await self._model_product_understanding()

        # Step 2: Business Object Discovery
        await self._model_business_objects()

        # Step 3: Workflow Reconstruction
        await self._model_workflows()

        # Step 4: Trust Boundary Mapping
        await self._model_trust_boundaries()

        # Step 5: Attack Opportunity Generation
        await self._model_attack_opportunities()

        console.print(f"[green]Model confidence: {self.app_model.confidence:.0%}[/green]")
        console.print(self.app_model.get_summary())

    async def _model_product_understanding(self):
        """Use LLM to understand what this application is."""
        context = self._build_understand_context()

        prompt = """You are an elite HackerOne security researcher analyzing a web application.

TASK: Understand this application deeply before testing.

ANALYZE:
1. What is this app? What problem does it solve?
2. Who are the users? What roles exist?
3. What is the business model? How does money flow?
4. What tech stack is used?
5. What are the valuable assets an attacker would want?

RESPOND WITH VALID JSON:
{
    "product_type": "ecommerce|banking|marketplace|saas|social|healthcare|government|ai_platform|education|gaming|unknown",
    "product_description": "one sentence describing what this app does",
    "user_roles": [
        {"name": "role_name", "level": 0-5, "permissions": ["perm1"], "description": "what this role can do"}
    ],
    "ownership_model": "who owns what",
    "monetization_model": "how money flows",
    "tech_stack": ["specific technologies"],
    "api_style": "REST|GraphQL|gRPC|mixed|unknown",
    "observations": [
        {"description": "specific observation", "category": "tech|workflow|business|security"}
    ]
}

ROLE LEVELS: 0=guest, 1=user, 2=premium, 3=seller, 4=admin, 5=superadmin
"""

        result = await self._llm_reason(prompt, context)
        if not result:
            return

        try:
            data = json.loads(result) if isinstance(result, str) else result
            self.app_model.product_type = ProductType(data.get("product_type", "unknown"))
            self.app_model.product_description = data.get("product_description", "")
            self.app_model.ownership_model = data.get("ownership_model", "")
            self.app_model.monetization_model = data.get("monetization_model", "")
            self.app_model.tech_stack = data.get("tech_stack", [])
            self.app_model.api_style = data.get("api_style", "unknown")

            for role_data in data.get("user_roles", []):
                from demogorgon.app_model import UserRole
                self.app_model.user_roles.append(UserRole(
                    name=role_data.get("name", "unknown"),
                    level=role_data.get("level", 1),
                    permissions=role_data.get("permissions", []),
                    description=role_data.get("description", ""),
                ))

            for obs in data.get("observations", []):
                self.app_model.add_observation(obs)

            console.print(f"[green]Product: {self.app_model.product_type.value} - {self.app_model.product_description}[/green]")
        except (json.JSONDecodeError, KeyError) as e:
            console.print(f"[yellow]Could not parse product understanding: {e}[/yellow]")

    async def _model_business_objects(self):
        """Use LLM to extract business objects from API responses."""
        # Visit key pages to capture API responses
        pages_to_visit = [
            self.target_url,
            f"{self.target_url}/api/v1",
            f"{self.target_url}/dashboard",
            f"{self.target_url}/profile",
        ]

        api_responses = []
        for page_url in pages_to_visit:
            try:
                result = await self.browser.navigate(page_url)
                if result.get("navigation_status") == "success":
                    api_endpoints = self.browser.get_api_endpoints()
                    for ep in api_endpoints[:5]:
                        if ep["url"] not in [r.get("url") for r in api_responses]:
                            resp = await self.http.request("GET", ep["url"])
                            api_responses.append({
                                "url": ep["url"],
                                "status": resp["status_code"],
                                "body": resp["body"][:3000],
                            })
            except Exception:
                pass

        if not api_responses:
            return

        context = f"API Responses:\n{json.dumps(api_responses[:5], indent=2)[:5000]}"

        prompt = """Extract every business object from these API responses.

A business object is any entity the application manages: users, products, orders, payments, messages, files, teams, etc.

For each object identify: type, identifier, owner, visibility, parent/child relationships.

RESPOND WITH VALID JSON:
{
    "business_objects": [
        {"object_type": "type", "identifier": "id", "owner": "owner_id", "visibility": "public|private", "endpoint": "where found"}
    ],
    "relationships": [
        {"from": "type1", "to": "type2", "relationship": "owns|contains|belongs_to"}
    ],
    "observations": [
        {"description": "what you noticed", "category": "business|data|auth"}
    ]
}
"""

        result = await self._llm_reason(prompt, context)
        if not result:
            return

        try:
            data = json.loads(result) if isinstance(result, str) else result
            for obj_data in data.get("business_objects", []):
                self.app_model.add_business_object(BusinessObject(
                    object_type=obj_data.get("object_type", "unknown"),
                    identifier=obj_data.get("identifier", ""),
                    owner=obj_data.get("owner"),
                    visibility=obj_data.get("visibility", "private"),
                    parent_objects=obj_data.get("parent_objects", []),
                    child_objects=obj_data.get("child_objects", []),
                    properties=obj_data.get("properties", {}),
                    endpoint=obj_data.get("endpoint", ""),
                ))

            for obs in data.get("observations", []):
                self.app_model.add_observation(obs)

            console.print(f"[green]Discovered {len(self.app_model.business_objects)} business objects[/green]")
        except (json.JSONDecodeError, KeyError) as e:
            console.print(f"[yellow]Could not parse business objects: {e}[/yellow]")

    async def _model_workflows(self):
        """Use LLM to reconstruct user workflows."""
        context = f"""
Product: {self.app_model.product_type.value}
Roles: {[r.name for r in self.app_model.user_roles]}
Objects: {[o.object_type for o in self.app_model.business_objects]}
Endpoints: {[e.url for e in list(self.memory.endpoints.values())[:20]]}
"""

        prompt = """Map the user workflows through this application.

A workflow is a sequence of steps a user takes to accomplish a goal.
Examples: Registration, Login, Purchase, Invitation, Admin management.

For each workflow list steps in order with: endpoint, method, auth required, role required, objects produced/consumed.

RESPOND WITH VALID JSON:
{
    "workflows": [
        {
            "name": "workflow_name",
            "steps": [
                {"name": "step", "endpoint": "url", "method": "GET|POST", "requires_auth": true, "produces_objects": ["type"], "consumes_objects": ["type"]}
            ],
            "attack_points": ["where this workflow can be attacked"]
        }
    ],
    "observations": [{"description": "what you noticed", "category": "workflow|auth|state"}]
}
"""

        result = await self._llm_reason(prompt, context)
        if not result:
            return

        try:
            data = json.loads(result) if isinstance(result, str) else result
            for wf_data in data.get("workflows", []):
                steps = []
                for step_data in wf_data.get("steps", []):
                    steps.append(WorkflowStep(
                        name=step_data.get("name", "unknown"),
                        endpoint=step_data.get("endpoint", ""),
                        method=step_data.get("method", "GET"),
                        requires_auth=step_data.get("requires_auth", False),
                        requires_role=step_data.get("requires_role"),
                        produces_objects=step_data.get("produces_objects", []),
                        consumes_objects=step_data.get("consumes_objects", []),
                        description=step_data.get("description", ""),
                    ))
                self.app_model.add_workflow(wf_data.get("name", "unknown"), steps)

            for obs in data.get("observations", []):
                self.app_model.add_observation(obs)

            console.print(f"[green]Discovered {len(self.app_model.workflows)} workflows[/green]")
        except (json.JSONDecodeError, KeyError) as e:
            console.print(f"[yellow]Could not parse workflows: {e}[/yellow]")

    async def _model_trust_boundaries(self):
        """Use LLM to map trust boundaries."""
        context = f"""
Product: {self.app_model.product_type.value}
Roles: {[(r.name, r.level) for r in self.app_model.user_roles]}
Objects: {[o.object_type for o in self.app_model.business_objects]}
Workflows: {list(self.app_model.workflows.keys())}
Ownership: {self.app_model.ownership_model}
"""

        prompt = """Map every trust boundary in this application.

A trust boundary is a point where authorization is checked.
Examples: guest->user (login), user->admin (role), org A->org B (tenant).

RESPOND WITH VALID JSON:
{
    "trust_boundaries": [
        {"name": "name", "from_level": "lower", "to_level": "higher", "boundary_type": "auth|role|org|workspace", "endpoint": "where enforced"}
    ],
    "observations": [{"description": "what you noticed", "category": "auth|trust|boundary"}]
}
"""

        result = await self._llm_reason(prompt, context)
        if not result:
            return

        try:
            data = json.loads(result) if isinstance(result, str) else result
            for b_data in data.get("trust_boundaries", []):
                self.app_model.add_trust_boundary(TrustBoundary(
                    name=b_data.get("name", "unknown"),
                    from_level=b_data.get("from_level", ""),
                    to_level=b_data.get("to_level", ""),
                    boundary_type=b_data.get("boundary_type", ""),
                    endpoint=b_data.get("endpoint", ""),
                    description=b_data.get("description", ""),
                ))

            for obs in data.get("observations", []):
                self.app_model.add_observation(obs)

            console.print(f"[green]Discovered {len(self.app_model.trust_boundaries)} trust boundaries[/green]")
        except (json.JSONDecodeError, KeyError) as e:
            console.print(f"[yellow]Could not parse trust boundaries: {e}[/yellow]")

    async def _model_attack_opportunities(self):
        """Use LLM to generate specific attack opportunities."""
        context = self.app_model.get_summary()

        prompt = """Generate SPECIFIC attack opportunities based on this application model.

CRITICAL: Never generate vague hypotheses like "maybe IDOR exists". Be SPECIFIC.

For each opportunity:
1. Identify a specific endpoint with a specific parameter
2. Explain the ownership model
3. Provide the EXACT request to try
4. Explain what response indicates success

RESPOND WITH VALID JSON:
{
    "attack_opportunities": [
        {
            "description": "SPECIFIC attack - exactly what to try",
            "vuln_class": "IDOR|auth_bypass|race_condition|privilege_escalation|information_disclosure|cors|jwt|xss|sqli|ssrf|csrf",
            "endpoint": "EXACT endpoint to test",
            "method": "GET|POST|PUT|DELETE",
            "confidence": 0.0-1.0,
            "reasoning": "WHY this specific endpoint is vulnerable based on evidence",
            "test_plan": ["EXACT step 1", "EXACT step 2", "EXACT step 3"]
        }
    ]
}
"""

        result = await self._llm_reason(prompt, context)
        if not result:
            return

        try:
            data = json.loads(result) if isinstance(result, str) else result
            for opp_data in data.get("attack_opportunities", []):
                self.app_model.add_attack_opportunity(AttackOpportunity(
                    description=opp_data.get("description", ""),
                    vuln_class=opp_data.get("vuln_class", "unknown"),
                    endpoint=opp_data.get("endpoint", ""),
                    method=opp_data.get("method", "GET"),
                    confidence=opp_data.get("confidence", 0.5),
                    reasoning=opp_data.get("reasoning", ""),
                    test_plan=opp_data.get("test_plan", []),
                ))

            console.print(f"[green]Generated {len(self.app_model.attack_opportunities)} attack opportunities[/green]")
            for opp in self.app_model.attack_opportunities[:5]:
                console.print(f"  [{opp.confidence:.0%}] {opp.description}")
        except (json.JSONDecodeError, KeyError) as e:
            console.print(f"[yellow]Could not parse attack opportunities: {e}[/yellow]")

    # ============================================================
    # Phase 3-N: Reason → Experiment → Observe → Adapt
    # ============================================================

    async def _phase_reason_experiment_cycle(self):
        """The core loop: Laya prioritize → reason → experiment → observe → adapt."""
        console.print("\n[bold cyan]Phase 3: Laya Prioritize → Hypothesize → Execute → Observe → Validate → Adapt[/bold cyan]")

        # Discover available tool adapters once (wires ToolManager into the loop)
        if self.tool_manager and self.tool_manager._adapters:
            try:
                discovered = await self.tool_manager.discover_all()
                available = [n for n, ok in discovered.items() if ok]
                if available:
                    console.print(f"[dim]ToolManager ready: {', '.join(available)}[/dim]")
            except Exception as e:
                console.print(f"[yellow]ToolManager discovery failed: {e}[/yellow]")

        while self.state.experiment_count < self.config.max_experiments:
            # Self-evaluate every 20 experiments
            if self.state.should_self_eval:
                self._self_evaluate()

            # Checkpoint every 10 experiments
            if self.state.experiment_count > 0 and self.state.experiment_count % 10 == 0:
                self._save_checkpoint()

            # Check stagnation
            if self.state.stagnation_count >= self.config.stagnation_threshold:
                console.print("[yellow]Stagnation detected — pivoting strategy[/yellow]")
                self.state.strategy = "pivot"
                self.state.stagnation_count = 0

            # Laya: fast structured decision (strategy / continue / stop)
            if not await self._laya_prioritize_step():
                console.print("[yellow]Laya requested stop — ending research cycle[/yellow]")
                break

            # Reason: what should I test next?
            console.print(f"\n[bold blue]=== Experiment {self.state.experiment_count + 1}/{self.config.max_experiments} ===[/bold blue]")
            console.print(f"[dim]Strategy: {self.state.strategy} | Findings: {self.state.finding_count} | Tested: {len(self.state.tested_actions)}[/dim]")

            hypothesis = await self._reason_next_action()
            if not hypothesis:
                console.print("[yellow]No more hypotheses to test[/yellow]")
                break

            # Experiment: execute the test
            result = await self._experiment(hypothesis)

            # Observe: update model with new observations
            self._observe(result)

            # Adapt: update strategy based on results
            self._adapt(result)

            # Laya: triage any new findings from this experiment
            await self._laya_triage_findings(result)

            # Close the loop on the decision that selected this experiment
            self._close_decision_trace(result)

            # Rate limit protection
            await asyncio.sleep(self.config.rate_limit_delay)

    async def _laya_prioritize_step(self) -> bool:
        """Run Laya strategy + continue/stop decisions.

        Returns False if the loop should stop.
        """
        if self.laya is None:
            return True
        if not getattr(self.hunt_config, "laya", None) or not self.hunt_config.laya.enabled:
            return True

        context = {
            "endpoints": len(self.memory.endpoints),
            "tested_actions": len(self.state.tested_actions),
            "findings": self.state.finding_count,
            "experiments": self.state.experiment_count,
            "max_experiments": self.config.max_experiments,
            "current_strategy": self.state.strategy,
            "stagnation": self.state.stagnation_count,
            "duplicate_streak": self.state.duplicate_streak,
            "failed_hypotheses": len(self.state.failed_hypotheses),
            "runtime_seconds": self.state.runtime_seconds,
        }

        try:
            strategy_decision = await self.laya.select_strategy(
                context, state_version=self.state.experiment_count
            )
            self._last_decision_id = strategy_decision.get("decision_id", "")
            selected = strategy_decision.get("selected", self.state.strategy)

            # Map Laya strategy vocabulary → LoopState strategy
            strategy_map = {
                "recon": "explore",
                "explore": "explore",
                "focused": "validate",
                "validate": "validate",
                "chain": "exploit",
                "pivot": "pivot",
                "stop": "stop",
            }
            mapped = strategy_map.get(selected, self.state.strategy)
            if mapped != "stop" and mapped != self.state.strategy:
                console.print(
                    f"[magenta]Laya strategy → {mapped} "
                    f"(conf={strategy_decision.get('confidence', 0):.0%}, "
                    f"src={strategy_decision.get('source')})[/magenta]"
                )
                self.state.strategy = mapped
            if selected == "stop" or mapped == "stop":
                return False

            # Periodic continue/stop check (every experiment after the first)
            if self.state.experiment_count > 0:
                stop_decision = await self.laya.continue_or_stop(
                    context, state_version=self.state.experiment_count
                )
                if stop_decision.get("selected") == "stop":
                    return False
                if stop_decision.get("selected") == "pause":
                    console.print("[yellow]Laya requested pause[/yellow]")
                    return False

            # Prioritize next target when we have candidates
            if len(self.memory.endpoints) >= 2:
                candidates = [
                    {"id": ep, "url": ep}
                    for ep in list(self.memory.endpoints)[:20]
                    if ep not in self.state.tested_actions
                ][:10]
                if candidates:
                    target_decision = await self.laya.prioritize_target(
                        candidates, state_version=self.state.experiment_count
                    )
                    preferred = target_decision.get("selected")
                    if preferred:
                        console.print(
                            f"[magenta]Laya preferred target: {preferred} "
                            f"(conf={target_decision.get('confidence', 0):.0%})[/magenta]"
                        )

            return True
        except Exception as e:
            console.print(f"[yellow]Laya prioritize step failed: {e}[/yellow]")
            return True

    async def _laya_triage_findings(self, result: Any) -> None:
        """Triage findings produced by an experiment via Laya."""
        if self.laya is None or not getattr(result, "findings", None):
            return
        if not getattr(self.hunt_config, "laya", None) or not self.hunt_config.laya.enabled:
            return

        for finding in result.findings[:3]:
            try:
                triage = await self.laya.triage_finding(
                    finding, state_version=self.state.experiment_count
                )
                action = triage.get("selected", "validate")
                if action == "ignore":
                    console.print(f"[dim]Laya triage: ignore {finding.get('title', '')}[/dim]")
                elif action in ("escalate", "report_candidate"):
                    console.print(
                        f"[red]Laya triage: {action} — {finding.get('title', '')} "
                        f"(conf={triage.get('confidence', 0):.0%})[/red]"
                    )
            except Exception as e:
                console.print(f"[yellow]Laya triage failed: {e}[/yellow]")
                break

    def _close_decision_trace(self, result: Any) -> None:
        """Attach experiment outcome to the last Laya decision."""
        if not self._last_decision_id or not self.decision_trace:
            return
        try:
            findings = getattr(result, "findings", []) or []
            error = getattr(result, "error", None)
            outcome = "finding" if findings else ("error" if error else "no_finding")
            self.decision_trace.update_result(
                self._last_decision_id,
                tool_executed=getattr(result, "executor", ""),
                result=(f"{len(findings)} finding(s)" if findings else (error or "ok")),
                outcome=outcome,
            )
        except Exception:
            pass
        self._last_decision_id = ""

    async def _reason_next_action(self) -> dict[str, Any] | None:
        """Ask the LLM what to test next."""
        context = self._build_reasoning_context()

        prompt = f"""You are an elite HackerOne security researcher testing a hypothesis.

CURRENT STATE:
- Strategy: {self.state.strategy}
- Experiments run: {self.state.experiment_count}
- Findings: {self.state.finding_count}
- Failed hypotheses: {len(self.state.failed_hypotheses)}

CRITICAL RULES:
1. NEVER test the same endpoint with the same parameters twice
2. NEVER generate the same hypothesis twice
3. NEVER use generic language like "maybe IDOR exists" — be specific
4. ALWAYS explain your reasoning before acting
5. If something failed, MOVE ON to a different approach
6. NEVER use browser for navigation — use HTTP tool for API testing

TOOL SELECTION:
- "http" — test API endpoints (GET, POST, PUT, DELETE)
- "replay" — replay captured requests with mutations
- "browser" — ONLY for JS evaluation, form filling, or clicking

WHAT TO TEST NEXT:
1. Look at what you've already tested
2. Look at untested endpoints and attack opportunities
3. Look at business objects and their ownership
4. Pick the MOST LIKELY vulnerability based on evidence
5. Test it SPECIFICALLY

RESPOND WITH VALID JSON:
{{
    "reasoning": "THINK OUT LOUD: What am I testing? Why? What evidence supports this?",
    "hypothesis": "EXACT hypothesis with specific endpoint",
    "vuln_class": "class",
    "endpoint": "EXACT endpoint to test",
    "method": "GET|POST|PUT|DELETE",
    "confidence": 0.0-1.0,
    "action": {{
        "tool": "http|replay|browser",
        "method": "GET|POST|PUT|DELETE",
        "url": "EXACT url",
        "headers": {{}},
        "body": "request body or null",
        "reason": "WHY this tests my hypothesis"
    }},
    "evidence_for": ["evidence supporting this"],
    "evidence_against": ["evidence against this"],
    "new_observations": [{{"description": "what I learned", "category": "tech|workflow|auth|data"}}],
    "new_business_objects": [{{"object_type": "type", "identifier": "id", "owner": "owner"}}],
    "status": "continue|done"
}}
"""

        result = await self._llm_reason(prompt, context)
        if not result:
            return None

        try:
            data = json.loads(result) if isinstance(result, str) else result
        except json.JSONDecodeError:
            console.print("[yellow]Could not parse LLM response as JSON[/yellow]")
            return None

        # Check for duplicates
        action = data.get("action", {})
        action_key = f"{action.get('tool', '')} {action.get('method', '')} {action.get('url', '')}"
        if action_key in self.state.tested_actions:
            self.state.duplicate_streak += 1
            console.print(f"[yellow]Duplicate action ({self.state.duplicate_streak} in a row)[/yellow]")
            if self.state.duplicate_streak >= self.config.max_duplicate_actions:
                self.state.failed_hypotheses.add(data.get("hypothesis", ""))
                self.state.duplicate_streak = 0
            return None
        else:
            self.state.duplicate_streak = 0

        # Register hypothesis with ExecutiveController
        self.controller.create_hypothesis(
            description=data.get("hypothesis", ""),
            vuln_class=data.get("vuln_class", "unknown"),
            endpoint=data.get("endpoint", ""),
            confidence=data.get("confidence", 0.5),
            test_plan=data.get("reasoning", ""),
        )

        # Register in ExecutionGraph if we have a current goal
        if self.graph._current_goal:
            self.graph.add_hypothesis(
                goal_id=self.graph._current_goal,
                description=data.get("hypothesis", ""),
                vuln_class=data.get("vuln_class", "unknown"),
                endpoint=data.get("endpoint", ""),
                confidence=data.get("confidence", 0.5),
                test_plan=data.get("reasoning", ""),
            )

        return data

    async def _experiment(self, hypothesis: dict[str, Any]) -> ExperimentResult:
        """Execute a single experiment."""
        self.state.experiment_count += 1
        start_time = time.time()

        action = hypothesis.get("action", {})
        tool = action.get("tool", "http")
        hypothesis_text = hypothesis.get("hypothesis", "unknown")
        vuln_class = hypothesis.get("vuln_class", "unknown")
        endpoint = action.get("url", hypothesis.get("endpoint", ""))

        console.print(f"[cyan]Hypothesis: {hypothesis_text[:100]}[/cyan]")
        console.print(f"[cyan]Tool: {tool} | Endpoint: {endpoint}[/cyan]")

        self.reasoning.begin(
            action=f"Testing: {hypothesis_text[:100]}",
            reasoning=hypothesis.get("reasoning", "No reasoning"),
            hypothesis=hypothesis_text,
            confidence=hypothesis.get("confidence", 0.5),
        )

        findings = []
        evidence_list = []
        new_observations = []
        new_business_objects = []
        error = None

        try:
            if tool == "http":
                result = await self._execute_http(action)
            elif tool == "replay":
                result = await self._execute_replay(action)
            elif tool == "browser":
                result = await self._execute_browser(action)
            elif self.tool_manager and self.tool_manager.get_adapter(tool):
                result = await self._execute_tool_manager(tool, action, vuln_class)
            else:
                result = {"error": f"Unknown tool: {tool}"}

            if result.get("error"):
                error = result["error"]
            else:
                # Extract findings from result
                if result.get("findings"):
                    findings = result["findings"]
                if result.get("evidence"):
                    evidence_list = result["evidence"]
                new_observations = hypothesis.get("new_observations", [])
                new_business_objects = hypothesis.get("new_business_objects", [])

                # Store evidence
                self.memory.add_evidence(
                    method=action.get("method", "GET"),
                    url=endpoint,
                    request_headers=action.get("headers", {}),
                    request_body=action.get("body"),
                    response_status=result.get("status_code", 0),
                    response_headers=result.get("headers", {}),
                    response_body=result.get("body", "")[:10000],
                )

        except Exception as e:
            error = str(e)
            console.print(f"[red]Experiment error: {error}[/red]")

        # Run authcore IDOR/role testing for relevant vuln classes
        if not error and vuln_class in ("idor", "access_control", "privilege_escalation", "role_bypass"):
            authcore_findings = await self._run_authcore_testing(endpoint, action, vuln_class)
            findings.extend(authcore_findings)

        # Run deterministic executors for SSRF / file upload / other classes
        if not error:
            exec_findings = await self._run_deterministic_executor(vuln_class, endpoint, action)
            findings.extend(exec_findings)

        # Track metrics
        self.metrics.metrics.experiments_run = self.state.experiment_count
        if vuln_class and vuln_class != "unknown":
            self.metrics.metrics.vuln_classes_tested.add(vuln_class)
        self.metrics.metrics.unique_actions_tested = len(self.state.tested_actions)
        self.metrics.metrics.endpoints_discovered = len(self.memory.endpoints)
        self.metrics.metrics.requests_made += 1
        if tool and tool not in ("http", "replay", "browser"):
            self.metrics.record_tool(tool)

        # Track tested action
        action_key = f"{tool} {action.get('method', 'GET')} {endpoint}"
        self.state.tested_actions.add(action_key)
        self.memory.mark_tested(endpoint, action.get("method", "GET"))

        # Record with ExecutiveController
        if self.controller.hypotheses:
            last_hyp_id = list(self.controller.hypotheses.keys())[-1]
            exp = self.controller.select_experiment()
            if exp:
                self.controller.record_experiment_result(
                    exp.id,
                    result={"findings": findings, "error": error},
                    finding=findings[0] if findings else None,
                )

        # Record in ExecutionGraph
        if self.graph._current_goal:
            # Find the latest hypothesis node for this goal
            hyp_nodes = [
                n for n in self.graph.nodes.values()
                if n.node_type.value == "hypothesis"
                and n.parent_id == self.graph._current_goal
                and n.status.value == "pending"
            ]
            if hyp_nodes:
                hyp_node = hyp_nodes[-1]
                self.graph.complete_node(hyp_node.id)

                # Add experiment node
                exp_node = self.graph.add_experiment(
                    hypothesis_id=hyp_node.id,
                    executor=tool,
                    target=endpoint,
                )
                self.graph.complete_node(exp_node.id)

                # Add evidence node
                ev_node = self.graph.add_evidence(
                    experiment_id=exp_node.id,
                    result={"status": "error" if error else "ok", "findings_count": len(findings)},
                    is_finding=len(findings) > 0,
                )
                self.graph.complete_node(ev_node.id)

                # Add finding node if applicable
                if findings:
                    for f in findings:
                        self.graph.add_finding(
                            evidence_id=ev_node.id,
                            title=f.get("title", "Unknown"),
                            severity=f.get("severity", "info"),
                            vuln_class=vuln_class,
                            endpoint=endpoint,
                            evidence=f.get("evidence", []),
                        )

        # Record reasoning
        self.reasoning.complete(
            result=f"Findings: {len(findings)}, Error: {error or 'none'}",
            observation=str(findings)[:200] if findings else "No findings",
        )

        duration = time.time() - start_time

        return ExperimentResult(
            experiment_id=f"E{self.state.experiment_count:04d}",
            hypothesis_id=f"H{self.state.experiment_count:04d}",
            executor=tool,
            endpoint=endpoint,
            method=action.get("method", "GET"),
            findings=findings,
            evidence=evidence_list,
            new_observations=new_observations,
            new_business_objects=new_business_objects,
            is_finding=len(findings) > 0,
            duration=duration,
            error=error,
        )

    def _score_finding(
        self,
        finding: dict[str, Any],
        response_status: int = 0,
        response_changed: bool = False,
    ) -> dict[str, Any]:
        """Score a finding through the ExploitConfidenceEngine.

        Returns the finding dict augmented with score fields and
        appends the score to self._finding_scores.
        """
        score = self.confidence_engine.score_finding(
            finding_id=finding.get("id", f"finding_{len(self._finding_scores)}"),
            title=finding.get("title", "Unknown Finding"),
            severity=finding.get("severity", "info"),
            vuln_class=finding.get("type", finding.get("vuln_class", "unknown")),
            endpoint=finding.get("endpoint", "unknown"),
            evidence=finding.get("evidence", []),
            response_status=response_status,
            response_changed=response_changed,
            has_screenshot=bool(finding.get("screenshot")),
            has_request_response=bool(finding.get("request") and finding.get("response")),
            business_context=finding.get("business_context", ""),
        )

        finding["confidence"] = score.final_confidence
        finding["should_report"] = score.should_report
        finding["score_reasoning"] = score.reasoning

        self._finding_scores.append(score.to_dict())
        return finding

    async def _run_deterministic_executor(
        self, vuln_class: str, endpoint: str, action: dict,
    ) -> list[dict[str, Any]]:
        """Load and run the deterministic executor for a vuln class (SSRF, upload, etc.)."""
        if not vuln_class or vuln_class == "unknown":
            return []
        # Alias mapping so LLM can say "ssrf" or "file_upload" etc.
        aliases = {
            "ssrf": "ssrf_tester",
            "file_upload": "upload_tester",
            "unrestricted_upload": "upload_tester",
            "path_traversal_upload": "upload_tester",
        }
        executor_name = aliases.get(vuln_class)
        if not executor_name:
            from demogorgon.controller.tool_selection import get_executor_spec
            spec = get_executor_spec(vuln_class)
            if not spec:
                return []
            executor_name = spec.name

        from demogorgon.controller.tool_selection import get_executor_by_name
        spec = get_executor_by_name(executor_name)
        if not spec:
            return []

        try:
            import importlib
            mod = importlib.import_module(spec.module_path)
            cls = getattr(mod, spec.class_name)
            executor = cls()
        except Exception as e:
            console.print(f"[yellow]Executor load failed ({executor_name}): {e}[/yellow]")
            return []

        # Detect param for SSRF from action / URL query
        param_name = action.get("parameter") or action.get("param") or "url"
        if vuln_class == "ssrf":
            from urllib.parse import urlparse, parse_qs
            qs = parse_qs(urlparse(endpoint).query)
            if qs:
                param_name = next(iter(qs.keys()))

        console.print(f"[cyan]Running executor {executor.name} on {endpoint}...[/cyan]")
        try:
            result = await executor.test(
                endpoint,
                http_client=self.http,
                headers=action.get("headers", {}),
                param_name=param_name,
            )
        except Exception as e:
            console.print(f"[yellow]Executor {executor.name} failed: {e}[/yellow]")
            return []

        findings = result.get("findings", [])
        for f in findings:
            # Normalize type key used by detectors
            if "type" not in f:
                f["type"] = f.get("vuln_class", vuln_class)
            if "method" not in f:
                f["method"] = action.get("method", "GET")
            self.metrics.record_finding(
                f.get("severity", "info"), f.get("vuln_class", vuln_class),
                f.get("confidence", 0),
            )
            # Persist into memory
            self.memory.add_finding(
                title=f.get("title", "Finding"),
                severity=f.get("severity", "info"),
                vuln_class=f.get("vuln_class", vuln_class),
                endpoint=f.get("endpoint", endpoint),
                method=f.get("method", action.get("method", "GET")),
                evidence=f.get("evidence", ""),
                reproduction=f.get("steps", []) if isinstance(f.get("steps"), list) else [],
                impact=f.get("impact", ""),
                confidence=f.get("confidence", 0.5),
            )
        if findings:
            console.print(f"[bold red]Executor {executor.name}: {len(findings)} finding(s)[/bold red]")
        return findings

    async def _execute_http(self, action: dict) -> dict[str, Any]:
        """Execute an HTTP request."""
        method = action.get("method", "GET").upper()
        url = action.get("url", "")
        headers = action.get("headers", {})
        body = action.get("body")

        if not url:
            return {"error": "No URL specified"}

        # Apply auth if available
        active = self.auth.get_active()
        if active:
            headers, _ = self.auth.apply_to_request(active.label, headers, {})

        result = await self.http.request(
            method=method,
            url=url,
            headers=headers or None,
            body=body,
        )

        console.print(f"[{'green' if 200 <= result['status_code'] < 300 else 'yellow'}] {method} {url} -> {result['status_code']} ({result['elapsed']:.2f}s, {len(result['body'])} bytes)[/]")

        # Run deterministic detectors
        findings = []
        if not result["error"] and result["status_code"] > 0:
            from demogorgon.detectors import Detector
            detector = Detector()
            auto_findings = detector.detect(url, result["body"], result["status_code"], method,
                                            response_headers=result.get("headers"))
            findings.extend(auto_findings)

            if auto_findings:
                for f in auto_findings:
                    # Score finding through confidence engine
                    f = self._score_finding(f, response_status=result["status_code"])
                    tag = "REPORTABLE" if f.get("should_report") else "LOW-CONF"
                    console.print(f"[bold red]AUTO-FINDING [{tag}]: [{f.get('severity', 'info').upper()}] {f['title']} ({f.get('confidence', 0):.0%})[/bold red]")
                    self.memory.add_finding(
                        title=f["title"],
                        severity=f.get("severity", "info"),
                        vuln_class=f.get("type", "unknown"),
                        endpoint=url,
                        method=method,
                        evidence=f.get("evidence", ""),
                        reproduction=f.get("steps", "").split("\n"),
                        impact=f.get("impact", ""),
                        confidence=f.get("confidence", 0),
                    )
                    # Feed finding to ChainFinder for chain discovery
                    self.chain_finder.add_finding({
                        "vuln_class": f.get("type", "unknown"),
                        "endpoint": url,
                        "param": f.get("parameter", ""),
                        "evidence": f.get("evidence", ""),
                        "severity": f.get("severity", "info"),
                    })

        # Feed endpoint to AttackGraph
        from demogorgon.are.attack_graph import Node, NodeType
        node_id = f"ep_{hash(url) % 100000}"
        if node_id not in self.attack_graph.nodes:
            self.attack_graph.add_node(Node(
                id=node_id,
                name=url,
                node_type=NodeType.ENDPOINT,
                properties={
                    "method": method,
                    "status_code": result["status_code"],
                    "response_length": len(result["body"]),
                },
            ))

        self.memory.add_endpoint(url, method=method, status_code=result["status_code"],
                                  response_length=len(result["body"]),
                                  response_snippet=result["body"][:500])

        return {
            "status_code": result["status_code"],
            "headers": result["headers"],
            "body": result["body"],
            "elapsed": result["elapsed"],
            "findings": findings,
            "evidence": [{
                "method": method,
                "url": url,
                "status": result["status_code"],
                "length": len(result["body"]),
            }],
        }

    async def _execute_replay(self, action: dict) -> dict[str, Any]:
        """Execute a replay request."""
        url = action.get("url", "")
        method = action.get("method", "GET")
        headers = action.get("headers", {})
        body = action.get("body")

        captured = self.browser.get_captured_requests(limit=100)
        target = None
        for req in reversed(captured):
            if req.get("url", "") == url and req.get("method", "") == method:
                target = req
                break
        if not target:
            target = {"method": method, "url": url, "headers": headers, "body": body}

        # Inject auth into replayed request headers
        active = self.auth.get_active()
        if active:
            target_headers = target.get("headers", {})
            target_headers, _ = self.auth.apply_to_request(active.label, target_headers, {})
            target["headers"] = target_headers

        from demogorgon.tools.replay import HTTPReplay
        replay = HTTPReplay(self.http)
        result = await replay.replay(target, label="research_loop")

        self.memory.add_evidence(
            method=method, url=url,
            request_headers=headers, request_body=body,
            response_status=result.status_code,
            response_headers={}, response_body=result.response_snippet,
        )

        return {
            "status_code": result.status_code,
            "headers": {},
            "body": result.response_snippet,
            "elapsed": result.elapsed,
            "findings": [],
            "evidence": [{
                "method": method,
                "url": url,
                "status": result.status_code,
                "length": result.response_length,
            }],
        }

    async def _run_authcore_testing(
        self, endpoint: str, action: dict, vuln_class: str,
    ) -> list[dict[str, Any]]:
        """Run authcore IDOR or role testing and return findings."""
        findings: list[dict[str, Any]] = []
        sessions = list(self.auth.sessions.values())
        if len(sessions) < 2:
            return findings

        method = action.get("method", "GET")

        try:
            if vuln_class in ("idor", "access_control"):
                # Cross-user IDOR testing
                candidates = self.inventory.get_idor_candidates()
                for candidate in candidates[:5]:  # Limit to 5 object types
                    obj_type = candidate["object_type"]
                    for i, source in enumerate(sessions):
                        targets = [s for s in sessions if s.session_id != source.session_id]
                        if not targets:
                            continue
                        results = await self.idor_tester.test_cross_access(
                            object_type=obj_type,
                            source_session=source,
                            target_sessions=targets,
                            methods=[method],
                        )
                        for r in results:
                            if r.get("is_breach"):
                                findings.append({
                                    "title": f"IDOR: {obj_type} accessible across users at {endpoint}",
                                    "type": "idor",
                                    "severity": "high",
                                    "confidence": 0.90,
                                    "evidence": f"Cross-user access: {r.get('breach_type', 'unknown')}",
                                    "parameter": "",
                                    "steps": f"1. Authenticate as user A\n2. Request {obj_type} using user B's credentials\n3. Observe unauthorized access",
                                    "impact": "Attacker can access other users' resources without authorization",
                                    "url": endpoint,
                                    "method": method,
                                })

            elif vuln_class in ("privilege_escalation", "role_bypass"):
                # Role-based access testing
                for i, low_session in enumerate(sessions):
                    for high_session in sessions:
                        if low_session.session_id == high_session.session_id:
                            continue
                        # Test if low-role user can access high-role endpoints
                        result = await self.role_tester.test_role_escalation(
                            endpoint=endpoint,
                            method=method,
                            low_role_session=low_session,
                            high_role_session=high_session,
                        )
                        if result.get("escalation_detected"):
                            findings.append({
                                "title": f"Privilege escalation: {low_session.role} accessed {high_session.role} resource at {endpoint}",
                                "type": "privilege_escalation",
                                "severity": "critical",
                                "confidence": 0.92,
                                "evidence": f"Role escalation from {low_session.role} to {high_session.role}",
                                "parameter": "",
                                "steps": f"1. Authenticate as {low_session.role}\n2. Access {endpoint} (requires {high_session.role})\n3. Observe unauthorized access",
                                "impact": "Attacker can escalate privileges and access administrative functions",
                                "url": endpoint,
                                "method": method,
                            })

                # Mass assignment testing
                for session in sessions:
                    result = await self.role_tester.test_mass_assignment(
                        endpoint=endpoint,
                        method=method,
                        session=session,
                        base_body=action.get("body", {}),
                    )
                    if result.get("vulnerable"):
                        findings.append({
                            "title": f"Mass assignment at {endpoint}",
                            "type": "mass_assignment",
                            "severity": "high",
                            "confidence": 0.88,
                            "evidence": f"Escalation fields accepted: {result.get('escalated_fields', [])}",
                            "parameter": "",
                            "steps": f"1. Send request with role/user_role fields set to 'admin'\n2. Observe fields accepted in response",
                            "impact": "Attacker can modify privileged fields to escalate access",
                            "url": endpoint,
                            "method": method,
                        })

        except Exception as e:
            console.print(f"[yellow]Authcore testing error: {e}[/yellow]")

        return findings

    async def _execute_browser(self, action: dict) -> dict[str, Any]:
        """Execute a browser action."""
        action_type = action.get("browser_action", "navigate")
        url = action.get("url", "")
        selector = action.get("selector", "")
        value = action.get("value", "")

        if action_type == "navigate" and url:
            result = await self.browser.navigate(url)
            return {"status_code": 200, "body": str(result), "headers": {}, "elapsed": 0, "findings": [], "evidence": []}
        elif action_type == "click" and selector:
            result = await self.browser.click(selector)
            return {"status_code": 200, "body": str(result), "headers": {}, "elapsed": 0, "findings": [], "evidence": []}
        elif action_type == "fill" and selector and value:
            result = await self.browser.fill(selector, value)
            return {"status_code": 200, "body": str(result), "headers": {}, "elapsed": 0, "findings": [], "evidence": []}
        elif action_type == "evaluate" and action.get("expression"):
            result = await self.browser.evaluate(action["expression"])
            return {"status_code": 200, "body": str(result), "headers": {}, "elapsed": 0, "findings": [], "evidence": []}
        elif action_type == "content":
            content = await self.browser.get_content()
            return {"status_code": 200, "body": content[:5000], "headers": {}, "elapsed": 0, "findings": [], "evidence": []}
        else:
            return {"error": f"Unknown browser action: {action_type}"}

    async def _execute_tool_manager(self, tool: str, action: dict, vuln_class: str = "") -> dict[str, Any]:
        """Execute a registered ToolManager adapter (subfinder, nuclei, ffuf, etc.)."""
        tool_action = action.get("tool_action") or action.get("action") or "enumerate"
        params = {
            k: v
            for k, v in action.items()
            if k not in ("tool", "tool_action", "action", "reason")
        }
        if "domain" not in params:
            from urllib.parse import urlparse
            host = urlparse(action.get("url", self.target_url)).hostname or ""
            if host:
                params.setdefault("domain", host)
                params.setdefault("target", action.get("url", self.target_url))

        console.print(f"[cyan]ToolManager → {tool}.{tool_action}({params})[/cyan]")
        result = await self.tool_manager.execute(tool, tool_action, params)

        findings: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = [dict(result)]
        if result.get("success") and result.get("items"):
            for item in result["items"]:
                if isinstance(item, dict) and item.get("finding"):
                    findings.append({
                        "title": str(item["finding"]),
                        "severity": item.get("severity", "info"),
                        "type": vuln_class or tool,
                        "vuln_class": vuln_class or tool,
                        "endpoint": params.get("url") or params.get("domain") or params.get("target", ""),
                        "evidence": [item],
                    })

        return {
            "status_code": 200 if result.get("success") else 0,
            "body": json.dumps(result.get("data", {}), default=str)[:5000],
            "headers": {},
            "elapsed": 0,
            "findings": findings,
            "evidence": evidence,
            "error": result.get("error") if not result.get("success") else None,
        }

    # ============================================================
    # Observe & Adapt
    # ============================================================

    def _observe(self, result: ExperimentResult):
        """Update the application model with new observations."""
        self.state.observation_count += len(result.new_observations)

        for obs in result.new_observations:
            if isinstance(obs, dict):
                self.app_model.add_observation(obs)
                self.memory.add_observation(
                    description=obs.get("description", str(obs)),
                    endpoint=result.endpoint,
                    category=obs.get("category", "general"),
                )

        for obj in result.new_business_objects:
            if isinstance(obj, dict):
                self.app_model.add_business_object(BusinessObject(
                    object_type=obj.get("object_type", "unknown"),
                    identifier=obj.get("identifier", ""),
                    owner=obj.get("owner"),
                    properties=obj.get("properties", {}),
                    endpoint=result.endpoint,
                ))

        # Update model confidence
        self._update_model_confidence()

    def _adapt(self, result: ExperimentResult):
        """Adapt strategy based on experiment results."""
        if result.is_finding:
            self.state.finding_count += 1
            self.state.last_finding_at = self.state.experiment_count
            self.state.stagnation_count = 0
            self.state.strategy = "exploit"

            # Score all executor-produced findings
            for f in result.findings:
                f = self._score_finding(f, response_status=0)
                tag = "REPORTABLE" if f.get("should_report") else "LOW-CONF"
                console.print(f"[bold red]FINDING #{self.state.finding_count} [{tag}]: {f.get('title', 'Unknown')} ({f.get('confidence', 0):.0%})[/bold red]")
        else:
            self.state.stagnation_count += 1

        # Update evaluator
        self.evaluator.evaluate(
            experiment_result={"findings": result.findings},
            hypothesis={"description": result.executor, "vuln_class": result.executor},
            is_finding=result.is_finding,
            endpoint=result.endpoint,
            vuln_class=result.executor,
            evidence=str(result.evidence)[:500] if result.evidence else "",
        )

        # Strategy transitions
        if self.state.strategy == "pivot":
            # Generate new hypotheses for untested vuln classes
            untested = self._get_untested_vuln_classes()
            for vc in untested[:3]:
                self.app_model.add_attack_opportunity(AttackOpportunity(
                    description=f"Test for {vc}",
                    vuln_class=vc,
                    endpoint=self.target_url,
                    confidence=0.3,
                    reasoning=f"Pivot to untested vulnerability class: {vc}",
                ))
            self.state.strategy = "explore"

    # ============================================================
    # Checkpoint / Resume
    # ============================================================

    def _save_checkpoint(self):
        """Save state for crash recovery."""
        self.checkpoint.update("experiment_count", self.state.experiment_count)
        self.checkpoint.update("finding_count", self.state.finding_count)
        self.checkpoint.update("observation_count", self.state.observation_count)
        self.checkpoint.update("strategy", self.state.strategy)
        self.checkpoint.update("stagnation_count", self.state.stagnation_count)
        self.checkpoint.update("tested_actions", list(self.state.tested_actions))
        self.checkpoint.update("failed_hypotheses", list(self.state.failed_hypotheses))
        self.checkpoint.update("finding_scores", self._finding_scores)
        self.memory.save()
        self.checkpoint.save_sync()

    def _load_checkpoint(self) -> bool:
        """Load state from checkpoint. Returns True if restored."""
        if not self.checkpoint.load_sync():
            return False
        self.state.experiment_count = self.checkpoint.get("experiment_count", 0)
        self.state.finding_count = self.checkpoint.get("finding_count", 0)
        self.state.observation_count = self.checkpoint.get("observation_count", 0)
        self.state.strategy = self.checkpoint.get("strategy", "explore")
        self.state.stagnation_count = self.checkpoint.get("stagnation_count", 0)
        self.state.tested_actions = set(self.checkpoint.get("tested_actions", []))
        self.state.failed_hypotheses = set(self.checkpoint.get("failed_hypotheses", []))
        self._finding_scores = self.checkpoint.get("finding_scores", [])

        # Restore memory from saved state
        restored = Memory.load(self.target_url)
        if restored:
            self.memory = restored
            console.print(f"[green]Restored from checkpoint: {self.state.experiment_count} experiments, {self.state.finding_count} findings[/green]")
            return True
        return False

    def _self_evaluate(self):
        """Self-evaluate progress every 20 experiments."""
        console.print("\n[bold yellow]=== Self-Evaluation ===[/bold yellow]")

        summary = self.evaluator.get_progress_summary()
        console.print(f"  Experiments: {self.state.experiment_count}")
        console.print(f"  Findings: {self.state.finding_count}")
        console.print(f"  Average score: {summary.get('average_score', 0):.2f}")
        console.print(f"  Endpoints discovered: {len(self.memory.endpoints)}")
        console.print(f"  Business objects: {len(self.app_model.business_objects)}")
        console.print(f"  Trust boundaries: {len(self.app_model.trust_boundaries)}")
        console.print(f"  Workflows: {len(self.app_model.workflows)}")

        # Check for stagnation
        if summary.get("should_change_strategy", False):
            console.print("[yellow]Evaluator recommends strategy change[/yellow]")
            self.state.strategy = "pivot"

        # Check coverage gaps
        untested_vulns = self._get_untested_vuln_classes()
        if untested_vulns:
            console.print(f"[yellow]Untested vuln classes: {', '.join(untested_vulns)}[/yellow]")

        untested_endpoints = [ep for ep in self.memory.endpoints.values() if not ep.tested]
        if untested_endpoints:
            console.print(f"[yellow]Untested endpoints: {len(untested_endpoints)}[/yellow]")

        # Check if we're just repeating
        if self.state.duplicate_streak > 3:
            console.print("[red]Too many duplicates — forcing strategy pivot[/red]")
            self.state.strategy = "pivot"
            self.state.duplicate_streak = 0

    # ============================================================
    # Context Building
    # ============================================================

    def _build_reasoning_context(self) -> str:
        """Build context for the LLM reasoning step — structured, budget-aware."""
        from demogorgon.core.context import ContextBuilder

        cb = ContextBuilder(budget=self.config.context_window_limit)

        # Target + strategy (always included, highest priority)
        cb.add_section(
            "target",
            f"TARGET: {self.target_url}\nSTRATEGY: {self.state.strategy}",
            priority=100,
        )

        # Application model summary
        model_lines = [
            f"Product: {self.app_model.product_type.value} - {self.app_model.product_description}",
            f"Roles: {', '.join(f'{r.name}(L{r.level})' for r in self.app_model.user_roles)}",
            f"Ownership: {self.app_model.ownership_model}",
        ]
        cb.add_section("app_model", "\n".join(model_lines), priority=95)

        # Business objects (high value for IDOR testing)
        if self.app_model.business_objects:
            bo_lines = [f"{len(self.app_model.business_objects)} objects:"]
            by_type: dict[str, list[BusinessObject]] = {}
            for obj in self.app_model.business_objects:
                by_type.setdefault(obj.object_type, []).append(obj)
            for obj_type, objects in by_type.items():
                owners = set(o.owner for o in objects if o.owner)
                bo_lines.append(f"  {obj_type}: {len(objects)} instances, owners: {owners}")
            cb.add_section("business_objects", "\n".join(bo_lines), priority=90)

        # IDOR candidates (critical for attack planning)
        idor = self.app_model.get_idor_candidates()
        if idor:
            idor_lines = [f"{len(idor)} candidates:"]
            for o1, o2 in idor[:5]:
                idor_lines.append(f"  {o1.object_type}#{o1.identifier} (owner={o1.owner}) vs {o2.object_type}#{o2.identifier} (owner={o2.owner})")
            cb.add_section("idor_candidates", "\n".join(idor_lines), priority=88)

        # Workflows
        if self.app_model.workflows:
            wf_lines = []
            for name, steps in self.app_model.workflows.items():
                wf_lines.append(f"  {name}: {' -> '.join(s.name for s in steps[:5])}")
            cb.add_section("workflows", "\n".join(wf_lines), priority=80)

        # Trust boundaries
        if self.app_model.trust_boundaries:
            tb_lines = [f"{len(self.app_model.trust_boundaries)} boundaries:"]
            for b in self.app_model.trust_boundaries[:5]:
                tb_lines.append(f"  {b.name}: {b.from_level} -> {b.to_level}")
            cb.add_section("trust_boundaries", "\n".join(tb_lines), priority=80)

        # Attack opportunities (high value — this is what the LLM reasons about)
        untested_opps = [
            o for o in self.app_model.attack_opportunities
            if f"{o.method} {o.endpoint}" not in self.state.tested_actions
        ]
        if untested_opps:
            opp_lines = [f"{len(untested_opps)} untested:"]
            for o in untested_opps[:10]:
                opp_lines.append(f"  [{o.confidence:.0%}] {o.description}")
                opp_lines.append(f"    {o.reasoning}")
            cb.add_section("attack_opportunities", "\n".join(opp_lines), priority=85)

        # What's been tested (avoid duplicates)
        if self.state.tested_actions:
            tested_lines = list(self.state.tested_actions)[-15:]
            cb.add_section("already_tested", "\n".join(f"  {c}" for c in tested_lines), priority=60)

        # Failed hypotheses (DO NOT RETRY)
        if self.state.failed_hypotheses:
            failed_lines = list(self.state.failed_hypotheses)[-10:]
            cb.add_section("failed_hypotheses", "\n".join(f"  FAILED: {h}" for h in failed_lines), priority=70)

        # Unvisited endpoints (discoverability)
        unvisited = [ep for ep in self.memory.endpoints.values()
                     if ep.url not in self.state.tested_actions and not ep.tested]
        if unvisited:
            uv_lines = [f"  {ep.method} {ep.url}" for ep in unvisited[:10]]
            cb.add_section("unvisited_endpoints", "\n".join(uv_lines), priority=50)

        # Recent evidence (lowest priority)
        if self.memory.evidence:
            ev_lines = [f"  {e.get('method', 'GET')} {e.get('url', '')} -> {e.get('response_status', 'unknown')}"
                        for e in self.memory.evidence[-5:]]
            cb.add_section("recent_evidence", "\n".join(ev_lines), priority=40)

        return cb.build()

    def _build_understand_context(self) -> str:
        """Build context for the understanding phase."""
        lines = [f"TARGET: {self.target_url}"]

        # Page content
        lines.append(f"\nENDPOINTS ({len(self.memory.endpoints)}):")
        for ep in list(self.memory.endpoints.values())[:20]:
            lines.append(f"  {ep.method} {ep.url} (status={ep.status_code})")

        # Recent evidence
        if self.memory.evidence:
            lines.append(f"\nRECENT API RESPONSES:")
            for e in self.memory.evidence[-5:]:
                lines.append(f"  {e.get('method', 'GET')} {e.get('url', '')} -> {e.get('response_status', 'unknown')}")

        return "\n".join(lines)

    def _update_app_model_from_observations(self):
        """Update app model confidence based on what we know."""
        score = 0.0
        if self.app_model.product_type != ProductType.UNKNOWN:
            score += 0.2
        if self.app_model.user_roles:
            score += 0.2
        if self.app_model.business_objects:
            score += 0.2
        if self.app_model.workflows:
            score += 0.2
        if self.app_model.trust_boundaries:
            score += 0.1
        if self.app_model.attack_opportunities:
            score += 0.1
        self.app_model.confidence = min(score, 1.0)

    def _update_model_confidence(self):
        """Update confidence based on what we've discovered."""
        self._update_app_model_from_observations()

    def _get_untested_vuln_classes(self) -> list[str]:
        """Get vulnerability classes that haven't been tested yet."""
        all_classes = {
            "idor", "xss", "sqli", "ssrf", "cors", "auth_bypass",
            "jwt", "privesc", "race", "info_disclosure", "csrf",
            "file_upload", "ssti", "xxe", "open_redirect", "business_logic",
        }
        tested = set()
        for action in self.state.tested_actions:
            for vc in all_classes:
                if vc in action.lower():
                    tested.add(vc)
        return list(all_classes - tested)

    def _in_scope(self, url: str) -> bool:
        """Check if a URL is in scope — delegates to canonical ScopeValidator."""
        return self._scope_validator.in_scope(url)

    # ============================================================
    # LLM Reasoning
    # ============================================================

    async def _llm_reason(self, system_prompt: str, context: str) -> str | None:
        """Make an LLM call for reasoning."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": f"Analyze this:\n{context}"},
        ]

        try:
            response = await self.llm_complete(messages, response_format={"type": "json_object"})
            self.metrics.record_llm(success=True)
            return response
        except Exception as e:
            self.metrics.record_llm(success=False)
            console.print(f"[red]LLM error: {e}[/red]")
            return None

    # ============================================================
    # Report Generation
    # ============================================================

    def _generate_report(self) -> dict[str, Any]:
        """Generate the final report."""
        findings = self.memory.findings
        runtime = self.state.runtime_seconds

        # Classify findings by confidence
        reportable = [s for s in self._finding_scores if s.get("should_report")]
        low_conf = [s for s in self._finding_scores if not s.get("should_report")]

        # Finalize metrics
        self.metrics.mark_end()
        self.metrics.metrics.experiments_run = self.state.experiment_count
        self.metrics.metrics.endpoints_discovered = len(self.memory.endpoints)
        # findings_total / by_severity already recorded as findings arrive
        if not self.metrics.metrics.findings_total:
            self.metrics.metrics.findings_total = len(findings)
            for f in findings:
                sev = getattr(f.severity, "value", str(f.severity))
                self.metrics.record_finding(sev, f.vuln_class, f.confidence)
        try:
            metrics_path = self.metrics.save("hunt_output/metrics.json")
        except Exception:
            metrics_path = None

        # Enhance findings with CVSS + PoC for report
        from demogorgon.core.cvss import enhance_finding_with_cvss
        enriched_findings = []
        for f in findings:
            d = {
                "title": f.title,
                "severity": getattr(f.severity, "value", str(f.severity)),
                "vuln_class": f.vuln_class,
                "endpoint": f.endpoint,
                "method": f.method,
                "evidence": f.evidence,
                "reproduction": f.reproduction,
                "impact": f.impact,
                "confidence": f.confidence,
            }
            enhance_finding_with_cvss(d)
            try:
                d["poc"] = generate_poc_from_finding(d)
            except Exception:
                d["poc"] = None
            enriched_findings.append(d)

        console.print(f"\n[bold green]Research Loop Complete[/bold green]")
        console.print(f"  Target: {self.target_url}")
        console.print(f"  Runtime: {runtime:.0f}s")
        console.print(f"  Experiments: {self.state.experiment_count}")
        console.print(f"  Findings: {len(findings)}")
        console.print(f"  Reportable (>=85%): {len(reportable)}")
        console.print(f"  Below threshold: {len(low_conf)}")
        console.print(f"  Endpoints: {len(self.memory.endpoints)}")
        console.print(f"  Subdomains: {self.metrics.metrics.subdomains_discovered}")
        console.print(f"  Business Objects: {len(self.app_model.business_objects)}")
        console.print(f"  Trust Boundaries: {len(self.app_model.trust_boundaries)}")
        if metrics_path:
            console.print(f"  Metrics: {metrics_path}")

        if reportable:
            console.print("\n[bold red]=== REPORTABLE FINDINGS ===[/bold red]")
            for s in reportable:
                console.print(f"  [{s['severity'].upper()}] {s['title']}")
                console.print(f"    Endpoint: {s['endpoint']}")
                console.print(f"    Confidence: {s['final_confidence']:.0%}")
                console.print(f"    Reasoning: {s['reasoning'][:120]}")
                console.print()

        if low_conf:
            console.print("\n[yellow]=== BELOW THRESHOLD ===[/yellow]")
            for s in low_conf:
                console.print(f"  [{s['severity'].upper()}] {s['title']} ({s['final_confidence']:.0%})")

        return {
            "target": self.target_url,
            "runtime": runtime,
            "experiments": self.state.experiment_count,
            "findings": len(findings),
            "reportable_count": len(reportable),
            "finding_details": enriched_findings,
            "scored_findings": self._finding_scores,
            "metrics": self.metrics.metrics.to_dict(),
            "endpoints_discovered": len(self.memory.endpoints),
            "business_objects": len(self.app_model.business_objects),
            "trust_boundaries": len(self.app_model.trust_boundaries),
            "workflows": len(self.app_model.workflows),
            "model_confidence": self.app_model.confidence,
            "coverage": self.evaluator.get_progress_summary(),
            "controller_coverage": self.controller.get_coverage_report(),
            "graph_statistics": self.graph.get_statistics(),
            "chain_summary": self.chain_finder.get_chain_summary(),
            "reportable_chains": [
                {
                    "title": c.title,
                    "severity": c.severity,
                    "confidence": c.confidence,
                    "chain_type": c.chain_type,
                    "steps": len(c.steps),
                    "final_impact": c.final_impact,
                }
                for c in self.chain_finder.get_reportable_chains()
            ],
            "attack_graph": self.attack_graph.get_summary(),
            "decision_trace": self.decision_trace.get_traces() if self.decision_trace else [],
            "laya": {
                "enabled": bool(
                    getattr(self.hunt_config, "laya", None)
                    and self.hunt_config.laya.enabled
                    and self.laya is not None
                ),
                "confidence_threshold": getattr(
                    getattr(self.hunt_config, "laya", None), "confidence_threshold", 0.0
                ),
                "decisions_recorded": len(self.decision_trace._decisions) if self.decision_trace else 0,
            },
            "tools_registered": list(self.tool_manager._adapters.keys()) if self.tool_manager else [],
        }
