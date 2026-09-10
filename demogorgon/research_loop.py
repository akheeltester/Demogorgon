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
from demogorgon.evidence_validator import EvidenceValidator
from demogorgon.controller.self_evaluator import SelfEvaluator

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
        self.evidence_validator = EvidenceValidator()
        self.evaluator = SelfEvaluator()
        self.state = LoopState()

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
        self.knowledge_base = KnowledgeBase()
        self.mutations = MutationIntelligence()
        self.chain_finder = ChainFinder()
        self.trust_mapper = TrustBoundaryMapper()
        self.attack_graph = AttackGraph()

        # Canonical scope validator
        from demogorgon.core.scope import ScopeValidator
        self._scope_validator = ScopeValidator(target_url)

        # Deterministic executors (lazy loaded)
        self._executors: dict[str, Any] = {}

    # ============================================================
    # Main Loop
    # ============================================================

    async def run(self) -> dict[str, Any]:
        """Run the full research loop."""
        console.print(f"\n[bold green]Research Loop started on {self.target_url}[/bold green]")
        console.print(f"[cyan]Max experiments: {self.config.max_experiments}[/cyan]")

        # Initialize ExecutionGraph with a primary goal
        self.graph.add_goal(
            description=f"Find vulnerabilities in {self.target_url}",
            priority=1.0,
        )

        try:
            # Phase 1: Understand
            await self._phase_understand()

            # Phase 2: Model
            await self._phase_model()

            # Phase 3-N: Reason → Experiment → Observe → Adapt
            await self._phase_reason_experiment_cycle()

            # Final: Validate and Report
            return self._generate_report()

        except KeyboardInterrupt:
            console.print("\n[yellow]Research loop interrupted[/yellow]")
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
        """The core loop: reason, experiment, observe, adapt."""
        console.print("\n[bold cyan]Phase 3: Reason → Experiment → Observe → Adapt[/bold cyan]")

        while self.state.experiment_count < self.config.max_experiments:
            # Self-evaluate every 20 experiments
            if self.state.should_self_eval:
                self._self_evaluate()

            # Check stagnation
            if self.state.stagnation_count >= self.config.stagnation_threshold:
                console.print("[yellow]Stagnation detected — pivoting strategy[/yellow]")
                self.state.strategy = "pivot"
                self.state.stagnation_count = 0

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

            # Rate limit protection
            await asyncio.sleep(self.config.rate_limit_delay)

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
                    console.print(f"[bold red]AUTO-FINDING: [{f.get('severity', 'info').upper()}] {f['title']}[/bold red]")
                    self.memory.add_finding(
                        title=f["title"],
                        severity=f.get("severity", "info"),
                        vuln_class=f.get("type", "unknown"),
                        endpoint=url,
                        method=method,
                        evidence=f.get("evidence", ""),
                        reproduction=f.get("steps", "").split("\n"),
                        impact=f.get("impact", ""),
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
            console.print(f"[bold red]FINDING #{self.state.finding_count}: {result.findings[0].get('title', 'Unknown')}[/bold red]")
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
            return response
        except Exception as e:
            console.print(f"[red]LLM error: {e}[/red]")
            return None

    # ============================================================
    # Report Generation
    # ============================================================

    def _generate_report(self) -> dict[str, Any]:
        """Generate the final report."""
        findings = self.memory.findings
        runtime = self.state.runtime_seconds

        console.print(f"\n[bold green]Research Loop Complete[/bold green]")
        console.print(f"  Target: {self.target_url}")
        console.print(f"  Runtime: {runtime:.0f}s")
        console.print(f"  Experiments: {self.state.experiment_count}")
        console.print(f"  Findings: {len(findings)}")
        console.print(f"  Endpoints: {len(self.memory.endpoints)}")
        console.print(f"  Business Objects: {len(self.app_model.business_objects)}")
        console.print(f"  Trust Boundaries: {len(self.app_model.trust_boundaries)}")

        if findings:
            console.print("\n[bold red]=== FINDINGS ===[/bold red]")
            for f in findings:
                console.print(f"  [{f.severity.value.upper()}] {f.title}")
                console.print(f"    Endpoint: {f.method} {f.endpoint}")
                console.print(f"    Impact: {f.impact}")
                console.print()

        return {
            "target": self.target_url,
            "runtime": runtime,
            "experiments": self.state.experiment_count,
            "findings": len(findings),
            "finding_details": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "vuln_class": f.vuln_class,
                    "endpoint": f.endpoint,
                    "method": f.method,
                    "evidence": f.evidence,
                    "reproduction": f.reproduction,
                    "impact": f.impact,
                }
                for f in findings
            ],
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
        }
