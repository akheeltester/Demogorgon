"""Experiment Executor — runs experiment plans via tools.

Implements the ExperimentExecutor interface. Takes a plan from the
ExperimentPlanner and executes it using available tools (HTTP client,
browser, external tools).
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Callable, Awaitable

from ..interfaces import ExperimentExecutor

logger = logging.getLogger(__name__)


class PlanExecutor(ExperimentExecutor):
    """Executes experiment plans using available tools.

    Usage:
        executor = PlanExecutor(
            http_client=http_client,
            tool_executor=tool_executor,
        )
        result = await executor.execute(plan)
    """

    def __init__(
        self,
        http_client: Any = None,
        tool_executor: Any = None,
        browser: Any = None,
        auth_headers: dict[str, str] | None = None,
        rate_limit_delay: float = 1.0,
        # Phase 11.1 agent integration
        capability_registry: Any = None,
        event_bus: Any = None,
    ):
        self._http = http_client
        self._tools = tool_executor
        self._browser = browser
        self._auth_headers = auth_headers or {}
        self._rate_limit_delay = rate_limit_delay
        self._last_request_time = 0.0

        # Agent subsystems
        self._capability_registry = capability_registry
        self._event_bus = event_bus

    async def execute(self, plan: dict[str, Any]) -> dict[str, Any]:
        """Execute an experiment plan.

        Args:
            plan: Experiment plan with steps, preconditions, safety_checks

        Returns:
            Execution results with observations, evidence, success, error
        """
        start_time = time.time()
        observations: list[dict[str, Any]] = []
        evidence: list[dict[str, Any]] = []
        errors: list[str] = []

        # Check preconditions
        preconditions = plan.get("preconditions", [])
        for precond in preconditions:
            if not await self._check_precondition(precond):
                return {
                    "observations": [],
                    "evidence": [],
                    "success": False,
                    "error": f"Precondition failed: {precond}",
                    "duration": time.time() - start_time,
                }

        # Execute steps
        steps = plan.get("steps", [])
        for step in steps:
            try:
                result = await self._execute_step(step)
                observations.extend(result.get("observations", []))
                evidence.extend(result.get("evidence", []))

                # Rate limiting
                await self._rate_limit()

            except Exception as e:
                error_msg = f"Step {step.get('step', '?')} failed: {e}"
                logger.warning(error_msg)
                errors.append(error_msg)

                # Check if step is critical
                if step.get("critical", False):
                    return {
                        "observations": observations,
                        "evidence": evidence,
                        "success": False,
                        "error": error_msg,
                        "duration": time.time() - start_time,
                    }

        return {
            "observations": observations,
            "evidence": evidence,
            "success": len(errors) == 0,
            "error": "; ".join(errors) if errors else "",
            "duration": time.time() - start_time,
        }

    async def _execute_step(self, step: dict[str, Any]) -> dict[str, Any]:
        """Execute a single step."""
        action = step.get("action", "send_request")
        target = step.get("target", "")
        method = step.get("method", "GET")

        if action == "send_request":
            return await self._execute_http_request(target, method, step)
        elif action == "navigate":
            return await self._execute_browser_navigate(target)
        elif action == "click":
            return await self._execute_browser_click(step)
        elif action == "fill":
            return await self._execute_browser_fill(step)
        elif action == "evaluate":
            return await self._execute_browser_evaluate(step)
        elif action == "tool":
            return await self._execute_tool_call(step)
        else:
            logger.warning(f"Unknown action: {action}")
            return {"observations": [], "evidence": []}

    async def _execute_http_request(
        self, url: str, method: str, step: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute an HTTP request."""
        if not self._http:
            return {
                "observations": [{"description": "No HTTP client available"}],
                "evidence": [],
            }

        headers = {**self._auth_headers}
        if "headers" in step:
            headers.update(step["headers"])

        body = step.get("body")
        timeout = step.get("timeout", 30)

        try:
            if method.upper() == "GET":
                response = await self._http.get(url, headers=headers, timeout=timeout)
            elif method.upper() == "POST":
                response = await self._http.post(url, headers=headers, content=body, timeout=timeout)
            elif method.upper() == "PUT":
                response = await self._http.put(url, headers=headers, content=body, timeout=timeout)
            elif method.upper() == "DELETE":
                response = await self._http.delete(url, headers=headers, timeout=timeout)
            elif method.upper() == "PATCH":
                response = await self._http.patch(url, headers=headers, content=body, timeout=timeout)
            else:
                response = await self._http.request(method, url, headers=headers, content=body, timeout=timeout)

            # Build evidence
            evidence_item = {
                "type": "http_request",
                "request": {
                    "method": method,
                    "url": url,
                    "headers": dict(headers),
                    "body": body,
                },
                "response": {
                    "status_code": response.status_code,
                    "headers": dict(response.headers),
                    "body": response.text[:10000] if hasattr(response, 'text') else str(response.content[:10000]),
                },
            }

            # Build observation
            observation = {
                "description": f"{method} {url} -> {response.status_code}",
                "data": {
                    "status_code": response.status_code,
                    "content_length": len(response.content) if hasattr(response, 'content') else 0,
                    "has_auth_header": "authorization" in {k.lower() for k in headers},
                },
            }

            return {
                "observations": [observation],
                "evidence": [evidence_item],
            }

        except Exception as e:
            return {
                "observations": [{"description": f"HTTP request failed: {e}"}],
                "evidence": [],
            }

    async def _execute_browser_navigate(self, url: str) -> dict[str, Any]:
        """Execute browser navigation."""
        if not self._browser:
            return {
                "observations": [{"description": "No browser available"}],
                "evidence": [],
            }

        try:
            await self._browser.goto(url)
            title = await self._browser.title()
            content = await self._browser.content()

            return {
                "observations": [{"description": f"Navigated to {url}, title: {title}"}],
                "evidence": [{
                    "type": "browser_navigation",
                    "url": url,
                    "title": title,
                    "content_length": len(content),
                }],
            }
        except Exception as e:
            return {
                "observations": [{"description": f"Browser navigation failed: {e}"}],
                "evidence": [],
            }

    async def _execute_browser_click(self, step: dict[str, Any]) -> dict[str, Any]:
        """Execute browser click."""
        selector = step.get("selector", "")
        if not self._browser:
            return {"observations": [], "evidence": []}

        try:
            await self._browser.click(selector)
            return {
                "observations": [{"description": f"Clicked {selector}"}],
                "evidence": [{"type": "browser_click", "selector": selector}],
            }
        except Exception as e:
            return {
                "observations": [{"description": f"Click failed: {e}"}],
                "evidence": [],
            }

    async def _execute_browser_fill(self, step: dict[str, Any]) -> dict[str, Any]:
        """Execute browser form fill."""
        selector = step.get("selector", "")
        value = step.get("value", "")
        if not self._browser:
            return {"observations": [], "evidence": []}

        try:
            await self._browser.fill(selector, value)
            return {
                "observations": [{"description": f"Filled {selector} with value"}],
                "evidence": [{"type": "browser_fill", "selector": selector}],
            }
        except Exception as e:
            return {
                "observations": [{"description": f"Fill failed: {e}"}],
                "evidence": [],
            }

    async def _execute_browser_evaluate(self, step: dict[str, Any]) -> dict[str, Any]:
        """Execute browser JavaScript evaluation."""
        expression = step.get("expression", "")
        if not self._browser:
            return {"observations": [], "evidence": []}

        try:
            result = await self._browser.evaluate(expression)
            return {
                "observations": [{"description": f"Evaluated JS expression"}],
                "evidence": [{"type": "browser_evaluate", "expression": expression, "result": str(result)[:1000]}],
            }
        except Exception as e:
            return {
                "observations": [{"description": f"JS evaluation failed: {e}"}],
                "evidence": [],
            }

    async def _execute_tool_call(self, step: dict[str, Any]) -> dict[str, Any]:
        """Execute a tool call via ToolExecutor."""
        tool_name = step.get("tool", "")
        action = step.get("tool_action", "")
        params = step.get("params", {})

        if not self._tools:
            return {"observations": [{"description": "No tool executor available"}], "evidence": []}

        try:
            result = await self._tools.execute_tool(tool_name, action, params)
            return {
                "observations": [{"description": f"Tool {tool_name} executed"}],
                "evidence": [{"type": "tool_call", "tool": tool_name, "action": action, "result": result}],
            }
        except Exception as e:
            return {
                "observations": [{"description": f"Tool call failed: {e}"}],
                "evidence": [],
            }

    async def _check_precondition(self, precond: str) -> bool:
        """Check if a precondition is met."""
        # Basic precondition checks
        precond_lower = precond.lower()
        if "rate limit" in precond_lower:
            return True  # Rate limiting is handled by _rate_limit()
        if "scope" in precond_lower:
            return True  # Scope checking is handled elsewhere
        if "auth" in precond_lower:
            return bool(self._auth_headers)
        return True  # Default: assume precondition is met

    async def _rate_limit(self) -> None:
        """Apply rate limiting between requests."""
        now = time.time()
        elapsed = now - self._last_request_time
        if elapsed < self._rate_limit_delay:
            await asyncio.sleep(self._rate_limit_delay - elapsed)
        self._last_request_time = time.time()
