"""Tool Executor — executes tools through structured adapters.

The executor:
1. Takes a tool action proposal from the reasoning engine
2. Validates it against policy
3. Routes to the appropriate tool adapter
4. Returns structured results

The LLM never executes arbitrary shell commands.
It proposes actions, and this executor validates and runs them.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from typing import Any

from .base import Tool, ToolCategory, ToolResult
from .registry import ToolRegistry


@dataclass
class ActionResult:
    """Result of an action execution."""
    success: bool
    tool_name: str
    action: str
    data: dict[str, Any]
    error: str = ""
    duration: float = 0.0

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "tool_name": self.tool_name,
            "action": self.action,
            "data": self.data,
            "error": self.error,
            "duration": self.duration,
        }


class ToolExecutor:
    """Executes tools through structured adapters.

    The executor is the bridge between the reasoning engine and the tools.
    It ensures:
    - All actions are policy-validated
    - All results are structured
    - All failures are handled gracefully

    Usage:
        executor = ToolExecutor(registry)

        # Execute a recon action
        result = await executor.execute_recon("subdomain_enum", {"domain": "example.com"})

        # Execute a fuzzing action
        result = await executor.execute_fuzz("directory_fuzz", {"url": "https://example.com", "wordlist": "common.txt"})
    """

    def __init__(self, registry: ToolRegistry):
        self._registry = registry

    async def execute_recon(self, action: str, params: dict[str, Any]) -> ActionResult:
        """Execute a reconnaissance action."""
        tool_map = {
            "subdomain_enum": self._execute_subfinder,
            "subdomain_enum_passive": self._execute_amass,
            "port_scan": self._execute_nmap,
            "http_probe": self._execute_httpx,
            "dns_enum": self._execute_dnsx,
            "web_crawl": self._execute_katana,
            "url_harvest": self._execute_gau,
            "wayback": self._execute_waybackurls,
            "cert_transparency": self._execute_crtsh,
        }

        handler = tool_map.get(action)
        if handler:
            return await handler(params)

        return ActionResult(
            success=False,
            tool_name="recon",
            action=action,
            data={},
            error=f"Unknown recon action: {action}",
        )

    async def execute_scan(self, action: str, params: dict[str, Any]) -> ActionResult:
        """Execute a scanning action."""
        tool_map = {
            "template_scan": self._execute_nuclei,
            "directory_fuzz": self._execute_ffuf_ffuf,
            "parameter_fuzz": self._execute_ffuf_params,
            "sql_injection": self._execute_sqlmap,
        }

        handler = tool_map.get(action)
        if handler:
            return await handler(params)

        return ActionResult(
            success=False,
            tool_name="scan",
            action=action,
            data={},
            error=f"Unknown scan action: {action}",
        )

    async def execute_tool(self, tool_name: str, action: str, params: dict[str, Any]) -> ActionResult:
        """Execute any tool action directly."""
        start = time.time()
        result = await self._registry.execute(tool_name, action, params)
        duration = time.time() - start

        return ActionResult(
            success=result.success,
            tool_name=tool_name,
            action=action,
            data=result.data,
            error=result.error,
            duration=duration,
        )

    # ─── Recon Handlers ──────────────────────────────────────────

    async def _execute_subfinder(self, params: dict[str, Any]) -> ActionResult:
        """Execute subfinder for subdomain enumeration."""
        domain = params.get("domain", "")
        if not domain:
            return ActionResult(success=False, tool_name="subfinder", action="subdomain_enum", data={}, error="No domain provided")

        start = time.time()
        result = await self._registry.execute("subfinder", "enumerate", {"domain": domain})
        return ActionResult(
            success=result.success,
            tool_name="subfinder",
            action="subdomain_enum",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_amass(self, params: dict[str, Any]) -> ActionResult:
        """Execute amass for passive subdomain enumeration."""
        domain = params.get("domain", "")
        if not domain:
            return ActionResult(success=False, tool_name="amass", action="subdomain_enum_passive", data={}, error="No domain provided")

        start = time.time()
        result = await self._registry.execute("amass", "enumerate", {"domain": domain, "passive": True})
        return ActionResult(
            success=result.success,
            tool_name="amass",
            action="subdomain_enum_passive",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_nmap(self, params: dict[str, Any]) -> ActionResult:
        """Execute nmap for port scanning."""
        target = params.get("target", "")
        ports = params.get("ports", "1-1000")
        if not target:
            return ActionResult(success=False, tool_name="nmap", action="port_scan", data={}, error="No target provided")

        start = time.time()
        result = await self._registry.execute("nmap", "scan", {"target": target, "ports": ports})
        return ActionResult(
            success=result.success,
            tool_name="nmap",
            action="port_scan",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_httpx(self, params: dict[str, Any]) -> ActionResult:
        """Execute httpx for HTTP probing."""
        targets = params.get("targets", [])
        if not targets:
            return ActionResult(success=False, tool_name="httpx", action="http_probe", data={}, error="No targets provided")

        start = time.time()
        result = await self._registry.execute("httpx", "probe", {"targets": targets})
        return ActionResult(
            success=result.success,
            tool_name="httpx",
            action="http_probe",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_dnsx(self, params: dict[str, Any]) -> ActionResult:
        """Execute dnsx for DNS enumeration."""
        domain = params.get("domain", "")
        if not domain:
            return ActionResult(success=False, tool_name="dnsx", action="dns_enum", data={}, error="No domain provided")

        start = time.time()
        result = await self._registry.execute("dnsx", "resolve", {"domain": domain})
        return ActionResult(
            success=result.success,
            tool_name="dnsx",
            action="dns_enum",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_katana(self, params: dict[str, Any]) -> ActionResult:
        """Execute katana for web crawling."""
        url = params.get("url", "")
        if not url:
            return ActionResult(success=False, tool_name="katana", action="web_crawl", data={}, error="No URL provided")

        start = time.time()
        result = await self._registry.execute("katana", "crawl", {"url": url, "depth": params.get("depth", 3)})
        return ActionResult(
            success=result.success,
            tool_name="katana",
            action="web_crawl",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_gau(self, params: dict[str, Any]) -> ActionResult:
        """Execute gau for URL harvesting."""
        domain = params.get("domain", "")
        if not domain:
            return ActionResult(success=False, tool_name="gau", action="url_harvest", data={}, error="No domain provided")

        start = time.time()
        result = await self._registry.execute("gau", "fetch", {"domain": domain})
        return ActionResult(
            success=result.success,
            tool_name="gau",
            action="url_harvest",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_waybackurls(self, params: dict[str, Any]) -> ActionResult:
        """Execute waybackurls for historical URL discovery."""
        domain = params.get("domain", "")
        if not domain:
            return ActionResult(success=False, tool_name="waybackurls", action="wayback", data={}, error="No domain provided")

        start = time.time()
        result = await self._registry.execute("waybackurls", "fetch", {"domain": domain})
        return ActionResult(
            success=result.success,
            tool_name="waybackurls",
            action="wayback",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_crtsh(self, params: dict[str, Any]) -> ActionResult:
        """Execute crt.sh certificate transparency lookup."""
        import httpx

        domain = params.get("domain", "")
        if not domain:
            return ActionResult(success=False, tool_name="crtsh", action="cert_transparency", data={}, error="No domain provided")

        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                resp = await client.get(f"https://crt.sh/?q=%25.{domain}&output=json")
                if resp.status_code == 200:
                    data = resp.json()
                    subdomains = set()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower()
                            if sub.endswith(f".{domain}") or sub == domain:
                                subdomains.add(sub)
                    return ActionResult(
                        success=True,
                        tool_name="crtsh",
                        action="cert_transparency",
                        data={"subdomains": sorted(subdomains), "total": len(subdomains)},
                        duration=time.time() - start,
                    )
        except Exception as e:
            pass

        return ActionResult(
            success=False,
            tool_name="crtsh",
            action="cert_transparency",
            data={},
            error="crt.sh lookup failed",
            duration=time.time() - start,
        )

    # ─── Scan Handlers ───────────────────────────────────────────

    async def _execute_nuclei(self, params: dict[str, Any]) -> ActionResult:
        """Execute nuclei for template-based scanning."""
        targets = params.get("targets", [])
        templates = params.get("templates", "")
        severity = params.get("severity", "low,medium,high,critical")

        start = time.time()
        result = await self._registry.execute("nuclei", "scan", {
            "targets": targets,
            "templates": templates,
            "severity": severity,
        })
        return ActionResult(
            success=result.success,
            tool_name="nuclei",
            action="template_scan",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_ffuf_ffuf(self, params: dict[str, Any]) -> ActionResult:
        """Execute ffuf for directory fuzzing."""
        url = params.get("url", "")
        wordlist = params.get("wordlist", "")

        start = time.time()
        result = await self._registry.execute("ffuf", "fuzz_directories", {
            "url": url,
            "wordlist": wordlist,
        })
        return ActionResult(
            success=result.success,
            tool_name="ffuf",
            action="directory_fuzz",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_ffuf_params(self, params: dict[str, Any]) -> ActionResult:
        """Execute ffuf for parameter fuzzing."""
        url = params.get("url", "")
        wordlist = params.get("wordlist", "")

        start = time.time()
        result = await self._registry.execute("ffuf", "fuzz_parameters", {
            "url": url,
            "wordlist": wordlist,
        })
        return ActionResult(
            success=result.success,
            tool_name="ffuf",
            action="parameter_fuzz",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )

    async def _execute_sqlmap(self, params: dict[str, Any]) -> ActionResult:
        """Execute sqlmap for SQL injection testing."""
        url = params.get("url", "")
        data = params.get("data", "")
        technique = params.get("technique", "BEUST")

        start = time.time()
        result = await self._registry.execute("sqlmap", "test", {
            "url": url,
            "data": data,
            "technique": technique,
        })
        return ActionResult(
            success=result.success,
            tool_name="sqlmap",
            action="sql_injection",
            data=result.data,
            error=result.error,
            duration=time.time() - start,
        )
