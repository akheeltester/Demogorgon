"""Subfinder Adapter — wraps ProjectDiscovery subfinder for subdomain enumeration."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import Tool, ToolCategory, ToolResult, ToolCapability
from ..discovery import discover_tool


class SubfinderAdapter(Tool):
    """Subfinder tool adapter for subdomain enumeration."""

    @property
    def name(self) -> str:
        return "subfinder"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                name="enumerate_subdomains",
                description="Discover subdomains using passive sources",
                input_types=["domain"],
                output_types=["subdomains"],
            ),
        ]

    async def discover(self) -> bool:
        """Check if subfinder is installed."""
        info = discover_tool("subfinder")
        return info.available

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        """Execute a subfinder action."""
        if action == "enumerate":
            return await self._enumerate(params)
        return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _enumerate(self, params: dict[str, Any]) -> ToolResult:
        """Enumerate subdomains for a domain."""
        domain = params.get("domain", "")
        if not domain:
            return ToolResult(success=False, error="No domain provided")

        info = discover_tool("subfinder")
        if not info.available:
            return ToolResult(success=False, error="subfinder not installed")

        try:
            proc = await asyncio.create_subprocess_exec(
                info.path, "-d", domain, "-silent", "-json",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            if proc.returncode != 0:
                error = stderr.decode(errors="ignore").strip()
                return ToolResult(success=False, error=f"subfinder failed: {error}")

            subdomains = set()
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    host = data.get("host", "")
                    if host:
                        subdomains.add(host)
                except json.JSONDecodeError:
                    if "." in line:
                        subdomains.add(line.strip())

            return ToolResult(
                success=True,
                data={
                    "subdomains": sorted(subdomains),
                    "total": len(subdomains),
                    "domain": domain,
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="subfinder timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
