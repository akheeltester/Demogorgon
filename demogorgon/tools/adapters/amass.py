"""Amass Adapter — wraps OWASP Amass for subdomain enumeration."""

from __future__ import annotations

import asyncio
from typing import Any

from ..base import Tool, ToolCategory, ToolResult, ToolCapability
from ..discovery import discover_tool


class AmassAdapter(Tool):
    """Amass tool adapter for subdomain enumeration."""

    @property
    def name(self) -> str:
        return "amass"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                name="enumerate",
                description="Passive subdomain enumeration",
                input_types=["domain"],
                output_types=["subdomains"],
            ),
        ]

    async def discover(self) -> bool:
        info = discover_tool("amass")
        return info.available

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        if action == "enumerate":
            return await self._enumerate(params)
        return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _enumerate(self, params: dict[str, Any]) -> ToolResult:
        """Enumerate subdomains passively."""
        domain = params.get("domain", "")
        passive = params.get("passive", True)

        if not domain:
            return ToolResult(success=False, error="No domain provided")

        info = discover_tool("amass")
        if not info.available:
            return ToolResult(success=False, error="amass not installed")

        try:
            cmd = [info.path, "enum"]
            if passive:
                cmd.append("-passive")
            cmd.extend(["-d", domain])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            subdomains = set()
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                line = line.strip()
                if line and "." in line and not line.startswith("#"):
                    subdomains.add(line.lower())

            return ToolResult(
                success=True,
                data={
                    "subdomains": sorted(subdomains),
                    "total": len(subdomains),
                    "domain": domain,
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="amass timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
