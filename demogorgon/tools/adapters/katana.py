"""Katana Adapter — wraps ProjectDiscovery katana for web crawling."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import Tool, ToolCategory, ToolResult, ToolCapability
from ..discovery import discover_tool


class KatanaAdapter(Tool):
    """Katana tool adapter for JavaScript-aware web crawling."""

    @property
    def name(self) -> str:
        return "katana"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.CRAWL

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                name="crawl",
                description="Crawl web applications and extract endpoints",
                input_types=["url"],
                output_types=["endpoints"],
            ),
        ]

    async def discover(self) -> bool:
        info = discover_tool("katana")
        return info.available

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        if action == "crawl":
            return await self._crawl(params)
        return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _crawl(self, params: dict[str, Any]) -> ToolResult:
        """Crawl a target URL."""
        url = params.get("url", "")
        depth = params.get("depth", 3)
        js_crawl = params.get("js_crawl", True)

        if not url:
            return ToolResult(success=False, error="No URL provided")

        info = discover_tool("katana")
        if not info.available:
            return ToolResult(success=False, error="katana not installed")

        try:
            cmd = [info.path, "-u", url, "-silent", "-json", "-d", str(depth)]
            if js_crawl:
                cmd.append("-jc")
            else:
                cmd.append("-nc")

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            endpoints = []
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    endpoints.append({
                        "url": data.get("url", ""),
                        "method": data.get("method", "GET"),
                        "tag": data.get("tag", ""),
                        "source": data.get("source", ""),
                    })
                except json.JSONDecodeError:
                    if line.startswith("http"):
                        endpoints.append({"url": line, "method": "GET", "tag": "", "source": ""})

            return ToolResult(
                success=True,
                data={
                    "endpoints": endpoints,
                    "total": len(endpoints),
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="katana timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
