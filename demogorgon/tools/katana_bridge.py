"""Katana Bridge — recovered from legacy katana_bridge.py.

JavaScript-aware web crawler.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from demogorgon.tools.tool_bus import ToolBus

logger = logging.getLogger("demogorgon.katana_bridge")


class KatanaBridge:
    def __init__(self, tool_bus: ToolBus):
        self.tool_bus = tool_bus

    async def crawl(
        self,
        target_url: str,
        depth: int = 3,
        js_crawl: bool = True,
        timeout: float = 300,
    ) -> dict[str, Any]:
        if not self.tool_bus.is_available("katana"):
            return {"error": "katana not installed", "endpoints": []}

        args = [
            "-u", target_url,
            "-d", str(depth),
            "-jc" if js_crawl else "-nc",
            "-json",
            "-silent",
            "-timeout", "30",
        ]

        result = await self.tool_bus.execute("katana", args, timeout=timeout)
        if not result.success and not result.stdout:
            return {"error": result.stderr or result.error, "endpoints": []}

        endpoints = []
        for line in result.stdout.splitlines():
            try:
                entry = json.loads(line)
                endpoints.append({
                    "url": entry.get("url", ""),
                    "method": entry.get("method", "GET"),
                    "tag": entry.get("tag", ""),
                    "source": entry.get("source", ""),
                })
            except Exception:
                continue

        return {
            "total": len(endpoints),
            "endpoints": endpoints,
        }

    async def extract_endpoints(self, target_url: str) -> list[str]:
        result = await self.crawl(target_url)
        return [ep["url"] for ep in result.get("endpoints", []) if ep.get("url")]
