"""Amass Bridge — recovered from legacy amass_bridge.py.

Subdomain enumeration via Amass.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sentinel_v2.tools.tool_bus import ToolBus

logger = logging.getLogger("sentinel_v2.amass_bridge")


class AmassBridge:
    def __init__(self, tool_bus: ToolBus):
        self.tool_bus = tool_bus

    async def enumerate(
        self,
        domain: str,
        passive: bool = True,
        timeout: float = 600,
    ) -> dict[str, Any]:
        if not self.tool_bus.is_available("amass"):
            return {"error": "amass not installed", "subdomains": []}

        args = ["enum"]
        if passive:
            args.append("-passive")
        args.extend(["-d", domain])

        result = await self.tool_bus.execute("amass", args, timeout=timeout)
        if not result.success:
            return {"error": result.stderr or result.error, "subdomains": []}

        subdomains = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        return {
            "total": len(subdomains),
            "subdomains": subdomains,
        }
