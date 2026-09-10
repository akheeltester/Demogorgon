"""Nuclei Bridge — recovered from legacy nuclei_bridge.py.

Wraps nuclei for template-based vulnerability scanning.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sentinel_v2.tools.tool_bus import ToolBus, ToolResult

logger = logging.getLogger("sentinel_v2.nuclei_bridge")


class NucleiBridge:
    def __init__(self, tool_bus: ToolBus):
        self.tool_bus = tool_bus

    async def scan(
        self,
        targets: list[str],
        templates: list[str] | None = None,
        severity: str = "low,medium,high,critical",
        rate_limit: int = 150,
        timeout: float = 600,
    ) -> dict[str, Any]:
        if not self.tool_bus.is_available("nuclei"):
            return {"error": "nuclei not installed", "findings": []}

        args = ["-json", "-silent", "-severity", severity, "-rl", str(rate_limit)]
        for t in targets:
            args.extend(["-u", t])
        if templates:
            for tpl in templates:
                args.extend(["-t", tpl])

        result = await self.tool_bus.execute("nuclei", args, timeout=timeout)
        if not result.success and not result.stdout:
            return {"error": result.stderr or result.error, "findings": []}

        findings = []
        for line in result.stdout.splitlines():
            try:
                finding = json.loads(line)
                findings.append({
                    "template_id": finding.get("template-id", ""),
                    "name": finding.get("info", {}).get("name", ""),
                    "severity": finding.get("info", {}).get("severity", "unknown"),
                    "url": finding.get("matched-at", finding.get("host", "")),
                    "description": finding.get("info", {}).get("description", ""),
                    "matcher_name": finding.get("matcher-name", ""),
                    "type": finding.get("type", ""),
                    "curl": finding.get("curl-command", ""),
                })
            except Exception:
                continue

        return {
            "total": len(findings),
            "findings": findings,
        }

    async def run_template(self, target: str, template: str) -> dict[str, Any]:
        return await self.scan([target], templates=[template])
