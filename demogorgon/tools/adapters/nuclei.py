"""Nuclei Adapter — wraps ProjectDiscovery nuclei for template-based scanning."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import Tool, ToolCategory, ToolResult, ToolCapability
from ..discovery import discover_tool


class NucleiAdapter(Tool):
    """Nuclei tool adapter for template-based vulnerability scanning."""

    @property
    def name(self) -> str:
        return "nuclei"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.SCAN

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                name="scan",
                description="Run nuclei templates against targets",
                input_types=["url", "domain"],
                output_types=["findings"],
            ),
        ]

    async def discover(self) -> bool:
        info = discover_tool("nuclei")
        return info.available

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        if action == "scan":
            return await self._scan(params)
        return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _scan(self, params: dict[str, Any]) -> ToolResult:
        """Run nuclei templates against targets."""
        targets = params.get("targets", [])
        templates = params.get("templates", "")
        severity = params.get("severity", "low,medium,high,critical")

        if not targets:
            return ToolResult(success=False, error="No targets provided")

        info = discover_tool("nuclei")
        if not info.available:
            return ToolResult(success=False, error="nuclei not installed")

        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            input_file = f.name

        try:
            cmd = [info.path, "-l", input_file, "-json", "-silent", "-severity", severity]
            if templates:
                cmd.extend(["-t", templates])

            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=600)

            findings = []
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    findings.append({
                        "template_id": data.get("template-id", ""),
                        "name": data.get("info", {}).get("name", ""),
                        "severity": data.get("info", {}).get("severity", ""),
                        "url": data.get("matched-at", ""),
                        "description": data.get("info", {}).get("description", ""),
                        "matcher_name": data.get("matcher-name", ""),
                        "type": data.get("type", ""),
                        "curl": data.get("curl-command", ""),
                    })
                except json.JSONDecodeError:
                    continue

            return ToolResult(
                success=True,
                data={
                    "findings": findings,
                    "total": len(findings),
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="nuclei timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            import os
            try:
                os.unlink(input_file)
            except Exception:
                pass
