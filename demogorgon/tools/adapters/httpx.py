"""httpx Adapter — wraps ProjectDiscovery httpx for HTTP probing."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import Tool, ToolCategory, ToolResult, ToolCapability
from ..discovery import discover_tool


class HttpxAdapter(Tool):
    """httpx tool adapter for HTTP probing and technology detection."""

    @property
    def name(self) -> str:
        return "httpx"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.RECON

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                name="probe",
                description="Probe hosts for HTTP services and extract metadata",
                input_types=["domain", "url"],
                output_types=["live_hosts"],
            ),
        ]

    async def discover(self) -> bool:
        info = discover_tool("httpx")
        return info.available

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        if action == "probe":
            return await self._probe(params)
        return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _probe(self, params: dict[str, Any]) -> ToolResult:
        """Probe targets for HTTP services."""
        targets = params.get("targets", [])
        if not targets:
            return ToolResult(success=False, error="No targets provided")

        info = discover_tool("httpx")
        if not info.available:
            return ToolResult(success=False, error="httpx not installed")

        # Write targets to temp file
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("\n".join(targets))
            input_file = f.name

        try:
            proc = await asyncio.create_subprocess_exec(
                info.path, "-l", input_file, "-silent", "-json",
                "-status-code", "-title", "-tech-detect", "-follow-redirects",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)

            live_hosts = []
            for line in stdout.decode(errors="ignore").strip().split("\n"):
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    live_hosts.append({
                        "url": data.get("url", ""),
                        "status_code": data.get("status_code", 0),
                        "title": data.get("title", ""),
                        "tech": data.get("tech", []),
                        "webserver": data.get("webserver", ""),
                        "content_type": data.get("content_type", ""),
                    })
                except json.JSONDecodeError:
                    continue

            return ToolResult(
                success=True,
                data={
                    "live_hosts": live_hosts,
                    "total": len(live_hosts),
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="httpx timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            import os
            try:
                os.unlink(input_file)
            except Exception:
                pass
