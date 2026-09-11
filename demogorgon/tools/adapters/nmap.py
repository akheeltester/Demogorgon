"""Nmap Adapter — wraps nmap for port scanning."""

from __future__ import annotations

import asyncio
import json
import xml.etree.ElementTree as ET
from typing import Any

from ..base import Tool, ToolCategory, ToolResult, ToolCapability
from ..discovery import discover_tool


class NmapAdapter(Tool):
    """Nmap tool adapter for port and service scanning."""

    @property
    def name(self) -> str:
        return "nmap"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.SCAN

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                name="scan",
                description="Scan ports and detect services",
                input_types=["domain", "ip", "url"],
                output_types=["ports", "services"],
            ),
        ]

    async def discover(self) -> bool:
        info = discover_tool("nmap")
        return info.available

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        if action == "scan":
            return await self._scan(params)
        return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _scan(self, params: dict[str, Any]) -> ToolResult:
        """Scan target for open ports and services."""
        target = params.get("target", "")
        ports = params.get("ports", "1-1000")
        scan_type = params.get("scan_type", "-sV")  # Version detection

        if not target:
            return ToolResult(success=False, error="No target provided")

        info = discover_tool("nmap")
        if not info.available:
            return ToolResult(success=False, error="nmap not installed")

        # Use XML output for structured parsing
        import tempfile
        output_file = tempfile.mktemp(suffix=".xml")

        try:
            proc = await asyncio.create_subprocess_exec(
                info.path, scan_type, "-p", ports, "-oX", output_file,
                "--open", "-T4", target,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            if proc.returncode != 0:
                error = stderr.decode(errors="ignore").strip()
                return ToolResult(success=False, error=f"nmap failed: {error}")

            # Parse XML output
            ports_found = []
            try:
                tree = ET.parse(output_file)
                root = tree.getroot()

                for host in root.findall(".//host"):
                    for port_elem in host.findall(".//port"):
                        state = port_elem.find("state")
                        if state is not None and state.get("state") == "open":
                            service = port_elem.find("service")
                            ports_found.append({
                                "port": int(port_elem.get("portid", 0)),
                                "protocol": port_elem.get("protocol", "tcp"),
                                "state": "open",
                                "service": service.get("name", "") if service is not None else "",
                                "version": service.get("version", "") if service is not None else "",
                                "product": service.get("product", "") if service is not None else "",
                            })
            except ET.ParseError:
                pass

            return ToolResult(
                success=True,
                data={
                    "ports": ports_found,
                    "total": len(ports_found),
                    "target": target,
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="nmap timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            import os
            try:
                os.unlink(output_file)
            except Exception:
                pass
