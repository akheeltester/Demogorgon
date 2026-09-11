"""Ffuf Adapter — wraps ffuf for directory and parameter fuzzing."""

from __future__ import annotations

import asyncio
import json
from typing import Any

from ..base import Tool, ToolCategory, ToolResult, ToolCapability
from ..discovery import discover_tool


class FfufAdapter(Tool):
    """Ffuf tool adapter for directory and parameter fuzzing."""

    @property
    def name(self) -> str:
        return "ffuf"

    @property
    def category(self) -> ToolCategory:
        return ToolCategory.FUZZ

    @property
    def capabilities(self) -> list[ToolCapability]:
        return [
            ToolCapability(
                name="fuzz_directories",
                description="Fuzz for directories and files",
                input_types=["url"],
                output_types=["directories"],
            ),
            ToolCapability(
                name="fuzz_parameters",
                description="Fuzz for parameters",
                input_types=["url"],
                output_types=["parameters"],
            ),
        ]

    async def discover(self) -> bool:
        info = discover_tool("ffuf")
        return info.available

    async def execute(self, action: str, params: dict[str, Any]) -> ToolResult:
        if action == "fuzz_directories":
            return await self._fuzz_directories(params)
        elif action == "fuzz_parameters":
            return await self._fuzz_parameters(params)
        return ToolResult(success=False, error=f"Unknown action: {action}")

    async def _fuzz_directories(self, params: dict[str, Any]) -> ToolResult:
        """Fuzz for directories."""
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

        if not url:
            return ToolResult(success=False, error="No URL provided")

        info = discover_tool("ffuf")
        if not info.available:
            return ToolResult(success=False, error="ffuf not installed")

        # Ensure URL has FUZZ placeholder
        if not url.endswith("/"):
            url += "/"
        url += "FUZZ"

        import tempfile
        output_file = tempfile.mktemp(suffix=".json")

        try:
            proc = await asyncio.create_subprocess_exec(
                info.path, "-u", url, "-w", wordlist, "-o", output_file,
                "-of", "json", "-mc", "200,201,204,301,302,307,401,403,405",
                "-s", "-timeout", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            findings = []
            try:
                with open(output_file) as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        findings.append({
                            "url": result.get("url", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "words": result.get("words", 0),
                            "input": result.get("input", {}),
                            "redirectlocation": result.get("redirectlocation", ""),
                        })
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            return ToolResult(
                success=True,
                data={
                    "findings": findings,
                    "total": len(findings),
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="ffuf timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            import os
            try:
                os.unlink(output_file)
            except Exception:
                pass

    async def _fuzz_parameters(self, params: dict[str, Any]) -> ToolResult:
        """Fuzz for parameters."""
        url = params.get("url", "")
        wordlist = params.get("wordlist", "/usr/share/wordlists/dirb/common.txt")

        if not url:
            return ToolResult(success=False, error="No URL provided")

        info = discover_tool("ffuf")
        if not info.available:
            return ToolResult(success=False, error="ffuf not installed")

        # Add FUZZ parameter
        separator = "&" if "?" in url else "?"
        fuzz_url = f"{url}{separator}FUZZ=FUZZ"

        import tempfile
        output_file = tempfile.mktemp(suffix=".json")

        try:
            proc = await asyncio.create_subprocess_exec(
                info.path, "-u", fuzz_url, "-w", wordlist, "-o", output_file,
                "-of", "json", "-mc", "200,201,204,301,302,307,401,403,405",
                "-s", "-timeout", "10",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)

            findings = []
            try:
                with open(output_file) as f:
                    data = json.load(f)
                    for result in data.get("results", []):
                        findings.append({
                            "url": result.get("url", ""),
                            "status": result.get("status", 0),
                            "length": result.get("length", 0),
                            "input": result.get("input", {}),
                        })
            except (FileNotFoundError, json.JSONDecodeError):
                pass

            return ToolResult(
                success=True,
                data={
                    "findings": findings,
                    "total": len(findings),
                },
            )
        except asyncio.TimeoutError:
            return ToolResult(success=False, error="ffuf timed out")
        except Exception as e:
            return ToolResult(success=False, error=str(e))
        finally:
            import os
            try:
                os.unlink(output_file)
            except Exception:
                pass
