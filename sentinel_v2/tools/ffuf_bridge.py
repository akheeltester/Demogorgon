"""FFUF Bridge — recovered from legacy ffuf_bridge.py.

Directory and parameter fuzzing.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sentinel_v2.tools.tool_bus import ToolBus

logger = logging.getLogger("sentinel_v2.ffuf_bridge")


class FfufBridge:
    def __init__(self, tool_bus: ToolBus):
        self.tool_bus = tool_bus

    async def fuzz_directories(
        self,
        target_url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str = "php,html,js,txt",
        threads: int = 40,
        rate_limit: int = 100,
        timeout: float = 300,
    ) -> dict[str, Any]:
        if not self.tool_bus.is_available("ffuf"):
            return {"error": "ffuf not installed", "findings": []}

        url = target_url.rstrip("/") + "/FUZZ"
        args = [
            "-u", url,
            "-w", wordlist,
            "-e", f".{extensions}" if not extensions.startswith(".") else extensions,
            "-t", str(threads),
            "-rate", str(rate_limit),
            "-mc", "200,201,204,301,302,307,401,403,405",
            "-o", "/tmp/ffuf_output.json",
            "-of", "json",
            "-s",
        ]

        result = await self.tool_bus.execute("ffuf", args, timeout=timeout)
        return self._parse_output("/tmp/ffuf_output.json")

    async def fuzz_parameters(
        self,
        target_url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        method: str = "GET",
        threads: int = 40,
        timeout: float = 300,
    ) -> dict[str, Any]:
        if not self.tool_bus.is_available("ffuf"):
            return {"error": "ffuf not installed", "findings": []}

        separator = "&" if "?" in target_url else "?"
        url = f"{target_url}{separator}FUZZ=FUZZ"
        args = [
            "-u", url,
            "-w", wordlist,
            "-X", method,
            "-t", str(threads),
            "-mc", "200,201,204,301,302,307,401,403",
            "-o", "/tmp/ffuf_param_output.json",
            "-of", "json",
            "-s",
        ]

        result = await self.tool_bus.execute("ffuf", args, timeout=timeout)
        return self._parse_output("/tmp/ffuf_param_output.json")

    def _parse_output(self, output_file: str) -> dict[str, Any]:
        try:
            with open(output_file) as f:
                data = json.load(f)
            findings = []
            for result in data.get("results", []):
                findings.append({
                    "url": result.get("url", ""),
                    "status": result.get("status", 0),
                    "length": result.get("length", 0),
                    "words": result.get("words", 0),
                    "lines": result.get("lines", 0),
                    "input": result.get("input", {}),
                    "redirectlocation": result.get("redirectlocation", ""),
                })
            return {"total": len(findings), "findings": findings}
        except Exception as e:
            return {"error": str(e), "findings": []}
