"""Tool Execution Bus — recovered from legacy tool_execution_bus.py.

Subprocess execution backbone for external security tools.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger("sentinel_v2.tool_bus")


@dataclass
class ToolResult:
    tool: str
    command: str
    return_code: int
    stdout: str
    stderr: str
    parsed: Any = None
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.return_code == 0 and self.error is None


class ToolBus:
    def __init__(self, timeout: float = 300.0):
        self.timeout = timeout
        self._tools: dict[str, str] = {}
        self._register_defaults()

    def _register_defaults(self):
        for tool in ["nuclei", "ffuf", "sqlmap", "amass", "katana", "httpx", "subfinder"]:
            path = shutil.which(tool)
            if path:
                self._tools[tool] = path
                logger.info(f"Found {tool} at {path}")

    def register(self, name: str, path: str) -> None:
        self._tools[name] = path

    def is_available(self, name: str) -> bool:
        return name in self._tools

    async def execute(
        self,
        tool: str,
        args: list[str],
        stdin_data: str | None = None,
        timeout: float | None = None,
    ) -> ToolResult:
        if tool not in self._tools:
            return ToolResult(
                tool=tool,
                command="",
                return_code=-1,
                stdout="",
                stderr=f"Tool '{tool}' not found. Available: {list(self._tools.keys())}",
                error="tool_not_found",
            )

        cmd = [self._tools[tool]] + args
        cmd_str = " ".join(cmd)
        effective_timeout = timeout or self.timeout

        logger.debug(f"Executing: {cmd_str}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=asyncio.subprocess.PIPE if stdin_data else None,
            )

            try:
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(
                        input=stdin_data.encode() if stdin_data else None
                    ),
                    timeout=effective_timeout,
                )
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                return ToolResult(
                    tool=tool,
                    command=cmd_str,
                    return_code=-1,
                    stdout="",
                    stderr=f"Timeout after {effective_timeout}s",
                    error="timeout",
                )

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")
            return_code = process.returncode or 0

            return ToolResult(
                tool=tool,
                command=cmd_str,
                return_code=return_code,
                stdout=stdout_str,
                stderr=stderr_str,
            )

        except FileNotFoundError:
            return ToolResult(
                tool=tool,
                command=cmd_str,
                return_code=-1,
                stdout="",
                stderr=f"Binary not found: {self._tools.get(tool)}",
                error="not_found",
            )
        except Exception as e:
            return ToolResult(
                tool=tool,
                command=cmd_str,
                return_code=-1,
                stdout="",
                stderr=str(e),
                error=str(e),
            )
