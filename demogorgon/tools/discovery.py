"""Tool Discovery — auto-detects installed security tools on the system.

Discovers tools by checking:
1. PATH (shutil.which)
2. Common installation directories
3. Version output (optional)

Results are cached for fast repeated checks.
"""

from __future__ import annotations

import shutil
import asyncio
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ToolInfo:
    """Information about a discovered tool."""
    name: str
    path: str = ""
    version: str = ""
    available: bool = False
    source: str = ""  # "path", "common_dir", "manual"
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "path": self.path,
            "version": self.version,
            "available": self.available,
            "source": self.source,
            "error": self.error,
        }


# Common installation directories per OS
COMMON_PATHS = {
    "subfinder": [
        "~/go/bin/subfinder",
        "/usr/local/bin/subfinder",
        "/opt/subfinder/subfinder",
    ],
    "httpx": [
        "~/go/bin/httpx",
        "/usr/local/bin/httpx",
        "/opt/httpx/httpx",
    ],
    "nmap": [
        "/usr/bin/nmap",
        "/usr/local/bin/nmap",
        "/opt/nmap/nmap",
    ],
    "nuclei": [
        "~/go/bin/nuclei",
        "/usr/local/bin/nuclei",
        "/opt/nuclei/nuclei",
    ],
    "ffuf": [
        "~/go/bin/ffuf",
        "/usr/local/bin/ffuf",
        "/opt/ffuf/ffuf",
    ],
    "katana": [
        "~/go/bin/katana",
        "/usr/local/bin/katana",
        "/opt/katana/katana",
    ],
    "amass": [
        "~/go/bin/amass",
        "/usr/local/bin/amass",
        "/opt/amass/amass",
    ],
    "dnsx": [
        "~/go/bin/dnsx",
        "/usr/local/bin/dnsx",
        "/opt/dnsx/dnsx",
    ],
    "naabu": [
        "~/go/bin/naabu",
        "/usr/local/bin/naabu",
        "/opt/naabu/naabu",
    ],
    "gau": [
        "~/go/bin/gau",
        "/usr/local/bin/gau",
        "/opt/gau/gau",
    ],
    "waybackurls": [
        "~/go/bin/waybackurls",
        "/usr/local/bin/waybackurls",
    ],
    "sqlmap": [
        "/usr/bin/sqlmap",
        "/usr/local/bin/sqlmap",
        "/opt/sqlmap/sqlmap",
    ],
    "curl": [
        "/usr/bin/curl",
        "/usr/local/bin/curl",
    ],
    "git": [
        "/usr/bin/git",
        "/usr/local/bin/git",
    ],
}


def discover_tool(name: str) -> ToolInfo:
    """Discover a single tool by name.

    Checks PATH first, then common installation directories.
    """
    # Check PATH
    path = shutil.which(name)
    if path:
        return ToolInfo(
            name=name,
            path=path,
            available=True,
            source="path",
        )

    # Check common directories
    for common_path in COMMON_PATHS.get(name, []):
        expanded = Path(common_path).expanduser()
        if expanded.exists():
            return ToolInfo(
                name=name,
                path=str(expanded),
                available=True,
                source="common_dir",
            )

    return ToolInfo(
        name=name,
        available=False,
        error="not found in PATH or common directories",
    )


def discover_all_tools(tool_names: list[str] | None = None) -> dict[str, ToolInfo]:
    """Discover all tools.

    Args:
        tool_names: List of tool names to check. If None, checks all known tools.

    Returns:
        Dict mapping tool name to ToolInfo.
    """
    if tool_names is None:
        tool_names = list(COMMON_PATHS.keys()) + ["curl", "git"]

    results = {}
    for name in tool_names:
        results[name] = discover_tool(name)

    return results


async def get_tool_version(tool_info: ToolInfo) -> str:
    """Get the version of a discovered tool."""
    if not tool_info.available or not tool_info.path:
        return ""

    version_args = {
        "subfinder": ["-version"],
        "httpx": ["-version"],
        "nmap": ["--version"],
        "nuclei": ["-version"],
        "ffuf": ["-V"],
        "katana": ["-version"],
        "amass": ["-version"],
        "dnsx": ["-version"],
        "naabu": ["-version"],
        "gau": ["--version"],
        "sqlmap": ["--version"],
        "curl": ["--version"],
        "git": ["--version"],
    }

    args = version_args.get(tool_info.name, ["--version"])

    try:
        proc = await asyncio.create_subprocess_exec(
            tool_info.path, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
        output = (stdout or stderr or b"").decode(errors="ignore").strip()
        # Take first line only
        return output.split("\n")[0][:200] if output else ""
    except Exception:
        return ""
