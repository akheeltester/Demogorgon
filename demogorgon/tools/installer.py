"""Tool Installer — installs missing security tools (subfinder, httpx, etc.).

Uses `go install` for ProjectDiscovery tools, apt/brew for system packages.
Never installs without checking availability first. Idempotent.
"""

from __future__ import annotations

import asyncio
import shutil
from dataclasses import dataclass, field
from typing import Any

from demogorgon.tools.discovery import discover_tool, discover_all_tools


# Tool → install recipe
INSTALL_RECIPES: dict[str, dict[str, Any]] = {
    "subfinder": {
        "go": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "apt": None,
        "priority": 1,
        "description": "Passive subdomain enumeration",
    },
    "httpx": {
        "go": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "apt": None,
        "priority": 1,
        "description": "HTTP prober / live host detection",
    },
    "nuclei": {
        "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "apt": None,
        "priority": 1,
        "description": "Vulnerability scanner with templates",
    },
    "katana": {
        "go": "github.com/projectdiscovery/katana/cmd/katana@latest",
        "apt": None,
        "priority": 2,
        "description": "Web crawler",
    },
    "ffuf": {
        "go": "github.com/ffuf/ffuf/v2@latest",
        "apt": "ffuf",
        "priority": 1,
        "description": "Directory / parameter fuzzer",
    },
    "amass": {
        "go": "github.com/owasp-amass/amass/v4/...@master",
        "apt": "amass",
        "priority": 2,
        "description": "Attack surface mapping",
    },
    "dnsx": {
        "go": "github.com/projectdiscovery/dnsx/cmd/dnsx@latest",
        "apt": None,
        "priority": 3,
        "description": "DNS toolkit",
    },
    "naabu": {
        "go": "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest",
        "apt": None,
        "priority": 3,
        "description": "Port scanner",
    },
    "nmap": {
        "go": None,
        "apt": "nmap",
        "priority": 1,
        "description": "Network mapper",
    },
    "sqlmap": {
        "go": None,
        "apt": "sqlmap",
        "priority": 2,
        "description": "SQL injection automation",
    },
}


@dataclass
class InstallResult:
    tool: str
    status: str  # "already_installed", "installed", "failed", "skipped"
    method: str = ""
    message: str = ""
    path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool,
            "status": self.status,
            "method": self.method,
            "message": self.message,
            "path": self.path,
        }


@dataclass
class ToolInstaller:
    """Installs missing tools using go/apt/brew as available."""

    use_go: bool = True
    use_apt: bool = True
    results: list[InstallResult] = field(default_factory=list)

    def missing_tools(self, tool_names: list[str] | None = None) -> list[str]:
        """Return list of tools that are not currently installed."""
        names = tool_names or list(INSTALL_RECIPES.keys())
        return [n for n in names if not discover_tool(n).available]

    def status_report(self, tool_names: list[str] | None = None) -> list[dict[str, Any]]:
        """Return availability for all (or given) tools."""
        infos = discover_all_tools(tool_names or list(INSTALL_RECIPES.keys()))
        report = []
        for name, info in infos.items():
            recipe = INSTALL_RECIPES.get(name, {})
            report.append({
                "tool": name,
                "available": info.available,
                "path": info.path,
                "description": recipe.get("description", ""),
                "installable": bool(recipe.get("go") or recipe.get("apt")),
            })
        return report

    async def install(
        self,
        tool_name: str,
        force: bool = False,
        timeout: float = 300.0,
    ) -> InstallResult:
        """Install a single tool. Returns InstallResult."""
        if not force:
            info = discover_tool(tool_name)
            if info.available:
                result = InstallResult(
                    tool=tool_name,
                    status="already_installed",
                    path=info.path,
                    message="Already on PATH",
                )
                self.results.append(result)
                return result

        recipe = INSTALL_RECIPES.get(tool_name)
        if not recipe:
            result = InstallResult(
                tool=tool_name,
                status="failed",
                message="No install recipe for this tool",
            )
            self.results.append(result)
            return result

        # Try go install first (preferred for ProjectDiscovery tools)
        if recipe.get("go") and self.use_go and shutil.which("go"):
            result = await self._go_install(tool_name, recipe["go"], timeout)
            if result.status == "installed":
                self.results.append(result)
                return result

        # Fallback to apt
        if recipe.get("apt") and self.use_apt and shutil.which("apt-get"):
            result = await self._apt_install(tool_name, recipe["apt"], timeout)
            if result.status == "installed":
                self.results.append(result)
                return result

        # Fallback to brew (macOS)
        if recipe.get("apt") and shutil.which("brew"):
            result = await self._brew_install(tool_name, recipe["apt"], timeout)
            self.results.append(result)
            return result

        result = InstallResult(
            tool=tool_name,
            status="failed",
            message="No available install method (need go, apt, or brew)",
        )
        self.results.append(result)
        return result

    async def install_missing(
        self,
        tool_names: list[str] | None = None,
        only_priority: int | None = None,
    ) -> list[InstallResult]:
        """Install all missing tools (optionally filtered by priority)."""
        names = tool_names or list(INSTALL_RECIPES.keys())
        if only_priority is not None:
            names = [
                n for n in names
                if INSTALL_RECIPES.get(n, {}).get("priority", 99) <= only_priority
            ]

        missing = [n for n in names if not discover_tool(n).available]
        results = []
        for name in missing:
            r = await self.install(name)
            results.append(r)
        return results

    async def _go_install(self, tool: str, pkg: str, timeout: float) -> InstallResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                "go", "install", pkg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)

            # Verify after install (go puts binary in ~/go/bin or GOBIN)
            info = discover_tool(tool)
            if info.available or proc.returncode == 0:
                # Re-discover with common paths
                info = discover_tool(tool)
                return InstallResult(
                    tool=tool,
                    status="installed" if info.available else "failed",
                    method="go",
                    path=info.path,
                    message=(stderr.decode(errors="ignore") if proc.returncode else "ok"),
                )
            return InstallResult(
                tool=tool,
                status="failed",
                method="go",
                message=stderr.decode(errors="ignore")[:500],
            )
        except asyncio.TimeoutError:
            return InstallResult(tool=tool, status="failed", method="go", message="timeout")
        except FileNotFoundError:
            return InstallResult(tool=tool, status="failed", method="go", message="go not found")
        except Exception as e:
            return InstallResult(tool=tool, status="failed", method="go", message=str(e))

    async def _apt_install(self, tool: str, pkg: str, timeout: float) -> InstallResult:
        try:
            # apt-get needs root for system install; try user-level first
            proc = await asyncio.create_subprocess_exec(
                "sudo", "apt-get", "install", "-y", pkg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            info = discover_tool(tool)
            return InstallResult(
                tool=tool,
                status="installed" if info.available else "failed",
                method="apt",
                path=info.path,
                message="ok" if info.available else stderr.decode(errors="ignore")[:500],
            )
        except Exception as e:
            return InstallResult(tool=tool, status="failed", method="apt", message=str(e))

    async def _brew_install(self, tool: str, pkg: str, timeout: float) -> InstallResult:
        try:
            proc = await asyncio.create_subprocess_exec(
                "brew", "install", pkg,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            info = discover_tool(tool)
            return InstallResult(
                tool=tool,
                status="installed" if info.available else "failed",
                method="brew",
                path=info.path,
                message="ok" if info.available else stderr.decode(errors="ignore")[:500],
            )
        except Exception as e:
            return InstallResult(tool=tool, status="failed", method="brew", message=str(e))

    def summary(self) -> dict[str, Any]:
        counts: dict[str, int] = {}
        for r in self.results:
            counts[r.status] = counts.get(r.status, 0) + 1
        return {"total_attempted": len(self.results), "by_status": counts}


def create_tool_installer() -> ToolInstaller:
    return ToolInstaller()
