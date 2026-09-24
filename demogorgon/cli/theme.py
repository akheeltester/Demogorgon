"""Shared CLI theme — banner, colors, severity styles for all Demogorgon entry points."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

VERSION = "3.0.0"

DEMO_THEME = Theme(
    {
        "brand": "bold cyan",
        "accent": "cyan",
        "success": "bold green",
        "warning": "yellow",
        "danger": "bold red",
        "muted": "dim",
        "sev.critical": "bold white on red",
        "sev.high": "bold red",
        "sev.medium": "yellow",
        "sev.low": "blue",
        "sev.info": "dim",
        "header": "bold cyan",
    }
)

console = Console(theme=DEMO_THEME)

# Unified severity → rich style map (matches web CSS tokens)
SEVERITY_STYLE = {
    "critical": "bold white on red",
    "high": "bold red",
    "medium": "yellow",
    "low": "blue",
    "info": "dim",
    "unknown": "dim",
}


def sev_style(severity: str) -> str:
    return SEVERITY_STYLE.get(str(severity or "unknown").lower(), "dim")


def sev_badge(severity: str) -> str:
    s = str(severity or "unknown").lower()
    style = sev_style(s)
    return f"[{style}]{s.upper()}[/{style}]"


BANNER_ART = r"""
 ▄▄▄  ▄▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄▄  ▄▄▄
 ███  ███  ███  ███  ███  ███  ███
  '▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀
"""

TAGLINE = "Autonomous Bug Bounty Researcher"


def print_banner(console_: Console | None = None) -> None:
    """Print the unified Demogorgon banner."""
    c = console_ or console
    c.print()
    c.print(
        Panel(
            f"[brand]{BANNER_ART}[/brand]\n"
            f"[bold white]  D E M O G O R G O N[/bold white]  "
            f"[muted]v{VERSION}[/muted]\n"
            f"[accent]  {TAGLINE}[/accent]\n"
            f"[muted]  Authorized testing only — stay in scope[/muted]",
            border_style="cyan",
            padding=(0, 1),
        )
    )
    c.print()


def print_header(title: str, console_: Console | None = None) -> None:
    c = console_ or console
    c.print(f"\n[header]{'━' * 60}[/header]")
    c.print(f"[bold]{title}[/bold]")
    c.print(f"[header]{'━' * 60}[/header]\n")


def info_table(rows: list[tuple[str, str]], title: str = "") -> Table:
    table = Table(show_header=False, border_style="cyan", title=title or None)
    table.add_column("Key", style="bold cyan", min_width=14)
    table.add_column("Value")
    for k, v in rows:
        table.add_row(k, str(v))
    return table


def findings_table(findings: list[dict], title: str = "Findings") -> Table:
    table = Table(show_header=True, border_style="cyan", title=title)
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Title", style="bold", min_width=20, max_width=50)
    table.add_column("Endpoint", max_width=40)
    table.add_column("Confirmed", width=10)
    for i, f in enumerate(findings, 1):
        sev = f.get("severity", "unknown")
        confirmed = "[green]Yes[/green]" if f.get("confirmed") else "[dim]No[/dim]"
        table.add_row(
            str(i),
            sev_badge(sev),
            str(f.get("title", "Untitled"))[:50],
            str(f.get("endpoint", ""))[:40],
            confirmed,
        )
    return table


def status_table(rows: list[tuple[str, str]], title: str = "Status") -> Table:
    table = Table(show_header=False, border_style="cyan", title=title)
    table.add_column("Key", style="bold cyan", min_width=14)
    table.add_column("Value")
    for k, v in rows:
        table.add_row(k, str(v))
    return table
