"""Web Control Center — local web UI for DEMOGORGON.

Provides a browser-based dashboard for:
- Provider configuration
- Engagement creation and management
- Live research monitoring
- Findings and evidence viewing

Usage:
    python -m demogorgon web
    python -m demogorgon web --port 8080
"""

from __future__ import annotations

import sys
import uvicorn


def start(args: list[str] | None = None):
    """Start the web control center."""
    port = 8000
    host = "127.0.0.1"

    # Parse args
    if args:
        for i, arg in enumerate(args):
            if arg == "--port" and i + 1 < len(args):
                port = int(args[i + 1])
            elif arg == "--host" and i + 1 < len(args):
                host = args[i + 1]

    from rich.console import Console
    console = Console()

    console.print()
    console.print("[bold blue]DEMOGOORGON Control Center[/]")
    console.print(f"  Local: [cyan]http://{host}:{port}[/]")
    console.print(f"  Docs:  [cyan]http://{host}:{port}/docs[/]")
    console.print()
    console.print("[dim]Press Ctrl+C to stop[/]")
    console.print()

    uvicorn.run(
        "demogorgon.web.app:app",
        host=host,
        port=port,
        log_level="info",
    )
