"""Demogorgon — Autonomous Security Research Agent.

Usage:
    python -m demogorgon                              # Interactive agent (default)
    python -m demogorgon <target>                     # Agent with target
    python -m demogorgon --resume                     # Resume saved session
    python -m demogorgon --session <id>               # Resume specific session
    python -m demogorgon --non-interactive <target>   # Non-interactive mode
    python -m demogorgon setup                        # Configure providers
    python -m demogorgon providers                    # List providers
    python -m demogorgon models                       # List models
    python -m demogorgon web                          # Web control center
    python -m demogorgon doctor                       # Diagnostics
"""

import asyncio
import sys


def main():
    args = sys.argv[1:]

    # ── Default: launch interactive agent ────────────────────────
    if not args:
        from demogorgon.agent.main import AgentMain
        agent = AgentMain()
        asyncio.run(agent.start())
        return

    command = args[0]

    # ── Flag-based routing ───────────────────────────────────────
    if command == "--resume":
        from demogorgon.agent.main import AgentMain
        agent = AgentMain()
        asyncio.run(agent.start_resume())
        return

    if command == "--session":
        session_id = args[1] if len(args) > 1 else ""
        if not session_id:
            print("Usage: demogorgon --session <session-id>")
            return
        from demogorgon.agent.main import AgentMain
        agent = AgentMain()
        asyncio.run(agent.start_resume(session_id=session_id))
        return

    if command == "--non-interactive":
        target = args[1] if len(args) > 1 else ""
        if not target:
            print("Usage: demogorgon --non-interactive <target>")
            return
        from demogorgon.agent.main import AgentMain
        agent = AgentMain()
        asyncio.run(agent.start(target=target, interactive=False))
        return

    if command in ("-h", "--help", "help"):
        _print_help()
        return

    # ── Subcommand routing ──────────────────────────────────────
    if command == "setup":
        _cmd_setup()
    elif command == "providers":
        _cmd_providers()
    elif command == "models":
        _cmd_models(args[1] if len(args) > 1 else None)
    elif command == "web":
        _cmd_web(args[1:] if len(args) > 1 else [])
    elif command == "doctor":
        from demogorgon.cli import cmd_doctor
        asyncio.run(cmd_doctor())
    elif command == "resume":
        from demogorgon.agent.main import AgentMain
        agent = AgentMain()
        asyncio.run(agent.start_resume())
    else:
        # Treat as a target URL — launch agent directly
        target = command
        from demogorgon.agent.main import AgentMain
        agent = AgentMain()
        asyncio.run(agent.start(target=target, interactive=False))


def _cmd_setup():
    """Interactive provider setup wizard."""
    from demogorgon.config.terminal_setup import run_setup_wizard
    asyncio.run(run_setup_wizard())


def _cmd_providers():
    """List configured providers."""
    from demogorgon.config.terminal_setup import print_provider_status
    print_provider_status()


def _cmd_models(provider: str | None):
    """List available models for a provider."""
    from rich.console import Console
    from rich.table import Table
    from demogorgon.config.provider_config import ProviderConfigManager
    from demogorgon.config.model_discovery import discover_models

    console = Console()
    mgr = ProviderConfigManager()

    if not provider:
        # Show models for active provider
        active = mgr.get_active_profile()
        if not active:
            console.print("[red]No provider configured. Run: python -m demogorgon setup[/]")
            return
        provider = active.provider

    profile = mgr.get_profile(provider)
    api_key = profile.api_key if profile else ""
    base_url = profile.base_url if profile else ""

    console.print(f"\n[cyan]Discovering models for {provider}...[/]\n")

    models = asyncio.run(discover_models(provider, api_key, base_url))

    if not models:
        console.print("[yellow]No models found.[/]")
        return

    table = Table(title=f"{provider.title()} Models", show_header=True, header_style="bold")
    table.add_column("#", width=4)
    table.add_column("Model", min_width=30)
    table.add_column("Context", width=12)
    if any(m.get("pricing") for m in models):
        table.add_column("Price", width=14)

    for i, m in enumerate(models[:50], 1):
        ctx = m.get("context_length", 0)
        ctx_str = f"{ctx:,}" if ctx else "?"
        price_str = ""
        if m.get("pricing"):
            p = m["pricing"].get("prompt", 0)
            price_str = f"${p*1e6:.2f}/M" if p else "free"
        table.add_row(str(i), m["id"], ctx_str, price_str)

    console.print(table)
    console.print(f"\n[dim]{len(models)} models total (showing up to 50)[/]")


def _cmd_web(extra_args: list[str]):
    """Start the web control center."""
    try:
        import demogorgon.web
        demogorgon.web.start(["web"] + extra_args)
    except ImportError:
        from rich.console import Console
        console = Console()
        console.print("[red]Web UI not available. Install dependencies:[/]")
        console.print("  pip install fastapi uvicorn websockets")


def _print_help():
    """Print help message."""
    from rich.console import Console
    from rich.panel import Panel

    console = Console()
    help_text = """[bold]DEMOGOORGON[/] — Autonomous Security Research Agent

[bold]Usage:[/]

  python -m demogorgon                     Launch interactive agent
  python -m demogorgon <target>            Hunt a specific target
  python -m demogorgon --resume            Resume saved session
  python -m demogorgon --session <id>      Resume specific session
  python -m demogorgon setup               Configure providers
  python -m demogorgon providers           List configured providers
  python -m demogorgon models [provider]   List available models
  python -m demogorgon web                 Start web control center
  python -m demogorgon doctor              Run diagnostics

[bold]Examples:[/]

  python -m demogorgon
  python -m demogorgon https://lab.local
  python -m demogorgon setup
  python -m demogorgon web"""

    console.print(Panel(help_text, border_style="blue"))


if __name__ == "__main__":
    main()
