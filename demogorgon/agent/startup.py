"""Interactive Startup — provider/model selection UI.

Rich-based interactive prompts for selecting LLM provider, model,
and configuring the agent session before launch.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text

from .session import SessionConfig

console = Console()

PROVIDER_INFO = {
    "openai": {
        "name": "OpenAI",
        "env_key": "OPENAI_API_KEY",
        "models": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "default_model": "gpt-4o-mini",
    },
    "openrouter": {
        "name": "OpenRouter",
        "env_key": "OPENROUTER_API_KEY",
        "models": [
            "nvidia/nemotron-3-super-120b-a12b:free",
            "anthropic/claude-3.5-sonnet",
            "google/gemini-2.0-flash-001",
            "meta-llama/llama-3.1-405b-instruct:free",
        ],
        "default_model": "nvidia/nemotron-3-super-120b-a12b:free",
    },
    "anthropic": {
        "name": "Anthropic",
        "env_key": "ANTHROPIC_API_KEY",
        "models": ["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
        "default_model": "claude-sonnet-4-20250514",
    },
    "gemini": {
        "name": "Google Gemini",
        "env_key": "GEMINI_API_KEY",
        "models": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "default_model": "gemini-2.0-flash",
    },
    "deepseek": {
        "name": "DeepSeek",
        "env_key": "DEEPSEEK_API_KEY",
        "models": ["deepseek-chat", "deepseek-coder"],
        "default_model": "deepseek-chat",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "env_key": "",
        "models": ["llama3.1:8b", "llama3.1:70b", "codellama:34b"],
        "default_model": "llama3.1:8b",
    },
}


def _detect_configured_providers() -> list[str]:
    """Detect which providers have API keys configured."""
    configured = []
    for name, info in PROVIDER_INFO.items():
        env_key = info["env_key"]
        if env_key and os.environ.get(env_key):
            configured.append(name)
        elif name == "ollama":
            # Ollama doesn't need an API key
            configured.append(name)
    return configured


async def interactive_startup() -> SessionConfig:
    """Run the interactive startup wizard.

    Returns a SessionConfig ready for agent launch.
    """
    _print_banner()

    config = SessionConfig()

    # Step 1: Target
    console.print("\n[bold]Target[/bold]")
    target = Prompt.ask(
        "Enter target URL/domain",
        default="",
    )
    if not target:
        console.print("[red]A target is required.[/red]")
        return config
    config.target = target if target.startswith("http") else f"https://{target}"

    # Step 2: Provider selection
    console.print("\n[bold]LLM Provider[/bold]\n")

    configured = _detect_configured_providers()
    providers = list(PROVIDER_INFO.keys())

    table = Table(show_header=True, border_style="cyan")
    table.add_column("#", style="dim")
    table.add_column("Provider", style="bold")
    table.add_column("Status")
    table.add_column("Default Model")

    for i, name in enumerate(providers, 1):
        info = PROVIDER_INFO[name]
        status = "[green]Configured[/green]" if name in configured else "[dim]Not configured[/dim]"
        table.add_row(str(i), info["name"], status, info["default_model"])

    console.print(table)

    choice = Prompt.ask(
        "\nSelect provider",
        choices=[str(i) for i in range(1, len(providers) + 1)],
        default="2" if "openrouter" in configured else "1",
    )
    provider_name = providers[int(choice) - 1]
    config.provider = provider_name

    # Step 3: API key (if needed)
    provider_info = PROVIDER_INFO[provider_name]
    env_key = provider_info["env_key"]

    if env_key and not os.environ.get(env_key):
        console.print(f"\n[yellow]No {env_key} found in environment.[/yellow]")
        api_key = Prompt.ask(f"Enter {provider_info['name']} API key", password=True)
        if api_key:
            os.environ[env_key] = api_key
            config.api_key = api_key

    # Step 4: Model selection
    console.print(f"\n[bold]Model for {provider_info['name']}[/bold]\n")

    models = provider_info["models"]
    for i, model in enumerate(models, 1):
        marker = " (default)" if model == provider_info["default_model"] else ""
        console.print(f"  [{i}] {model}{marker}")

    model_choice = Prompt.ask(
        "Select model",
        choices=[str(i) for i in range(1, len(models) + 1)],
        default="1",
    )
    config.model = models[int(model_choice) - 1]

    # Step 5: Budget
    console.print("\n[bold]Budget Limits[/bold]\n")

    max_cycles = int(Prompt.ask("Max research cycles", default="50"))
    max_cost = float(Prompt.ask("Max cost (USD)", default="2.00"))
    max_requests = int(Prompt.ask("Max HTTP requests", default="200"))

    config.max_cycles = max_cycles
    config.max_cost_usd = max_cost
    config.max_requests = max_requests

    # Step 6: Safety
    console.print("\n[bold]Safety Settings[/bold]\n")

    approval = Prompt.ask(
        "Approval level",
        choices=["none", "required", "for_exploits"],
        default="none",
    )
    config.approval_level = approval

    # Summary
    _print_summary(config)

    return config


def _print_banner():
    """Print the agent startup banner."""
    banner = Text()
    banner.append("╔══════════════════════════════════════════════╗\n", style="bold cyan")
    banner.append("║              DEMOGORGON                      ║\n", style="bold cyan")
    banner.append("║     Interactive Security Research Agent      ║\n", style="bold cyan")
    banner.append("╚══════════════════════════════════════════════╝\n", style="bold cyan")
    console.print(banner)


def _print_summary(config: SessionConfig):
    """Print the session configuration summary."""
    console.print("\n" + "=" * 50)
    console.print("[bold green]Session Configuration[/bold green]\n")

    table = Table(show_header=False, border_style="cyan")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row("Target", config.target)
    table.add_row("Provider", config.provider)
    table.add_row("Model", config.model)
    table.add_row("Max Cycles", str(config.max_cycles))
    table.add_row("Max Cost", f"${config.max_cost_usd:.2f}")
    table.add_row("Max Requests", str(config.max_requests))
    table.add_row("Approval Level", config.approval_level)
    console.print(table)

    console.print("\n[bold yellow]Press Enter to start, or Ctrl+C to cancel.[/bold yellow]")


async def quick_startup(target: str, **kwargs) -> SessionConfig:
    """Quick startup with just a target (for CLI usage).

    Detects provider from environment, uses defaults for everything else.
    """
    from demogorgon.llm.manager import _detect_provider_from_env, _load_env

    env = _load_env()
    provider_name, api_key, base_url, model = _detect_provider_from_env(env)

    config = SessionConfig(
        target=target if target.startswith("http") else f"https://{target}",
        provider=provider_name,
        model=model,
        api_key=api_key,
        base_url=base_url,
        **kwargs,
    )

    return config
