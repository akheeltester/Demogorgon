"""Interactive Startup — provider/model selection UI.

Rich-based interactive prompts for selecting LLM provider, model,
and configuring the agent session before launch.

Integrates with ProviderConfigManager for persistent credential storage
and ModelDiscovery for dynamic model listing.
"""

from __future__ import annotations

import asyncio
import os
import time
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
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o-mini",
    },
    "openrouter": {
        "name": "OpenRouter",
        "env_key": "OPENROUTER_API_KEY",
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "nvidia/nemotron-3-super-120b-a12b:free",
    },
    "anthropic": {
        "name": "Anthropic",
        "env_key": "ANTHROPIC_API_KEY",
        "base_url": "https://api.anthropic.com",
        "default_model": "claude-sonnet-4-20250514",
    },
    "gemini": {
        "name": "Google Gemini",
        "env_key": "GEMINI_API_KEY",
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "default_model": "gemini-2.0-flash",
    },
    "deepseek": {
        "name": "DeepSeek",
        "env_key": "DEEPSEEK_API_KEY",
        "base_url": "https://api.deepseek.com/v1",
        "default_model": "deepseek-chat",
    },
    "ollama": {
        "name": "Ollama (Local)",
        "env_key": "",
        "base_url": "http://localhost:11434/v1",
        "default_model": "llama3.1:8b",
    },
}

PROVIDER_ORDER = ["openrouter", "openai", "anthropic", "gemini", "deepseek", "ollama"]


def _detect_configured_providers() -> list[str]:
    """Detect which providers have API keys configured."""
    configured = []
    for name in PROVIDER_ORDER:
        info = PROVIDER_INFO[name]
        env_key = info["env_key"]
        if env_key and os.environ.get(env_key):
            configured.append(name)
        elif name == "ollama":
            configured.append(name)
    return configured


def _load_saved_config() -> SessionConfig | None:
    """Try to load a previously saved provider configuration."""
    try:
        from ..config.provider_config import ProviderConfigManager
        mgr = ProviderConfigManager()
        active = mgr.get_active_profile()
        if active and active.has_key:
            config = SessionConfig(
                provider=active.provider,
                model=active.selected_model,
                api_key=active.api_key,
                base_url=active.base_url,
            )
            return config
    except Exception:
        pass
    return None


def _save_provider_config(provider: str, api_key: str, model: str, base_url: str = "") -> None:
    """Save provider configuration persistently."""
    try:
        from ..config.provider_config import ProviderConfigManager, ProviderProfile
        mgr = ProviderConfigManager()
        profile = ProviderProfile(
            provider=provider,
            api_key=api_key,
            selected_model=model,
            base_url=base_url or PROVIDER_INFO.get(provider, {}).get("base_url", ""),
        )
        mgr.save_profile(profile)
        mgr.set_active_provider(provider)
        mgr.load_into_environment(provider)
    except Exception as e:
        console.print(f"[dim]Note: Could not save config persistently: {e}[/dim]")


def _discover_models_for_provider(provider: str, api_key: str, base_url: str = "") -> list[dict]:
    """Discover available models for a provider. Returns list of {id, name}."""
    import concurrent.futures
    try:
        from ..config.model_discovery import discover_models

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, discover_models(provider, api_key, base_url))
                return future.result(timeout=15)
        else:
            return asyncio.run(discover_models(provider, api_key, base_url))
    except Exception:
        return []


def _test_connection(provider: str, api_key: str, base_url: str = "") -> dict:
    """Test provider connection. Returns {success, error, latency_ms}."""
    import concurrent.futures
    try:
        from ..config.model_discovery import test_provider_connection

        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            loop = None

        if loop and loop.is_running():
            with concurrent.futures.ThreadPoolExecutor() as pool:
                future = pool.submit(asyncio.run, test_provider_connection(provider, api_key, base_url))
                return future.result(timeout=15)
        else:
            return asyncio.run(test_provider_connection(provider, api_key, base_url))
    except Exception as e:
        return {"success": False, "error": str(e)}


async def interactive_startup() -> SessionConfig:
    """Run the interactive startup wizard.

    Returns a SessionConfig ready for agent launch.
    """
    _print_banner()

    # Check for existing saved config
    saved = _load_saved_config()
    if saved and saved.provider:
        info = PROVIDER_INFO.get(saved.provider, {})
        console.print(f"\n[dim]Found saved config: {info.get('name', saved.provider)} / {saved.model}[/dim]")
        if Confirm.ask("Use saved configuration?", default=True):
            # Still need target
            target = _ask_target()
            if not target:
                return saved
            saved.target = target
            _print_summary(saved)
            return saved

    config = SessionConfig()

    # Step 1: Target (always ask)
    target = _ask_target()
    if not target:
        return config
    config.target = target

    # Step 2: Provider selection
    config = await _ask_provider(config)

    # Step 3: Budget (quick)
    config = _ask_budget(config)

    # Summary
    _print_summary(config)

    return config


async def hunt_startup(target: str = "") -> SessionConfig:
    """Hunt-style startup: target first, then provider if needed.

    Used when user types: demogorgon <target> or hunt <target>
    """
    if not _is_configured():
        # No provider configured — full wizard
        return await interactive_startup()

    # Provider is configured, just need target
    config = _load_saved_config() or SessionConfig()

    if not target:
        target = _ask_target()
    else:
        config.target = target if target.startswith("http") else f"https://{target}"

    if not config.target:
        return config

    _print_summary(config)
    return config


def _is_configured() -> bool:
    """Check if any provider is configured (env or saved)."""
    if _detect_configured_providers():
        return True
    saved = _load_saved_config()
    return saved is not None and saved.provider is not None


def _ask_target() -> str:
    """Ask user for target URL/domain."""
    console.print("\n[bold]Target[/bold]")
    target = Prompt.ask(
        "Enter target URL/domain (or 'paste' to load program policy)",
        default="",
    )

    if not target:
        console.print("[red]A target is required.[/red]")
        return ""

    if target.lower() == "paste":
        return _handle_program_paste()

    return target if target.startswith("http") else f"https://{target}"


def _handle_program_paste() -> str:
    """Handle pasting a bug bounty program policy."""
    console.print("\n[bold]Paste the complete program guidelines.[/bold]")
    console.print("Type [cyan]END[/cyan] on a new line when finished.\n")

    lines = []
    while True:
        try:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        except EOFError:
            break

    if not lines:
        console.print("[red]No program text provided.[/red]")
        return ""

    program_text = "\n".join(lines)

    # Parse the program
    try:
        from demogorgon.core.scope.parser import parse_program_policy
        policy = parse_program_policy(program_text)

        console.print("\n[bold green]Program Parsed[/bold green]\n")

        table = Table(show_header=False, border_style="cyan")
        table.add_column("Key", style="bold")
        table.add_column("Value")
        table.add_row("Program", policy.program_name)
        table.add_row("Platform", policy.platform)
        table.add_row("In-Scope Assets", str(len(policy.in_scope)))
        table.add_row("Out-of-Scope Assets", str(len(policy.out_of_scope)))
        table.add_row("Restrictions", str(len(policy.restrictions)))
        console.print(table)

        if policy.in_scope:
            console.print("\n[bold]In-Scope:[/bold]")
            for asset in policy.in_scope[:10]:
                console.print(f"  • {asset.pattern} ({asset.asset_type})")
            if len(policy.in_scope) > 10:
                console.print(f"  ... and {len(policy.in_scope) - 10} more")

        if Confirm.ask("\nUse this scope?", default=True):
            # Return first in-scope asset as target
            if policy.in_scope:
                first = policy.in_scope[0].pattern
                return first if first.startswith("http") else f"https://{first}"
    except Exception as e:
        console.print(f"[yellow]Could not parse program: {e}[/yellow]")

    return Prompt.ask("Enter target URL/domain")


async def _ask_provider(config: SessionConfig) -> SessionConfig:
    """Ask user to select and configure an LLM provider."""
    console.print("\n[bold]LLM Provider[/bold]\n")

    configured = _detect_configured_providers()

    table = Table(show_header=True, border_style="cyan")
    table.add_column("#", style="dim")
    table.add_column("Provider", style="bold")
    table.add_column("Status")
    table.add_column("Default Model")

    for i, name in enumerate(PROVIDER_ORDER, 1):
        info = PROVIDER_INFO[name]
        status = "[green]Configured[/green]" if name in configured else "[dim]Not configured[/dim]"
        table.add_row(str(i), info["name"], status, info["default_model"])

    console.print(table)

    # Default to first configured provider, or OpenRouter
    default_choice = "1"
    if configured:
        default_idx = PROVIDER_ORDER.index(configured[0]) + 1
        default_choice = str(default_idx)

    choice = Prompt.ask(
        "\nSelect provider",
        choices=[str(i) for i in range(1, len(PROVIDER_ORDER) + 1)],
        default=default_choice,
    )
    provider_name = PROVIDER_ORDER[int(choice) - 1]
    config.provider = provider_name

    provider_info = PROVIDER_INFO[provider_name]
    env_key = provider_info["env_key"]
    base_url = provider_info["base_url"]

    # Step 3: API key (if needed)
    api_key = ""
    if env_key:
        api_key = os.environ.get(env_key, "")
        if not api_key:
            console.print(f"\n[yellow]No {env_key} found in environment.[/yellow]")
            api_key = Prompt.ask(f"Enter {provider_info['name']} API key", password=True)
            if api_key:
                os.environ[env_key] = api_key
                config.api_key = api_key
        else:
            config.api_key = api_key
            console.print(f"[green]Using existing {env_key}[/green]")

    # Test connection
    console.print("\n[cyan]Testing connection...[/cyan]")
    result = _test_connection(provider_name, api_key, base_url)
    if result.get("success"):
        latency = result.get("latency_ms", 0)
        console.print(f"[green]✓ Connection successful[/green] ({latency:.0f}ms)")
    else:
        error = result.get("error", "unknown error")
        console.print(f"[red]✗ Connection failed: {error}[/red]")
        if not Confirm.ask("Continue anyway?", default=False):
            return await _ask_provider(config)  # Re-ask

    # Step 4: Model selection with dynamic discovery
    config = await _ask_model(config, provider_name, api_key, base_url)

    return config


async def _ask_model(
    config: SessionConfig,
    provider: str,
    api_key: str,
    base_url: str,
) -> SessionConfig:
    """Ask user to select a model, with dynamic discovery."""
    console.print(f"\n[bold]Model for {PROVIDER_INFO[provider]['name']}[/bold]\n")

    # Try dynamic model discovery
    console.print("[dim]Discovering available models...[/dim]")
    discovered = _discover_models_for_provider(provider, api_key, base_url)

    if discovered:
        console.print(f"[green]✓ Found {len(discovered)} models[/green]\n")

        # Show top models in a table
        table = Table(show_header=True, border_style="cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Model", min_width=30)
        table.add_column("Context", width=10)
        if any(m.get("pricing") for m in discovered):
            table.add_column("Price", width=14)

        for i, m in enumerate(discovered[:20], 1):
            ctx = m.get("context_length", 0)
            ctx_str = f"{ctx // 1024}K" if ctx else "?"
            price_str = ""
            if m.get("pricing"):
                p = m["pricing"].get("prompt", 0)
                price_str = f"${p * 1e6:.2f}/M" if p else "free"
            table.add_row(str(i), m["id"], ctx_str, price_str)

        if len(discovered) > 20:
            table.add_row("...", f"{len(discovered) - 20} more", "", "")

        console.print(table)

        choice = Prompt.ask(
            "Select model (number or type custom model name)",
            default="1",
        )

        if choice.isdigit() and 1 <= int(choice) <= len(discovered):
            config.model = discovered[int(choice) - 1]["id"]
        else:
            config.model = choice
    else:
        # Fallback: show static list
        console.print("[yellow]Dynamic discovery unavailable, showing defaults[/yellow]\n")
        default_models = _get_default_models(provider)
        for i, model in enumerate(default_models, 1):
            marker = " (default)" if model == PROVIDER_INFO[provider]["default_model"] else ""
            console.print(f"  [{i}] {model}{marker}")

        model_choice = Prompt.ask(
            "Select model (number or type custom)",
            default="1",
        )

        if model_choice.isdigit() and 1 <= int(model_choice) <= len(default_models):
            config.model = default_models[int(model_choice) - 1]
        else:
            config.model = model_choice

    # Save the configuration
    _save_provider_config(provider, api_key, config.model, base_url)

    return config


def _get_default_models(provider: str) -> list[str]:
    """Get default model list for a provider."""
    defaults = {
        "openai": ["gpt-4o", "gpt-4o-mini", "gpt-4-turbo", "gpt-3.5-turbo"],
        "openrouter": [
            "nvidia/nemotron-3-super-120b-a12b:free",
            "anthropic/claude-3.5-sonnet",
            "google/gemini-2.0-flash-001",
            "meta-llama/llama-3.1-405b-instruct:free",
        ],
        "anthropic": ["claude-sonnet-4-20250514", "claude-3-5-sonnet-20241022", "claude-3-5-haiku-20241022"],
        "gemini": ["gemini-2.0-flash", "gemini-1.5-pro", "gemini-1.5-flash"],
        "deepseek": ["deepseek-chat", "deepseek-coder"],
        "ollama": ["llama3.1:8b", "llama3.1:70b", "codellama:34b"],
    }
    return defaults.get(provider, ["default"])


def _ask_budget(config: SessionConfig) -> SessionConfig:
    """Ask user for budget limits (with sensible defaults)."""
    console.print("\n[bold]Budget[/bold] (press Enter for defaults)\n")

    max_cycles = Prompt.ask("Max research cycles", default="50")
    max_cost = Prompt.ask("Max cost (USD)", default="2.00")
    max_requests = Prompt.ask("Max HTTP requests", default="200")

    config.max_cycles = int(max_cycles)
    config.max_cost_usd = float(max_cost)
    config.max_requests = int(max_requests)

    return config


def _print_banner():
    """Print the agent startup banner."""
    banner = """
╭──────────────────────────────────────────────╮
│ DEMOGORGON                                   │
│ Autonomous Bug Bounty Research Agent         │
│                                              │
│ Authorized security research only            │
╰──────────────────────────────────────────────╯"""
    console.print(banner, style="bold cyan")


def _print_summary(config: SessionConfig):
    """Print the session configuration summary."""
    provider_info = PROVIDER_INFO.get(config.provider, {})
    provider_name = provider_info.get("name", config.provider or "not configured")

    console.print("\n[bold green]DEMOGORGON is ready.[/bold green]\n")

    table = Table(show_header=False, border_style="cyan", padding=(0, 2))
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row("Target", config.target or "not set")
    table.add_row("Provider", provider_name)
    table.add_row("Model", config.model or "not set")
    table.add_row("Max Cycles", str(config.max_cycles))
    table.add_row("Max Cost", f"${config.max_cost_usd:.2f}")
    console.print(table)


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
