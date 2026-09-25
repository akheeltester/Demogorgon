"""Interactive Terminal Setup — provider configuration wizard.

Replaces the old hardcoded startup with a dynamic wizard that:
- Lists available providers
- Discovers models from APIs
- Tests provider connections
- Persists configuration securely
- Supports quick restart with existing config

Usage:
    python -m demogorgon setup
    python -m demogorgon  (auto-detects config)
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.text import Text

from ..config.provider_config import ProviderConfigManager, ProviderProfile, _mask_key
from ..config.model_discovery import discover_models, test_provider_connection

console = Console()

PROVIDER_DISPLAY = {
    "openai": {"name": "OpenAI", "icon": "🤖", "env_key": "OPENAI_API_KEY"},
    "anthropic": {"name": "Anthropic", "icon": "🧠", "env_key": "ANTHROPIC_API_KEY"},
    "gemini": {"name": "Google Gemini", "icon": "💎", "env_key": "GEMINI_API_KEY"},
    "openrouter": {"name": "OpenRouter", "icon": "🔀", "env_key": "OPENROUTER_API_KEY"},
    "deepseek": {"name": "DeepSeek", "icon": "🔍", "env_key": "DEEPSEEK_API_KEY"},
    "ollama": {"name": "Ollama (Local)", "icon": "🏠", "env_key": ""},
}


def _provider_info(provider: str) -> dict:
    return PROVIDER_DISPLAY.get(provider, {"name": provider, "icon": "❓", "env_key": ""})


def _prompt_api_key() -> str:
    """Prompt for an API key until a non-empty value is entered."""
    api_key = ""
    while not api_key:
        api_key = Prompt.ask("Enter API key", password=True).strip()
        if not api_key:
            console.print(
                "[red]An API key is required.[/] "
                "Get a free key at https://openrouter.ai/keys (Ctrl+C to cancel)"
            )
    return api_key


async def run_setup_wizard(existing_config_only: bool = False) -> ProviderProfile | None:
    """Run the interactive setup wizard.

    Args:
        existing_config_only: If True, only offer to use existing configuration.

    Returns:
        Selected ProviderProfile or None if cancelled.
    """
    mgr = ProviderConfigManager()

    # Check for existing config
    active = mgr.get_active_profile()

    if active and active.api_key:
        console.print()
        console.print(Panel(
            f"Configured provider: [bold green]{active.provider}[/]\n"
            f"Model: [cyan]{active.selected_model or 'not set'}[/]\n"
            f"API Key: [dim]{active.masked_key}[/]",
            title="Existing Configuration",
            border_style="green",
        ))

        if existing_config_only:
            return active

        use_existing = Prompt.ask(
            "Use existing configuration?",
            choices=["y", "n"],
            default="y",
        )
        if use_existing == "y":
            return active

    # ── Step 1: Choose provider ──────────────────────────────────

    console.print()
    console.print(Panel("[bold]DEMOGORGON[/] — Configure AI Provider", border_style="cyan"))

    providers = list(PROVIDER_DISPLAY.keys())
    for i, prov in enumerate(providers, 1):
        info = _provider_info(prov)
        configured = _is_configured(mgr, prov)
        status = "[green]✓ configured[/]" if configured else "[dim]not configured[/]"
        console.print(f"  {i}. {info['icon']}  {info['name']}  {status}")

    console.print()
    choice = Prompt.ask("Select provider", choices=[str(i) for i in range(1, len(providers) + 1)])
    selected_provider = providers[int(choice) - 1]
    info = _provider_info(selected_provider)

    console.print(f"\nSelected: [bold]{info['name']}[/]")

    # ── Step 2: API Key ──────────────────────────────────────────

    api_key = ""

    if selected_provider == "ollama":
        # Ollama doesn't need an API key
        console.print("[dim]Ollama runs locally — no API key needed[/]")
    else:
        # Check env var first
        env_key = info.get("env_key", "")
        if env_key and os.environ.get(env_key):
            api_key = os.environ[env_key]
            console.print(f"Found API key in environment: [dim]{_mask_key(api_key)}[/]")
            use_env = Prompt.ask("Use this key?", choices=["y", "n"], default="y")
            if use_env == "n":
                api_key = _prompt_api_key()
        else:
            # Check secure config
            existing = mgr.get_profile(selected_provider)
            if existing and existing.api_key:
                console.print(f"Found stored key: [dim]{existing.masked_key}[/]")
                use_stored = Prompt.ask("Use stored key?", choices=["y", "n"], default="y")
                if use_stored == "y":
                    api_key = existing.api_key
                else:
                    api_key = _prompt_api_key()
            else:
                api_key = _prompt_api_key()

    # ── Step 3: Base URL (optional) ──────────────────────────────

    base_url = ""
    if selected_provider == "openrouter":
        base_url = "https://openrouter.ai/api/v1"
    elif selected_provider == "ollama":
        base_url = Prompt.ask("Ollama base URL", default="http://localhost:11434/v1")

    # ── Step 4: Test connection ──────────────────────────────────

    if api_key or selected_provider == "ollama":
        console.print("\n[cyan]Testing provider...[/]")
        result = await test_provider_connection(selected_provider, api_key, base_url)

        if result["success"]:
            console.print(f"  [green]✓ Authentication successful[/]")
            console.print(f"  [green]✓ Model available: {result.get('model', 'unknown')}[/]")
            if result.get("structured_output"):
                console.print(f"  [green]✓ Structured output supported[/]")
            else:
                console.print(f"  [yellow]⚠ Structured output test failed (may still work)[/]")
        else:
            console.print(f"  [red]✗ Connection failed: {result.get('error', 'unknown')}[/]")
            retry = Prompt.ask("Try again?", choices=["y", "n"], default="y")
            if retry == "y":
                return await run_setup_wizard()

    # ── Step 5: Discover models ──────────────────────────────────

    console.print("\n[cyan]Discovering available models...[/]")
    models = await discover_models(selected_provider, api_key, base_url)

    if not models:
        console.print("[yellow]No models discovered. Using defaults.[/]")
        selected_model = "default"
    else:
        console.print(f"Found [bold]{len(models)}[/] models:\n")

        # Display models in a table
        table = Table(show_header=True, header_style="bold")
        table.add_column("#", width=4)
        table.add_column("Model", min_width=30)
        table.add_column("Context", width=12)
        if any(m.get("pricing") for m in models):
            table.add_column("Price (prompt)", width=14)

        for i, m in enumerate(models[:50], 1):  # Limit display to 50
            ctx = m.get("context_length", 0)
            ctx_str = f"{ctx:,}" if ctx else "?"
            price_str = ""
            if m.get("pricing"):
                p = m["pricing"].get("prompt", 0)
                price_str = f"${p*1e6:.2f}/M" if p else "free"
            table.add_row(str(i), m["id"], ctx_str, price_str)

        console.print(table)

        # Model selection
        console.print()
        model_choice = Prompt.ask(
            "Select model (number or type model ID)",
            default="1",
        )

        if model_choice.isdigit() and 1 <= int(model_choice) <= len(models):
            selected_model = models[int(model_choice) - 1]["id"]
        else:
            selected_model = model_choice

    console.print(f"\nSelected model: [bold cyan]{selected_model}[/]")

    # ── Step 6: Build profile ────────────────────────────────────

    profile = ProviderProfile(
        provider=selected_provider,
        api_key=api_key,
        base_url=base_url,
        selected_model=selected_model,
    )

    # Save
    mgr.save_profile(profile)
    mgr.set_active_provider(selected_provider)

    # Also load into environment for LLMManager compatibility
    mgr.load_into_environment(selected_provider)

    # Mirror into the project .env so doctor / hand-editing / fresh shells work
    _write_dotenv(profile)

    # ── Summary ──────────────────────────────────────────────────

    console.print()
    console.print(Panel(
        f"Provider: [bold]{info['name']}[/]\n"
        f"Model: [cyan]{selected_model}[/]\n"
        f"API Key: [dim]{profile.masked_key}[/]\n"
        f"Status: [green]✓ Connected[/]",
        title="Provider Ready",
        border_style="green",
    ))

    console.print(Panel(
        "[cyan]demogorgon doctor[/]                    Verify install + LLM connectivity\n"
        "[cyan]demogorgon tools[/]                     List security tools "
        "(subfinder, httpx, nuclei…)\n"
        "[cyan]demogorgon https://target.example[/]     Start hunting "
        "(authorized targets only)",
        title="Next Steps",
        border_style="cyan",
    ))

    return profile


# Keys the wizard owns inside .env (everything else is preserved)
_MANAGED_ENV_KEYS = (
    "DEMOGORGON_LLM_PROVIDER",
    "DEMOGORGON_API_KEY",
    "DEMOGORGON_MODEL",
    "DEMOGORGON_BASE_URL",
    "DEMOGORGON_FAST_MODEL",
    "DEMOGORGON_REASONING_MODEL",
)


def _write_dotenv(profile: ProviderProfile, env_path: Path | None = None) -> bool:
    """Mirror the wizard config into the project .env file.

    Preserves comments and unrelated settings; replaces only the managed
    DEMOGORGON_* provider keys. Returns True if written.
    """
    if env_path is None:
        env_path = Path(__file__).resolve().parents[2] / ".env"

    new_lines = [
        "# Written by `demogorgon setup` — see .env.example for all options",
        f"DEMOGORGON_LLM_PROVIDER={profile.provider}",
    ]
    if profile.api_key:
        new_lines.append(f"DEMOGORGON_API_KEY={profile.api_key}")
    if profile.selected_model:
        new_lines.append(f"DEMOGORGON_MODEL={profile.selected_model}")
    if profile.base_url:
        new_lines.append(f"DEMOGORGON_BASE_URL={profile.base_url}")
    new_block = "\n".join(new_lines) + "\n"

    kept: list[str] = []
    if env_path.exists():
        existing = env_path.read_text()
        has_live_config = any(
            ln.strip().startswith("DEMOGORGON_LLM_PROVIDER=")
            for ln in existing.splitlines()
            if not ln.strip().startswith("#")
        )
        if has_live_config and not Confirm.ask(
            ".env already has a provider configured. Update it?", default=True
        ):
            return False
        kept = [
            ln for ln in existing.splitlines()
            if ln.strip().split("=", 1)[0].strip() not in _MANAGED_ENV_KEYS
        ]
        while kept and not kept[-1].strip():
            kept.pop()

    content = ("\n".join(kept) + "\n\n" if kept else "") + new_block
    env_path.write_text(content)
    try:
        env_path.chmod(0o600)
    except OSError:
        pass
    console.print(f"[green]✓ Configuration saved to {env_path}[/green]")
    return True


def _is_configured(mgr: ProviderConfigManager, provider: str) -> bool:
    """Check if a provider has a stored API key."""
    profile = mgr.get_profile(provider)
    return profile is not None and bool(profile.api_key)


def print_provider_status() -> None:
    """Print status of all configured providers."""
    mgr = ProviderConfigManager()
    profiles = mgr.list_providers()

    if not profiles:
        console.print("[dim]No providers configured. Run: python -m demogorgon setup[/]")
        return

    console.print()
    table = Table(title="Configured Providers", show_header=True, header_style="bold")
    table.add_column("Status", width=3)
    table.add_column("Provider", min_width=15)
    table.add_column("Model", min_width=20)
    table.add_column("Key", min_width=15)

    for p in profiles:
        info = _provider_info(p.provider)
        status = "[green]✓[/]" if p.enabled else "[red]✗[/]"
        model = p.selected_model or "[dim]not set[/]"
        key_display = p.masked_key if p.api_key else "[dim]not set[/]"
        table.add_row(status, f"{info['icon']} {info['name']}", model, key_display)

    console.print(table)


async def run_quick_setup(target: str = "") -> ProviderProfile | None:
    """Quick setup that auto-detects existing config."""
    mgr = ProviderConfigManager()
    active = mgr.get_active_profile()

    if active and active.api_key:
        # Load existing config
        mgr.load_into_environment(active.provider)
        return active

    # No config — run full wizard
    return await run_setup_wizard()
