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

import importlib
import os
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ..config.model_discovery import discover_models, test_provider_connection
from ..config.provider_config import (
    ProviderConfigManager,
    ProviderProfile,
    redact_secrets,
)

console = Console()

PROVIDER_DISPLAY = {
    "openai": {"name": "OpenAI", "icon": "🤖", "env_key": "OPENAI_API_KEY"},
    "anthropic": {"name": "Anthropic", "icon": "🧠", "env_key": "ANTHROPIC_API_KEY"},
    "gemini": {"name": "Google Gemini", "icon": "💎", "env_key": "GEMINI_API_KEY"},
    "openrouter": {"name": "OpenRouter", "icon": "🔀", "env_key": "OPENROUTER_API_KEY"},
    "deepseek": {"name": "DeepSeek", "icon": "🔍", "env_key": "DEEPSEEK_API_KEY"},
    "ollama": {"name": "Ollama (Local)", "icon": "🏠", "env_key": ""},
}

# provider → (distribution to pip install, importable module to probe)
_PROVIDER_SDK: dict[str, tuple[str, str]] = {
    "openai": ("openai", "openai"),
    "openrouter": ("openai", "openai"),
    "deepseek": ("openai", "openai"),
    "anthropic": ("anthropic", "anthropic"),
    "gemini": ("google-genai", "google.genai"),
}


def _provider_info(provider: str) -> dict:
    return PROVIDER_DISPLAY.get(provider, {"name": provider, "icon": "❓", "env_key": ""})


def missing_sdk(provider: str) -> str:
    """Return the distribution to install for `provider`, or '' if present.

    Surfacing this BEFORE the network test is what turns
    ``Provider not reachable (FAILED)`` into an actionable instruction.
    """
    pkg, module = _PROVIDER_SDK.get(provider, ("", ""))
    if not pkg:
        return ""
    try:
        importlib.import_module(module)
    except Exception:
        return pkg
    return ""


def _read_line(hidden: bool = False) -> str:
    """Read one line from stdin, optionally with terminal echo suppressed.

    The wizard asks y/n questions directly after API-key prompts.  Pasting a
    key at one of them used to dump the plaintext key into the terminal
    scrollback (Rich's ``Prompt.ask`` reads on an echoing tty).  Suppressing
    echo makes such a mis-paste harmless.

    Raises ``EOFError`` when stdin is exhausted (piped input, closed tty) so
    callers can abort instead of spinning on an empty string forever.
    """
    try:
        import termios

        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        if hidden:
            quiet = termios.tcgetattr(fd)
            quiet[3] &= ~termios.ECHO
            termios.tcsetattr(fd, termios.TCSADRAIN, quiet)
        try:
            line = sys.stdin.readline()
            if line == "":
                raise EOFError
            return line.rstrip("\n")
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    except EOFError:
        raise
    except Exception:
        # Non-tty stdin (tests, Windows) — fall back to plain input.
        return input()


def _flush_prompt() -> None:
    """Make sure a partial-line prompt is visible before we block on stdin."""
    try:
        console.file.flush()
    except Exception:
        pass


def _read_default(prompt: str, default: str, hidden: bool = False) -> str:
    """Read an optional value, falling back to `default` on empty/EOF."""
    console.print(prompt, end="")
    _flush_prompt()
    try:
        return _read_line(hidden=hidden).strip() or default
    except EOFError:
        return default


def _ask_yes_no(question: str, default: bool = True) -> bool:
    """Ask a y/n question without echoing whatever was pasted into it."""
    hint = "(Y/n)" if default else "(y/N)"
    for _ in range(5):
        console.print(f"{question} {hint} ", end="")
        _flush_prompt()
        try:
            raw = _read_line(hidden=True).strip().lower()
        except EOFError:
            return default
        if not raw:
            return default
        if raw in ("y", "yes"):
            return True
        if raw in ("n", "no"):
            return False
        console.print("[dim]Please answer y or n.[/]")
    return default


def _ask_retry_action() -> str:
    """After a failed connection test: 'retry' | 'switch' | 'quit'.

    Replaces the old ambiguous ``Prompt.ask("Try again?", y/n)`` whose only
    exit was a full recursion into ``run_setup_wizard()`` — which re-showed
    the Existing Configuration panel and lost the user's place.
    """
    for _ in range(5):
        console.print(
            "Try again? (Enter/y) new key  ·  (p) other provider  ·  (n) quit ",
            end="",
        )
        _flush_prompt()
        try:
            raw = _read_line(hidden=True).strip().lower()
        except EOFError:
            return "quit"
        if raw in ("", "y", "yes", "r", "retry"):
            return "retry"
        if raw in ("p", "s", "provider", "other"):
            return "switch"
        if raw in ("n", "no", "q", "quit", "c", "cancel"):
            return "quit"
        console.print("[dim]Please answer y, p or n.[/]")
    return "quit"


def _prompt_api_key() -> str:
    """Prompt for an API key until a non-empty value is entered."""
    for _ in range(100):
        console.print("Enter API key ", end="")
        _flush_prompt()
        try:
            api_key = _read_line(hidden=True).strip()
        except EOFError:
            raise SystemExit(
                "Setup aborted: no more input available (stdin closed)."
            ) from None
        if api_key:
            return api_key
        console.print(
            "[red]An API key is required.[/] "
            "Get a free key at https://openrouter.ai/keys (Ctrl+C to cancel)"
        )
    raise SystemExit("Setup aborted: no API key entered.")


def _ask_choice(question: str, choices: list[str]) -> str:
    """Ask for one of `choices` with echo suppressed (see ``_read_line``)."""
    for _ in range(5):
        console.print(f"{question} ({'/'.join(choices)}) ", end="")
        _flush_prompt()
        try:
            raw = _read_line(hidden=True).strip()
        except EOFError:
            break
        if raw in choices:
            return raw
        console.print(f"[dim]Please enter one of: {', '.join(choices)}[/]")
    raise SystemExit("Setup aborted: no valid selection received.")


def _choose_provider(mgr: ProviderConfigManager) -> str:
    """Step 1 — list providers and return the selected key."""
    console.print()
    console.print(Panel("[bold]DEMOGORGON[/] — Configure AI Provider", border_style="cyan"))

    providers = list(PROVIDER_DISPLAY.keys())
    for i, prov in enumerate(providers, 1):
        info = _provider_info(prov)
        configured = _is_configured(mgr, prov)
        status = "[green]✓ configured[/]" if configured else "[dim]not configured[/]"
        console.print(f"  {i}. {info['icon']}  {info['name']}  {status}")

    console.print()
    choice = _ask_choice("Select provider", [str(i) for i in range(1, len(providers) + 1)])
    return providers[int(choice) - 1]


async def _collect_credentials_and_test(
    mgr: ProviderConfigManager,
    selected_provider: str,
    info: dict,
) -> tuple[str, str] | str | None:
    """Steps 2–4: gather credentials, verify the connection, retry in place.

    Returns ``(api_key, base_url)`` on success, ``"switch"`` to re-choose the
    provider, or ``None`` to abandon setup.  Never restarts the wizard.
    """
    # ── Step 2: API key ──────────────────────────────────────────
    api_key = ""
    if selected_provider == "ollama":
        console.print("[dim]Ollama runs locally — no API key needed[/]")
    else:
        env_key = info.get("env_key", "")
        if env_key and os.environ.get(env_key):
            console.print("Found API key in environment — will use it [dim](hidden)[/]")
            if _ask_yes_no("Use this key?", default=True):
                api_key = os.environ[env_key]
        if not api_key:
            existing = mgr.get_profile(selected_provider)
            if existing and existing.api_key:
                console.print("Found stored key for this provider [dim](hidden)[/]")
                if _ask_yes_no("Use stored key?", default=True):
                    api_key = existing.api_key
        if not api_key:
            api_key = _prompt_api_key()

    # ── Step 3: base URL ─────────────────────────────────────────
    base_url = ""
    if selected_provider == "openrouter":
        base_url = "https://openrouter.ai/api/v1"
    elif selected_provider == "ollama":
        base_url = _read_default(
            "Ollama base URL (http://localhost:11434/v1) ",
            "http://localhost:11434/v1",
            hidden=True,
        )

    # ── Step 4: connection test (bounded retry) ──────────────────
    while True:
        pkg = missing_sdk(selected_provider)
        if pkg:
            console.print(f"\n  [red]✗ Missing dependency for {selected_provider}: {pkg}[/]")
            console.print(f"    [yellow]Install it:[/] pip install {pkg}")
            result = {"success": False, "error": f"{pkg} is not installed"}
        else:
            console.print("\n[cyan]Testing provider...[/]")
            result = await test_provider_connection(selected_provider, api_key, base_url)

        if result.get("success"):
            console.print("  [green]✓ Authentication successful[/]")
            console.print(f"  [green]✓ Model available: {result.get('model', 'unknown')}[/]")
            if result.get("structured_output"):
                console.print("  [green]✓ Structured output supported[/]")
            else:
                console.print("  [yellow]⚠ Structured output test failed (may still work)[/]")
            return api_key, base_url

        err = redact_secrets(result.get("error", "unknown"))
        console.print(f"  [red]✗ Connection failed: {err}[/]")
        action = _ask_retry_action()
        if action == "switch":
            return "switch"
        if action == "quit":
            return None
        # retry — always re-prompt the value that could be wrong
        if selected_provider == "ollama":
            fallback = base_url or "http://localhost:11434/v1"
            base_url = _read_default(
                f"Ollama base URL ({fallback}) ", fallback, hidden=True
            )
        else:
            api_key = _prompt_api_key()


def _next_steps_panel() -> Panel:
    """Post-setup guidance — the guided hunt asks target/scope inside the tool."""
    return Panel(
        "[cyan]python -m demogorgon doctor[/]   Verify install + LLM connectivity\n"
        "[cyan]python -m demogorgon tools[/]    List security tools "
        "(subfinder, httpx, nuclei…)\n"
        "[cyan]python -m demogorgon[/]          Guided hunt — the tool asks your "
        "target,\n"
        "                                    scope, and program document step by step",
        title="Next Steps",
        border_style="cyan",
    )


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
            f"API Key: [green]✓ Supplied[/] [dim](hidden)[/]",
            title="Existing Configuration",
            border_style="green",
        ))

        if existing_config_only:
            return active

        if _ask_yes_no("Use existing configuration?", default=True):
            return active

    # ── Steps 1–4: provider, key, base URL, connection test ──────
    # Bounded in-place retry.  The old code did
    # ``return await run_setup_wizard()`` on failure, which restarted the
    # whole wizard (re-showing the Existing Configuration panel) and made a
    # bad key look like an infinite loop.
    while True:
        selected_provider = _choose_provider(mgr)
        info = _provider_info(selected_provider)
        console.print(f"\nSelected: [bold]{info['name']}[/]")

        outcome = await _collect_credentials_and_test(mgr, selected_provider, info)
        if outcome == "switch":
            console.print()
            continue
        if outcome is None:
            console.print("[yellow]Setup cancelled — nothing was saved.[/]")
            return None
        api_key, base_url = outcome
        break

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
        f"API Key: [green]✓ Supplied[/] [dim](hidden)[/]\n"
        f"Status: [green]✓ Connected[/]",
        title="Provider Ready",
        border_style="green",
    ))

    console.print(_next_steps_panel())

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
