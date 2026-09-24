"""Setup Wizard for Demogorgon."""

from __future__ import annotations

from pathlib import Path

from rich.prompt import Prompt, Confirm

from .theme import console, print_banner, print_header


async def run_setup_wizard():
    """Interactive wizard to configure providers, Laya, and models."""
    print_banner()
    print_header("Setup Wizard")

    # 1. AI Provider setup
    providers = ["OpenRouter", "OpenAI", "Anthropic", "DeepSeek", "Gemini", "Ollama"]
    console.print("[bold]1. AI Provider[/bold]\n")
    for i, p in enumerate(providers, 1):
        console.print(f"  [cyan]{i}[/cyan]  {p}")

    choice = Prompt.ask(
        "\nSelect AI provider",
        choices=[str(i) for i in range(1, len(providers) + 1)],
        default="1",
        console=console,
    )
    provider = providers[int(choice) - 1].lower()

    api_key = ""
    if provider != "ollama":
        api_key = Prompt.ask(f"Enter {provider.title()} API Key", password=True, console=console)

    base_url = ""
    if provider == "ollama":
        base_url = Prompt.ask(
            "Enter Ollama base URL",
            default="http://localhost:11434/v1",
            console=console,
        )

    # 2. Models
    console.print("\n[bold]2. Models[/bold]")
    console.print(
        "Demogorgon uses two models: [cyan]fast[/cyan] for Laya decisions "
        "and [cyan]reasoning[/cyan] for deep analysis."
    )
    fast_default = "llama3.1:8b" if provider == "ollama" else "gpt-4o-mini"
    reasoning_default = "llama3.1:8b" if provider == "ollama" else "gpt-4o"
    fast_model = Prompt.ask("Fast Model", default=fast_default, console=console)
    reasoning_model = Prompt.ask("Reasoning Model", default=reasoning_default, console=console)

    # 3. Save to config
    console.print("\n[bold]3. Save Configuration[/bold]")
    env_content = f"""# DEMOGORGON CONFIGURATION

# AI Provider
DEMOGORGON_LLM_PROVIDER={provider}
DEMOGORGON_API_KEY={api_key}
DEMOGORGON_FAST_MODEL={fast_model}
DEMOGORGON_REASONING_MODEL={reasoning_model}
"""
    if base_url:
        env_content += f"DEMOGORGON_BASE_URL={base_url}\n"

    env_path = Path(".env")
    if env_path.exists():
        if Confirm.ask(".env already exists. Overwrite?", console=console):
            env_path.write_text(env_content)
            console.print("[green]✓ Configuration saved to .env[/green]")
    else:
        env_path.write_text(env_content)
        console.print("[green]✓ Configuration saved to .env[/green]")

    # 4. Test Connectivity
    console.print("\n[bold]4. Testing Connectivity…[/bold]")
    import os

    os.environ["DEMOGORGON_LLM_PROVIDER"] = provider
    os.environ["DEMOGORGON_API_KEY"] = api_key
    os.environ["DEMOGORGON_FAST_MODEL"] = fast_model
    if base_url:
        os.environ["DEMOGORGON_BASE_URL"] = base_url

    from demogorgon.llm.manager import AIProviderManager

    manager = AIProviderManager()
    manager.configure()
    with console.status("[cyan]Connecting…[/cyan]"):
        health = await manager.health_check()

    if health.get("status") == "healthy":
        console.print(
            f"[bold green]✓ Provider connected[/bold green] "
            f"(Latency: {health.get('latency')}s)"
        )
    else:
        console.print(f"[bold red]✗ Connection failed:[/bold red] {health.get('connectivity')}")

    console.print("\n[green]Setup complete. Run [bold]demogorgon[/bold] to start a hunt.[/green]\n")
