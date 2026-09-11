"""CLI — Demogorgon command-line interface.

Usage:
    demogorgon                              # Interactive menu
    demogorgon https://example.com          # Quick scan (requires confirmation)
    demogorgon --program                    # Paste program policy
    demogorgon resume                       # Resume engagement
    demogorgon status                       # Show status
    demogorgon findings                     # Show findings
    demogorgon report                       # Generate report
    demogorgon setup                        # Configuration wizard
    demogorgon doctor                       # Diagnostics
"""

from __future__ import annotations

import sys
import asyncio
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.table import Table
from rich.text import Text

console = Console()


BANNER = """
╔══════════════════════════════════════════════╗
║              DEMOGORGON                      ║
║       Autonomous Bug Bounty Researcher       ║
╚══════════════════════════════════════════════╝
"""


def print_banner():
    console.print(BANNER, style="bold cyan")


async def cmd_interactive():
    """Interactive menu."""
    print_banner()
    
    console.print("\n[bold]How do you want to start?[/bold]\n")
    console.print("  [1] Paste bug bounty program")
    console.print("  [2] Enter target URL/domain")
    console.print("  [3] Resume engagement")
    console.print("  [4] Configuration")
    console.print("  [5] Diagnostics")
    console.print()
    
    choice = Prompt.ask("Select", choices=["1", "2", "3", "4", "5"], default="1")
    
    if choice == "1":
        await cmd_program()
    elif choice == "2":
        url = Prompt.ask("Enter target URL/domain")
        await cmd_target(url)
    elif choice == "3":
        await cmd_resume()
    elif choice == "4":
        await cmd_config()
    elif choice == "5":
        await cmd_doctor()


async def cmd_program():
    """Paste and parse a bug bounty program."""
    print_banner()
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
        return
    
    program_text = "\n".join(lines)
    
    # Parse the program
    from demogorgon.core.scope.parser import parse_program_policy
    policy = parse_program_policy(program_text)
    
    # Display parsed results
    console.print("\n[bold green]Program Parsed Successfully[/bold green]\n")
    
    table = Table(show_header=False, border_style="cyan")
    table.add_column("Key", style="bold")
    table.add_column("Value")
    table.add_row("Program", policy.program_name)
    table.add_row("Platform", policy.platform)
    table.add_row("In-Scope Assets", str(len(policy.in_scope)))
    table.add_row("Out-of-Scope Assets", str(len(policy.out_of_scope)))
    table.add_row("Restrictions", str(len(policy.restrictions)))
    table.add_row("Allowed Vulns", ", ".join(policy.allowed_vulnerabilities) or "Not specified")
    table.add_row("Forbidden Vulns", ", ".join(policy.forbidden_vulnerabilities) or "Not specified")
    table.add_row("Account Creation", "Allowed" if policy.account_creation_allowed else "Not Allowed")
    table.add_row("Safe Harbor", "Yes" if policy.safe_harbor else "Not specified")
    console.print(table)
    
    if policy.in_scope:
        console.print("\n[bold]In-Scope Assets:[/bold]")
        for asset in policy.in_scope[:20]:
            console.print(f"  • {asset.pattern} ({asset.asset_type})")
        if len(policy.in_scope) > 20:
            console.print(f"  ... and {len(policy.in_scope) - 20} more")
    
    if policy.restrictions:
        console.print("\n[bold]Restrictions:[/bold]")
        for r in policy.restrictions:
            console.print(f"  • {r.category}: {r.description}")
    
    # Confirm engagement
    if Confirm.ask("\n[bold]Create engagement?[/bold]", default=True):
        from demogorgon.core.engagement.manager import EngagementManager
        manager = EngagementManager()
        engagement = manager.create_from_policy(program_text)
        
        console.print(f"\n[green]Engagement created: {engagement.id}[/green]")
        console.print(f"Workspace: {engagement.workspace_dir}")
        
        # Ask for authorization confirmation
        console.print("\n[bold yellow]Authorization Required[/bold yellow]")
        console.print("Please confirm that you are authorized to test this target.")
        if Confirm.ask("[bold]Are you authorized to test this target?[/bold]", default=False):
            from demogorgon.core.engagement.models import AuthorizationStatus, EngagementStatus
            engagement.authorization_status = AuthorizationStatus.CONFIRMED
            engagement.status = EngagementStatus.ACTIVE
            engagement.save(str(Path(engagement.workspace_dir) / "engagement.json"))
            console.print("[green]Authorization confirmed. Engagement active.[/green]")
        else:
            console.print("[red]Authorization not confirmed. Engagement paused.[/red]")


async def cmd_target(url: str):
    """Create engagement from a target URL."""
    print_banner()
    console.print(f"\n[bold]Target:[/bold] {url}")
    
    # Safety check
    console.print("\n[bold yellow]Authorization Required[/bold yellow]")
    console.print("DEMOGORGON assumes NO authorization unless explicitly confirmed.")
    console.print(f"Is {url} an authorized bug bounty target?")
    
    if not Confirm.ask("[bold]Are you authorized to test this target?[/bold]", default=False):
        console.print("[red]Authorization not confirmed. Cannot proceed.[/red]")
        console.print("\nTo test an authorized target, run:")
        console.print(f"  demogorgon --program  (then paste the program policy)")
        return
    
    from demogorgon.core.engagement.manager import EngagementManager
    from demogorgon.core.engagement.models import AuthorizationStatus, EngagementStatus
    
    manager = EngagementManager()
    engagement = manager.create_from_url(url)
    engagement.authorization_status = AuthorizationStatus.CONFIRMED
    engagement.status = EngagementStatus.ACTIVE
    engagement.save(str(Path(engagement.workspace_dir) / "engagement.json"))
    
    console.print(f"\n[green]Engagement created and authorized: {engagement.id}[/green]")
    console.print(f"Workspace: {engagement.workspace_dir}")
    
    # TODO: Start the autonomous research loop
    console.print("\n[cyan]Starting autonomous research...[/cyan]")
    console.print("[yellow]Phase 1 complete. Research loop not yet implemented.[/yellow]")


async def cmd_resume():
    """Resume an existing engagement."""
    print_banner()
    
    from demogorgon.core.engagement.manager import EngagementManager
    manager = EngagementManager()
    engagements = manager.list_engagements()
    
    if not engagements:
        console.print("[yellow]No engagements found.[/yellow]")
        return
    
    console.print("\n[bold]Existing Engagements:[/bold]\n")
    
    table = Table(show_header=True, border_style="cyan")
    table.add_column("#", style="dim")
    table.add_column("ID", style="bold")
    table.add_column("Name")
    table.add_column("Status")
    table.add_column("Created")
    
    for i, eng in enumerate(engagements, 1):
        status_style = "green" if eng["status"] == "active" else "yellow"
        table.add_row(
            str(i),
            eng["id"],
            eng["name"],
            f"[{status_style}]{eng['status']}[/{status_style}]",
            eng["created_at"][:10] if eng["created_at"] else "Unknown",
        )
    
    console.print(table)
    
    choice = Prompt.ask("\nSelect engagement number", default="1")
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(engagements):
            eng_id = engagements[idx]["id"]
            console.print(f"\n[cyan]Resuming engagement: {eng_id}[/cyan]")
            # TODO: Resume the engagement
            console.print("[yellow]Resume not yet implemented.[/yellow]")
    except (ValueError, IndexError):
        console.print("[red]Invalid selection.[/red]")


async def cmd_config():
    """Configuration wizard."""
    print_banner()
    console.print("\n[bold]DEMOGORGON Configuration[/bold]\n")
    
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if env_file.exists():
        console.print("[green].env file exists[/green]")
    elif env_example.exists():
        console.print("[yellow].env not found. Copy from .env.example?[/yellow]")
        if Confirm.ask("Create .env from .env.example?", default=True):
            import shutil
            shutil.copy(env_example, env_file)
            console.print("[green].env created. Edit it with your API keys.[/green]")
    else:
        console.print("[red]No .env.example found.[/red]")


async def cmd_doctor():
    """Diagnostics."""
    print_banner()
    console.print("\n[bold]Diagnostics[/bold]\n")
    
    checks = []
    
    # Python version
    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    checks.append(("Python", py_version, py_ok))
    
    # Dependencies
    deps = [
        ("rich", "rich"),
        ("httpx", "httpx"),
        ("openai", "openai"),
        ("pydantic", "pydantic"),
        ("playwright", "playwright"),
        ("beautifulsoup4", "bs4"),
    ]
    
    for name, module in deps:
        try:
            __import__(module)
            checks.append((name, "Installed", True))
        except ImportError:
            checks.append((name, "Not installed", False))
    
    # .env file
    env_exists = Path(".env").exists()
    checks.append((".env", "Exists" if env_exists else "Missing", env_exists))
    
    # Display results
    table = Table(show_header=True, border_style="cyan")
    table.add_column("Component")
    table.add_column("Status")
    table.add_column("Detail")
    
    for name, detail, ok in checks:
        status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(name, status, detail)
    
    console.print(table)


async def cmd_findings():
    """Show findings."""
    print_banner()
    console.print("\n[bold]Findings[/bold]\n")
    # TODO: Implement
    console.print("[yellow]Not yet implemented.[/yellow]")


async def cmd_report():
    """Generate report."""
    print_banner()
    console.print("\n[bold]Report Generation[/bold]\n")
    # TODO: Implement
    console.print("[yellow]Not yet implemented.[/yellow]")


async def cmd_status():
    """Show status."""
    print_banner()
    console.print("\n[bold]Status[/bold]\n")
    # TODO: Implement
    console.print("[yellow]Not yet implemented.[/yellow]")


async def main():
    """Main CLI entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Demogorgon — Autonomous Bug Bounty Researcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  demogorgon                              Interactive menu
  demogorgon https://example.com          Quick scan (requires confirmation)
  demogorgon --program                    Paste program policy
  demogorgon resume                       Resume engagement
  demogorgon status                       Show status
  demogorgon findings                     Show findings
  demogorgon report                       Generate report
  demogorgon setup                        Configuration wizard
  demogorgon doctor                       Diagnostics
        """,
    )
    
    parser.add_argument("target", nargs="?", help="Target URL/domain")
    parser.add_argument("--program", action="store_true", help="Paste program policy")
    parser.add_argument("command", nargs="?", choices=[
        "resume", "status", "findings", "report", "setup", "doctor",
    ], help="Command to run")
    
    args = parser.parse_args()
    
    if args.program:
        await cmd_program()
    elif args.command == "resume":
        await cmd_resume()
    elif args.command == "status":
        await cmd_status()
    elif args.command == "findings":
        await cmd_findings()
    elif args.command == "report":
        await cmd_report()
    elif args.command == "setup":
        await cmd_config()
    elif args.command == "doctor":
        await cmd_doctor()
    elif args.target:
        await cmd_target(args.target)
    else:
        await cmd_interactive()


if __name__ == "__main__":
    asyncio.run(main())
