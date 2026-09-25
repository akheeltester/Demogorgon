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

from .theme import (
    console,
    print_banner,
    print_header,
    info_table,
    findings_table,
    sev_badge,
    sev_style,
    status_table,
    VERSION,
    DEMO_THEME,
)

__all__ = [
    "main", "cmd_doctor", "cmd_config", "cmd_status", "cmd_findings",
    "cmd_report", "cmd_tools", "cmd_metrics", "console",
]


async def _run_engagement(engagement, resume: bool = False):
    """Run or resume an autonomous engagement."""
    from demogorgon.core.runner import AutonomousRunner, RunnerConfig
    from demogorgon.llm.manager import AIProviderManager
    from demogorgon.core.hitl.gate import ApprovalLevel

    llm_manager = AIProviderManager()
    llm_manager.configure()
    llm_generate = llm_manager.generate if llm_manager.available else None

    if not llm_generate:
        console.print("[yellow]No LLM provider configured — observation-only mode.[/yellow]")
        console.print("  Run [cyan]demogorgon setup[/cyan] or set DEMOGORGON_LLM_PROVIDER / DEMOGORGON_API_KEY")

    runner = AutonomousRunner(
        engagement=engagement,
        config=RunnerConfig(
            max_iterations=50,
            checkpoint_interval=5,
            approval_level=ApprovalLevel.NONE,
        ),
        llm_generate=llm_generate,
    )

    console.print(f"\n[accent]{'Resuming' if resume else 'Starting'} autonomous research...[/accent]")
    console.print(f"  Target:   {engagement.target_url}")
    console.print(f"  Workspace: {runner.workspace_dir}\n")

    with console.status("[cyan]Researching…[/cyan]"):
        try:
            if resume:
                result = await runner.resume()
            else:
                result = await runner.run()
        except KeyboardInterrupt:
            console.print("\n[yellow]Engagement interrupted. Resume with: demogorgon resume[/yellow]")
            return
        except Exception as e:
            console.print(f"\n[red]Engagement failed: {e}[/red]")
            console.print("State saved. Resume with: demogorgon resume")
            return

    if result.get("error"):
        console.print(f"\n[red]Engagement error: {result['error']}[/red]")
    else:
        console.print(Panel(
            f"[green]Engagement Complete[/green]\n"
            f"  Findings: {result.get('findings_count', 0)}\n"
            f"  Chains:   {result.get('chains_count', 0)}\n"
            f"  Duration: {result.get('duration', 0):.1f}s"
            + (f"\n  Report:   {result['report_path']}" if result.get("report_path") else ""),
            border_style="green",
            title="Results",
        ))


async def cmd_interactive():
    """Interactive menu — unified panel menu."""
    print_banner()

    menu = (
        "[bold cyan]How do you want to start?[/bold cyan]\n\n"
        "  [bold white]1[/bold white]  📋  Paste bug bounty program policy\n"
        "  [bold white]2[/bold white]  🎯  Quick hunt (enter target URL/domain)\n"
        "  [bold white]3[/bold white]  ▶   Resume engagement\n"
        "  [bold white]4[/bold white]  ⚙   Setup / providers / models\n"
        "  [bold white]5[/bold white]  🩺  Diagnostics (doctor)\n"
        "  [bold white]6[/bold white]  📊  Show status\n"
        "  [bold white]7[/bold white]  🔍  Show findings\n"
        "  [bold white]8[/bold white]  📄  Generate report\n"
        "  [bold white]9[/bold white]  🌐  Launch web dashboard\n"
        "  [bold white]0[/bold white]  ✕   Exit"
    )
    console.print(Panel(menu, border_style="cyan", title="Demogorgon", title_align="left"))

    choice = Prompt.ask(
        "Select",
        choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "0"],
        default="1",
        console=console,
    )

    if choice == "1":
        await cmd_program()
    elif choice == "2":
        url = Prompt.ask("Enter target URL/domain", console=console)
        await cmd_target(url)
    elif choice == "3":
        await cmd_resume()
    elif choice == "4":
        await cmd_config()
    elif choice == "5":
        await cmd_doctor()
    elif choice == "6":
        await cmd_status()
    elif choice == "7":
        await cmd_findings()
    elif choice == "8":
        await cmd_report()
    elif choice == "9":
        await _launch_web()
    # 0 = exit


async def _launch_web():
    """Launch the web control center."""
    try:
        from demogorgon.web import start as web_start
        console.print("[cyan]Launching web dashboard…[/cyan]")
        await asyncio.to_thread(web_start, ["web"])
    except ImportError:
        console.print("[red]Web UI not available. Install:[/red]")
        console.print("  pip install fastapi 'uvicorn[standard]' websockets")
    except Exception as e:
        console.print(f"[red]Failed to launch web: {e}[/red]")


async def cmd_program():
    """Paste and parse a bug bounty program."""
    print_banner()
    print_header("Paste Program Policy")
    console.print("Paste the complete program guidelines.")
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

    with console.status("[cyan]Parsing program…[/cyan]"):
        from demogorgon.core.scope.parser import parse_program_policy
        policy = parse_program_policy(program_text)

    console.print("[green]✓ Program parsed successfully[/green]\n")

    table = info_table(
        [
            ("Program", policy.program_name),
            ("Platform", policy.platform),
            ("In-Scope", str(len(policy.in_scope))),
            ("Out-of-Scope", str(len(policy.out_of_scope))),
            ("Restrictions", str(len(policy.restrictions))),
            ("Allowed Vulns", ", ".join(policy.allowed_vulnerabilities) or "Not specified"),
            ("Forbidden", ", ".join(policy.forbidden_vulnerabilities) or "Not specified"),
            ("Account Creation", "Allowed" if policy.account_creation_allowed else "Not Allowed"),
            ("Safe Harbor", "Yes" if policy.safe_harbor else "Not specified"),
        ],
        title="Parsed Policy",
    )
    console.print(table)

    if policy.in_scope:
        console.print("\n[bold]In-Scope Assets:[/bold]")
        for asset in policy.in_scope[:20]:
            console.print(f"  • [green]{asset.pattern}[/green] ({asset.asset_type})")
        if len(policy.in_scope) > 20:
            console.print(f"  … and {len(policy.in_scope) - 20} more")

    if policy.restrictions:
        console.print("\n[bold]Restrictions:[/bold]")
        for r in policy.restrictions:
            console.print(f"  [yellow]![/yellow] {r.category}: {r.description}")

    if Confirm.ask("\n[bold]Create engagement?[/bold]", default=True, console=console):
        from demogorgon.core.engagement.manager import EngagementManager
        manager = EngagementManager()
        engagement = manager.create_from_policy(program_text)

        console.print(f"[green]Engagement created: {engagement.id}[/green]")
        console.print(f"Workspace: {engagement.workspace_dir}")

        console.print("\n[bold yellow]Authorization Required[/bold yellow]")
        console.print("Confirm you are authorized to test this target.")
        if Confirm.ask("[bold]Are you authorized to test this target?[/bold]", default=False, console=console):
            from demogorgon.core.engagement import AuthorizationStatus, EngagementStatus
            engagement.authorization_status = AuthorizationStatus.CONFIRMED
            engagement.status = EngagementStatus.ACTIVE
            engagement.save(str(Path(engagement.workspace_dir) / "engagement.json"))
            console.print("[green]Authorization confirmed. Engagement active.[/green]")
            await _run_engagement(engagement)
        else:
            console.print("[red]Authorization not confirmed. Engagement paused.[/red]")


async def cmd_target(url: str):
    """Create engagement from a target URL."""
    print_banner()
    print_header(f"Target: {url}")

    console.print("[bold yellow]Authorization Required[/bold yellow]")
    console.print("Demogorgon assumes NO authorization unless explicitly confirmed.")
    console.print(f"Is [cyan]{url}[/cyan] an authorized bug bounty target?")

    if not Confirm.ask("[bold]Are you authorized?[/bold]", default=False, console=console):
        console.print("[red]Authorization not confirmed. Cannot proceed.[/red]")
        console.print("\nTo test an authorized target, run:")
        console.print("  [cyan]demogorgon --program[/cyan]  (then paste the program policy)")
        return

    from demogorgon.core.engagement.manager import EngagementManager
    from demogorgon.core.engagement import AuthorizationStatus, EngagementStatus

    manager = EngagementManager()
    engagement = manager.create_from_url(url)
    engagement.authorization_status = AuthorizationStatus.CONFIRMED
    engagement.status = EngagementStatus.ACTIVE
    engagement.save(str(Path(engagement.workspace_dir) / "engagement.json"))

    console.print(f"[green]Engagement created and authorized: {engagement.id}[/green]")
    console.print(f"Workspace: {engagement.workspace_dir}")

    await _run_engagement(engagement)


async def cmd_resume():
    """Resume an existing engagement."""
    print_banner()
    print_header("Resume Engagement")

    from demogorgon.core.engagement.manager import EngagementManager
    manager = EngagementManager()
    engagements = manager.list_engagements()

    if not engagements:
        console.print("[yellow]No engagements found.[/yellow]")
        return

    table = Table(show_header=True, border_style="cyan")
    table.add_column("#", style="dim", width=4)
    table.add_column("ID", style="bold cyan")
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

    choice = Prompt.ask("\nSelect engagement number", default="1", console=console)
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(engagements):
            eng_id = engagements[idx]["id"]
            console.print(f"[cyan]Resuming engagement: {eng_id}[/cyan]")
            engagement = manager.load(eng_id)
            if engagement:
                await _run_engagement(engagement, resume=True)
            else:
                console.print(f"[red]Could not load engagement: {eng_id}[/red]")
    except (ValueError, IndexError):
        console.print("[red]Invalid selection.[/red]")


async def cmd_config():
    """Configuration wizard."""
    from demogorgon.cli.setup import run_setup_wizard
    await run_setup_wizard()


async def cmd_doctor():
    """Diagnostics with spinner + table output."""
    print_banner()
    print_header("Diagnostics")

    checks = []

    py_version = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    py_ok = sys.version_info >= (3, 11)
    checks.append(("Python", py_version, py_ok))

    deps = [
        ("rich", "rich"),
        ("httpx", "httpx"),
        ("openai", "openai"),
        ("pydantic", "pydantic"),
        ("fastapi", "fastapi"),
        ("playwright", "playwright"),
        ("beautifulsoup4", "bs4"),
    ]

    with console.status("[cyan]Checking components…[/cyan]"):
        for name, module in deps:
            try:
                __import__(module)
                checks.append((name, "Installed", True))
            except ImportError:
                checks.append((name, "Not installed", False))

    env_exists = Path(".env").exists()
    if env_exists:
        checks.append((".env", "Exists", True))
    else:
        wizard_saved = False
        try:
            from demogorgon.config.provider_config import ProviderConfigManager
            active = ProviderConfigManager().get_active_profile()
            wizard_saved = active is not None and bool(
                active.api_key or active.provider == "ollama"
            )
        except Exception:
            pass
        if wizard_saved:
            checks.append(("LLM config", "Saved by setup wizard", True))
        else:
            checks.append((".env", "Missing — run: demogorgon setup", False))

    table = Table(show_header=True, border_style="cyan")
    table.add_column("Component", min_width=14)
    table.add_column("Status", width=8)
    table.add_column("Detail")

    for name, detail, ok in checks:
        status = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        table.add_row(name, status, detail)

    console.print(table)

    console.print("\n[bold]LLM Diagnostics[/bold]\n")

    from demogorgon.llm.manager import AIProviderManager, PROVIDER_ENV_MAP

    mgr = AIProviderManager()
    mgr.configure()

    llm_table = Table(show_header=True, border_style="cyan")
    llm_table.add_column("Check", min_width=14)
    llm_table.add_column("Result")

    llm_table.add_row("Provider", mgr._active_provider or "[red]NOT CONFIGURED[/red]")
    llm_table.add_row("Model", mgr._active_model or "N/A")

    api_key = (
        mgr._env.get("DEMOGORGON_API_KEY")
        or mgr._env.get("LLM_API_KEY")
        or next((mgr._env[k] for k in PROVIDER_ENV_MAP if mgr._env.get(k)), "")
    )
    if api_key:
        masked = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) > 8 else "SET"
        llm_table.add_row("API Key", f"[green]{masked}[/green]")
    elif mgr.available:
        llm_table.add_row("API Key", "[green]Not required (local provider)[/green]")
    else:
        llm_table.add_row("API Key", "[red]NOT CONFIGURED[/red]")

    if mgr.available:
        with console.status("[cyan]Checking connectivity…[/cyan]"):
            health = await mgr.health_check()
        connectivity = health.get("connectivity", "UNKNOWN")
        status_style = "green" if connectivity == "OK" else "red"
        llm_table.add_row("Connectivity", f"[{status_style}]{connectivity}[/{status_style}]")
        if health.get("latency"):
            llm_table.add_row("Latency", f"{health['latency']:.2f}s")
    else:
        llm_table.add_row("Connectivity", "[yellow]SKIPPED (not configured)[/yellow]")

    console.print(llm_table)

    console.print("\n[bold]LLM Smoke Test[/bold]\n")
    if mgr.available:
        with console.status("[cyan]Running smoke test…[/cyan]"):
            smoke = await mgr.smoke_test()

        smoke_table = Table(show_header=False, border_style="cyan")
        smoke_table.add_column("Key", style="bold cyan", min_width=16)
        smoke_table.add_column("Value")
        smoke_table.add_row("Provider", smoke.get("provider", "unknown"))
        smoke_table.add_row("Model", smoke.get("model", "unknown"))
        smoke_table.add_row("Latency", f"{smoke.get('latency', 0):.2f}s")

        status = smoke.get("status", "unknown")
        s_style = "green" if status == "ok" else "red"
        smoke_table.add_row("Status", f"[{s_style}]{status.upper()}[/{s_style}]")

        structured = smoke.get("structured_output", "N/A")
        st_style = "green" if structured == "OK" else "red"
        smoke_table.add_row("Structured Output", f"[{st_style}]{structured}[/{st_style}]")

        if smoke.get("error"):
            smoke_table.add_row("Error", f"[red]{str(smoke['error'])[:100]}[/red]")
        if smoke.get("missing_fields"):
            smoke_table.add_row("Missing Fields", str(smoke["missing_fields"]))

        console.print(smoke_table)
    else:
        console.print("[yellow]Skipped (no LLM provider configured)[/yellow]")

    console.print()


async def cmd_findings():
    """Show findings from the most recent engagement as a styled table."""
    print_banner()
    print_header("Findings")

    from demogorgon.core.engagement.manager import EngagementManager
    from demogorgon.core.state.manager import StateManager

    manager = EngagementManager()
    engagements = manager.list_engagements()

    if not engagements:
        console.print("[yellow]No engagements found.[/yellow]")
        return

    eng = engagements[-1]
    workspace = eng.get("workspace_dir", "")

    if not workspace:
        console.print("[yellow]No workspace found for engagement.[/yellow]")
        return

    with console.status("[cyan]Loading findings…[/cyan]"):
        state_manager = StateManager(workspace)
        state_manager.load_state()
        case_data = state_manager.load_case()

    if not case_data:
        console.print("[yellow]No research data found.[/yellow]")
        return

    findings = case_data.get("findings", [])
    if not findings:
        console.print("[yellow]No findings yet.[/yellow]")
        return

    console.print(f"Engagement: [bold]{eng.get('name', eng['id'])}[/bold]  "
                  f"({len(findings)} findings)\n")
    console.print(findings_table(findings))

    # Severity breakdown
    counts: dict[str, int] = {}
    for f in findings:
        s = str(f.get("severity", "unknown")).lower()
        counts[s] = counts.get(s, 0) + 1
    parts = [f"{sev_badge(s)}: {n}" for s, n in sorted(counts.items())]
    console.print("\n" + "  ".join(parts))


async def cmd_report():
    """Generate report from the most recent engagement."""
    print_banner()
    print_header("Generate Report")

    from demogorgon.core.engagement.manager import EngagementManager
    from demogorgon.core.state.manager import StateManager
    from demogorgon.core.reporting.generator import ReportGenerator, Finding

    manager = EngagementManager()
    engagements = manager.list_engagements()

    if not engagements:
        console.print("[yellow]No engagements found.[/yellow]")
        return

    eng = engagements[-1]
    workspace = eng.get("workspace_dir", "")

    if not workspace:
        console.print("[yellow]No workspace found.[/yellow]")
        return

    with console.status("[cyan]Loading research data…[/cyan]"):
        state_manager = StateManager(workspace)
        case_data = state_manager.load_case()

    if not case_data:
        console.print("[yellow]No research data to report on.[/yellow]")
        return

    findings_data = case_data.get("findings", [])
    findings = []
    for f in findings_data:
        findings.append(
            Finding(
                title=f.get("title", "Untitled"),
                severity=f.get("severity", "unknown"),
                vuln_class=f.get("vuln_class", ""),
                endpoint=f.get("endpoint", ""),
                description=f.get("description", ""),
                impact=f.get("impact", ""),
                remediation=f.get("remediation", ""),
                reproduction_steps=f.get("steps_to_reproduce", []),
            )
        )

    with console.status("[cyan]Generating report…[/cyan]"):
        gen = ReportGenerator(workspace_dir=workspace)
        report = gen.generate(
            findings=findings,
            target=eng.get("target", ""),
            program=eng.get("name", ""),
        )
        json_path = gen.save_json(report)
        md_path = gen.save_markdown(report)

    sevs = sorted({str(f.get("severity", "")) for f in findings_data})
    console.print(
        Panel(
            f"[green]Report generated[/green]\n\n"
            f"  JSON:       {json_path}\n"
            f"  Markdown:   {md_path}\n"
            f"  Findings:   {len(findings)} across {len(sevs)} severity level(s)",
            border_style="green",
            title="Report",
        )
    )

    if findings_data:
        console.print(findings_table(findings_data))


async def cmd_status():
    """Show status of the most recent engagement."""
    print_banner()
    print_header("Engagement Status")

    from demogorgon.core.engagement.manager import EngagementManager
    from demogorgon.core.state.manager import StateManager

    manager = EngagementManager()
    engagements = manager.list_engagements()

    if not engagements:
        console.print("[yellow]No engagements found.[/yellow]")
        return

    eng = engagements[-1]
    workspace = eng.get("workspace_dir", "")

    if not workspace:
        console.print("[yellow]No workspace found.[/yellow]")
        return

    with console.status("[cyan]Loading state…[/cyan]"):
        state_manager = StateManager(workspace)
        summary = state_manager.get_summary()

    rows = [
        ("Engagement", eng.get("id", "unknown")),
        ("Target", eng.get("target", "unknown")),
        ("Status", eng.get("status", "unknown")),
        ("Workspace", workspace),
    ]

    if summary.get("has_state"):
        state = summary.get("state", {})
        if state:
            rows.append(("Iteration", str(state.get("iteration", 0))))
            rows.append(("Strategy", state.get("strategy", "unknown")))
            rows.append(("Findings", str(state.get("findings_count", 0))))

    rows.append(("Checkpoints", str(summary.get("checkpoint_count", 0))))
    rows.append(("Has Case Data", "Yes" if summary.get("has_case") else "No"))

    console.print(status_table(rows))


async def cmd_tools(subcmd: str | None = None, tool_name: str | None = None):
    """Inspect or install external security tools."""
    from demogorgon.tools.installer import ToolInstaller, INSTALL_RECIPES

    installer = ToolInstaller()

    if subcmd in (None, "list", "status"):
        print_banner()
        print_header("Security Tools")
        report = installer.status_report()
        table = Table(show_header=True, border_style="cyan")
        table.add_column("Tool", min_width=12)
        table.add_column("Status", width=10)
        table.add_column("Priority", width=8)
        table.add_column("Description")
        table.add_column("Path")
        for row in report:
            status = "[green]OK[/green]" if row["available"] else "[red]MISSING[/red]"
            prio = str(INSTALL_RECIPES.get(row["tool"], {}).get("priority", "-"))
            table.add_row(
                row["tool"], status, prio,
                row.get("description", ""), row.get("path", ""),
            )
        console.print(table)
        missing = [r["tool"] for r in report if not r["available"]]
        if missing:
            console.print(
                f"\n[yellow]Missing:[/yellow] {', '.join(missing)}\n"
                f"[dim]Install with:[/dim] demogorgon tools install"
            )
        return

    if subcmd == "install":
        print_banner()
        print_header("Install Tools")
        if tool_name and tool_name not in INSTALL_RECIPES:
            console.print(f"[red]Unknown tool:[/red] {tool_name}")
            console.print(f"[dim]Known:[/dim] {', '.join(INSTALL_RECIPES)}")
            return
        targets = [tool_name] if tool_name else None
        with console.status("[cyan]Installing missing tools…[/cyan]"):
            if tool_name:
                result = await installer.install(tool_name)
                results = [result]
            else:
                results = await installer.install_missing(targets)
        table = Table(show_header=True, border_style="cyan")
        table.add_column("Tool")
        table.add_column("Status", width=16)
        table.add_column("Method", width=8)
        table.add_column("Message")
        for r in results:
            style = {
                "installed": "green",
                "already_installed": "dim",
                "failed": "red",
            }.get(r.status, "yellow")
            table.add_row(r.tool, f"[{style}]{r.status}[/{style}]", r.method, r.message[:80])
        console.print(table)
        console.print(f"\n[dim]{installer.summary()}[/dim]")
        return

    console.print("[yellow]Usage:[/yellow] demogorgon tools [list|install] [tool]")


async def cmd_metrics(path: str | None = None):
    """Show hunt metrics from metrics.json."""
    print_banner()
    print_header("Hunt Metrics")

    from demogorgon.core.metrics import MetricsCollector

    metrics_path = Path(path or "hunt_output/metrics.json")
    metrics = MetricsCollector.load(metrics_path)
    if not metrics:
        console.print(f"[yellow]No metrics found at {metrics_path}[/yellow]")
        console.print("[dim]Run a hunt first, or pass a path: demogorgon metrics path/to/metrics.json[/dim]")
        return

    m = metrics
    rows = [
        ("Target", m.target or "unknown"),
        ("Runtime", f"{m.runtime_seconds:.0f}s"),
        ("Endpoints discovered", str(m.endpoints_discovered)),
        ("Subdomains", str(m.subdomains_discovered)),
        ("Live hosts", str(m.live_hosts)),
        ("Experiments run", str(m.experiments_run)),
        ("Requests made", str(m.requests_made)),
        ("Parallel batches", f"{m.parallel_batches} ({m.parallel_requests} req)"),
        ("LLM calls", f"{m.llm_calls} ({m.llm_failures} failed)"),
        ("Findings", str(m.findings_total)),
        ("Reportable (≥85%)", str(m.reportable_count)),
        ("Findings/min", f"{m.findings_per_minute:.2f}"),
        ("Endpoints/min", f"{m.endpoints_per_minute:.2f}"),
    ]
    if m.findings_by_severity:
        sev = ", ".join(f"{k}:{v}" for k, v in sorted(m.findings_by_severity.items()))
        rows.append(("By severity", sev))
    if m.findings_by_class:
        cls = ", ".join(f"{k}:{v}" for k, v in sorted(m.findings_by_class.items()))
        rows.append(("By class", cls))
    if m.tools_invoked:
        tools = ", ".join(f"{k}:{v}" for k, v in sorted(m.tools_invoked.items()))
        rows.append(("Tools invoked", tools))
    if m.vuln_classes_tested:
        rows.append(("Vuln classes tested", ", ".join(sorted(m.vuln_classes_tested))))

    console.print(status_table(rows))


def _sync_main():
    """Console-script entry: wrap async main in asyncio.run."""
    asyncio.run(main())


async def main():
    """Main CLI entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="demogorgon",
        description="Demogorgon — Autonomous Bug Bounty Researcher",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
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
  demogorgon web                          Launch web dashboard
  demogorgon tools                        List/install security tools
  demogorgon tools install [tool]         Install missing tools
  demogorgon metrics                      Show hunt metrics

Version: {VERSION}
        """,
    )

    parser.add_argument("target", nargs="?", help="Target URL/domain")
    parser.add_argument("--program", action="store_true", help="Paste program policy")
    parser.add_argument(
        "command",
        nargs="?",
        choices=[
            "resume", "status", "findings", "report", "setup",
            "doctor", "web", "help", "tools", "metrics",
        ],
        help="Command to run",
    )
    parser.add_argument(
        "subcommand",
        nargs="?",
        help="Subcommand (e.g. tools install <name>)",
    )
    parser.add_argument(
        "tool",
        nargs="?",
        help="Tool name for 'tools install'",
    )

    args = parser.parse_args()

    known_commands = {
        "resume", "status", "findings", "report", "setup",
        "doctor", "web", "help", "tools", "metrics",
    }
    if args.target in known_commands and not args.command:
        args.command = args.target
        args.target = None

    if args.command == "help":
        parser.print_help()
    elif args.program:
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
    elif args.command == "web":
        await _launch_web()
    elif args.command == "tools":
        await cmd_tools(args.subcommand, args.tool)
    elif args.command == "metrics":
        await cmd_metrics(args.target or args.subcommand)
    elif args.target:
        await cmd_target(args.target)
    else:
        await cmd_interactive()


if __name__ == "__main__":
    _sync_main()
