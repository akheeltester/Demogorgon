"""Guided hunt flow — colorful CLI onboarding.

One flow: target → scope → upload program document → authorization → hunt.

Usage:
    demogorgon                       # guided hunt
    demogorgon https://example.com   # guided hunt, target prefilled
    demogorgon --program             # guided hunt (program-document intake)
"""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from .theme import console, info_table, print_banner, print_header

BINARY_SUFFIXES = {
    ".pdf", ".docx", ".doc", ".zip", ".png", ".jpg", ".jpeg",
    ".gif", ".webp", ".exe", ".gz", ".tar",
}
MAX_DOC_BYTES = 5 * 1024 * 1024


def normalize_target(raw: str) -> str:
    """Validate and normalize a user-supplied target into a URL."""
    target = raw.strip().strip('"').strip("'")
    if not target:
        raise ValueError("Target cannot be empty")
    if not re.match(r"^https?://", target, re.IGNORECASE):
        target = f"https://{target}"
    host = urlparse(target).hostname or ""
    if not host or any(c.isspace() for c in host):
        raise ValueError(f"Could not read a hostname from: {raw.strip()!r}")
    return target


def read_program_file(raw_path: str) -> str:
    """Read a program/policy document from disk (drag-and-drop friendly).

    Accepts quoted paths (terminal drag & drop), ~ expansion, text formats,
    and PDF (via optional pypdf).
    """
    cleaned = raw_path.strip().strip('"').strip("'")
    path = Path(cleaned).expanduser()
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")
    if not path.is_file():
        raise ValueError(f"Not a file: {path}")
    size = path.stat().st_size
    if size == 0:
        raise ValueError(f"File is empty: {path}")
    if size > MAX_DOC_BYTES:
        mb = size // (1024 * 1024)
        raise ValueError(f"File too large ({mb} MB) — max 5 MB. Trim the policy and retry.")

    suffix = path.suffix.lower()
    if suffix == ".pdf":
        try:
            from pypdf import PdfReader
        except ImportError:
            raise ValueError(
                "PDF support needs the 'pypdf' package — run: pip install pypdf "
                "(or export the policy as .txt/.md, or paste the text instead)"
            ) from None
        reader = PdfReader(str(path))
        text = "\n".join((page.extract_text() or "") for page in reader.pages)
        if not text.strip():
            raise ValueError(
                f"No extractable text in {path.name} (scanned PDF?) — paste the policy instead"
            )
        return text
    if suffix in BINARY_SUFFIXES:
        raise ValueError(f"Unsupported file type '{suffix}' — use .txt, .md, .html, .json or .pdf")
    return path.read_text(encoding="utf-8", errors="replace")


def parse_extra_scope(raw: str) -> list[str]:
    """Split a comma/newline separated list of extra scope patterns."""
    parts = re.split(r"[,\n]", raw)
    return [p.strip() for p in parts if p.strip()]


def show_policy(policy) -> None:
    """Render a parsed ProgramPolicy as colorful tables."""
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
        console.print("\n  [bold]In-Scope Assets:[/bold]")
        for asset in policy.in_scope[:20]:
            console.print(f"    • [green]{asset.pattern}[/green] ({asset.asset_type})")
        if len(policy.in_scope) > 20:
            console.print(f"    … and {len(policy.in_scope) - 20} more")

    if policy.out_of_scope:
        console.print("\n  [bold]Out of Scope:[/bold]")
        for asset in policy.out_of_scope[:10]:
            console.print(f"    • [red]{asset.pattern}[/red] ({asset.asset_type})")
        if len(policy.out_of_scope) > 10:
            console.print(f"    … and {len(policy.out_of_scope) - 10} more")

    if policy.restrictions:
        console.print("\n  [bold]Restrictions:[/bold]")
        for r in policy.restrictions:
            console.print(f"    [yellow]![/yellow] {r.category}: {r.description}")


def _create_engagement(
    program_text: str,
    target: str,
    extras: list[str],
    workspace_root: str = "",
):
    """Create an authorized engagement from the collected target/scope/document."""
    from demogorgon.core.engagement import AuthorizationStatus, EngagementStatus, ScopeAsset
    from demogorgon.core.engagement.manager import EngagementManager

    manager = (
        EngagementManager(workspace_root=workspace_root) if workspace_root else EngagementManager()
    )

    if program_text.strip():
        engagement = manager.create_from_policy(program_text)
    else:
        engagement = manager.create_from_url(target)

    engagement.target_url = target
    for pattern in extras:
        engagement.policy.in_scope.append(ScopeAsset(
            pattern=pattern,
            asset_type="url" if pattern.startswith(("http://", "https://")) else "domain",
            source="user_input",
            description="Added by user during guided hunt",
        ))
    if not engagement.policy.in_scope:
        engagement.policy.in_scope.append(ScopeAsset(
            pattern=target,
            asset_type="url",
            source="user_input",
            description="User-provided target (no assets found in document)",
        ))

    engagement.authorization_status = AuthorizationStatus.CONFIRMED
    engagement.status = EngagementStatus.ACTIVE
    engagement.save(str(Path(engagement.workspace_dir) / "engagement.json"))
    return engagement


async def guided_hunt(target: str | None = None) -> None:
    """Colorful guided flow: target → scope → program document → hunt."""
    try:
        print_banner()
        print_header("Guided Hunt")

        console.print(Panel(
            "[cyan]1[/cyan] Target  [cyan]2[/cyan] Scope  [cyan]3[/cyan] Program doc → Hunt",
            border_style="cyan",
            title="Steps",
            title_align="left",
        ))

        # ── Step 1: target ────────────────────────────────────────
        if target:
            try:
                target = normalize_target(target)
                console.print(f"  [green]✓[/green] Target: [bold]{target}[/bold]")
            except ValueError as e:
                console.print(f"  [red]✗ {e}[/red]")
                target = None
        while not target:
            raw = Prompt.ask(
                "\n[bold cyan]Step 1[/bold cyan] 🎯 Target URL or domain", console=console
            )
            try:
                target = normalize_target(raw)
                console.print(f"  [green]✓[/green] Target: [bold]{target}[/bold]")
            except ValueError as e:
                console.print(f"  [red]✗ {e}[/red]")

        # ── Step 2: scope source ──────────────────────────────────
        console.print(Panel(
            "[bold white]1[/bold white]  📄  Upload program document (policy file)\n"
            "[bold white]2[/bold white]  📋  Paste program policy text\n"
            "[bold white]3[/bold white]  ⚡  Target only (no program document)",
            border_style="cyan",
            title="Step 2 · Scope — what are the rules of engagement?",
            title_align="left",
        ))
        choice = Prompt.ask("  Select", choices=["1", "2", "3"], default="1", console=console)

        program_text = ""
        if choice == "1":
            while True:
                doc_path = Prompt.ask(
                    "\n[bold cyan]📄[/bold cyan] Program document path (drag & drop, then Enter)",
                    console=console,
                )
                try:
                    program_text = read_program_file(doc_path)
                    console.print(f"  [green]✓[/green] Loaded {len(program_text):,} characters")
                    break
                except (FileNotFoundError, ValueError) as e:
                    console.print(f"  [red]✗ {e}[/red]")
                    if not Confirm.ask("  Try another path?", default=True, console=console):
                        console.print("  [yellow]Falling back to target-only scope.[/yellow]")
                        choice = "3"
                        break
        elif choice == "2":
            console.print(
                "\nPaste the program policy. [cyan]END[/cyan] on a new line to finish.\n"
            )
            lines: list[str] = []
            while True:
                line = input()
                if line.strip() == "END":
                    break
                lines.append(line)
            program_text = "\n".join(lines)
            if not program_text.strip():
                console.print("  [yellow]No text pasted — using target-only scope.[/yellow]")
                choice = "3"

        policy = None
        if program_text.strip():
            with console.status("[cyan]Parsing program document…[/cyan]"):
                from demogorgon.core.scope.parser import parse_program_policy
                policy = parse_program_policy(program_text)
            console.print("\n[green]✓ Program parsed successfully[/green]")
            show_policy(policy)
            if not policy.in_scope:
                console.print(
                    "  [yellow]⚠ No in-scope assets detected in the document — "
                    "the target itself will be used.[/yellow]"
                )

        extra_raw = Prompt.ask(
            "\n[bold cyan]➕[/bold cyan] Extra in-scope patterns (comma-separated, Enter to skip)",
            default="",
            console=console,
        )
        extras = parse_extra_scope(extra_raw)
        if extras:
            console.print(
                f"  [green]✓[/green] Will add {len(extras)} pattern(s): "
                f"[cyan]{', '.join(extras)}[/cyan]"
            )

        # ── Step 3: authorization → engagement → hunt ─────────────
        scope_desc = (
            f"program document ({len(policy.in_scope)} assets)" if policy else "target only"
        )
        if extras:
            scope_desc += f" + {len(extras)} added"

        console.print(Panel(
            "Demogorgon assumes [bold red]NO[/bold red] authorization.\n"
            f"Target: [cyan]{target}[/cyan]\n"
            f"Scope:  [cyan]{scope_desc}[/cyan]",
            border_style="yellow",
            title="Step 3 · Authorization",
            title_align="left",
        ))
        authorized = Confirm.ask(
            f"  Are you authorized to test [bold]{target}[/bold]?",
            default=False,
            console=console,
        )
        if not authorized:
            console.print("\n[red]Authorization not confirmed — hunt not started.[/red]")
            console.print("Run [cyan]demogorgon menu[/cyan] for all commands.")
            return

        engagement = _create_engagement(program_text, target, extras)

        console.print(f"\n[green]✓ Engagement [bold]{engagement.id}[/bold] authorized[/green]")
        console.print(f"  Workspace: [dim]{engagement.workspace_dir}[/dim]\n")

        from . import _run_engagement
        await _run_engagement(engagement)
    except (KeyboardInterrupt, EOFError):
        console.print(
            "\n[yellow]Cancelled.[/yellow] Run [cyan]demogorgon menu[/cyan] for all commands."
        )
