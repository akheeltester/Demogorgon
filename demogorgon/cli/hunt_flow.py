"""Guided hunt flow — colorful CLI onboarding, run as a strict state machine.

States (each state has exactly one input function; paste mode never runs
path validation, file mode never runs the multiline reader):

    TARGET_INPUT  → SCOPE_SOURCE  →  FILE_INPUT | PASTE_INPUT | TARGET_ONLY
                 → DOCUMENT_PARSE → SCOPE_REVIEW → AUTH_CONFIRM → HUNT_START

Usage:
    demogorgon                       # guided hunt
    demogorgon https://example.com   # guided hunt, target prefilled
    demogorgon --program             # guided hunt (program-document intake)
"""

from __future__ import annotations

import re
import select
import sys
from enum import Enum
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
MAX_FILE_ATTEMPTS = 3
PASTE_SENTINEL = "END"


class HuntPhase(Enum):
    """Explicit states of the guided hunt."""

    TARGET_INPUT = "target_input"
    SCOPE_SOURCE = "scope_source"
    FILE_INPUT = "file_input"
    PASTE_INPUT = "paste_input"
    DOCUMENT_PARSE = "document_parse"
    SCOPE_REVIEW = "scope_review"
    AUTH_CONFIRM = "auth_confirm"
    HUNT_START = "hunt_start"
    ABORTED = "aborted"


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


# ── State-specific input readers ─────────────────────────────────────────

def _drain_pending_stdin(timeout: float = 0.05) -> str:
    """Return any input lines already buffered in stdin (a multi-line paste).

    Prevents the classic bug where a pasted policy gets consumed as answers
    to later prompts ("Try another path?" / extra-scope questions).
    """
    if not sys.stdin.isatty():
        return ""
    chunks: list[str] = []
    while True:
        ready, _, _ = select.select([sys.stdin], [], [], timeout)
        if not ready:
            break
        line = sys.stdin.readline()
        if not line:
            break
        chunks.append(line)
        timeout = 0.02  # rest of the same paste arrives together
    return "".join(chunks)


def _prompt_file_path() -> tuple[str, str]:
    """FILE_INPUT state reader.

    Returns ("path", path) for a single-line path entry, or
    ("paste", text) when the user pasted a whole policy into the prompt
    (detected via buffered follow-up lines).
    """
    first = Prompt.ask(
        "\n[bold cyan]📄[/bold cyan] Program document path (drag & drop, then Enter)",
        console=console,
    )
    pending = _drain_pending_stdin()
    if pending.strip():
        return "paste", f"{first}\n{pending}".strip()
    return "path", first


def _read_pasted_policy() -> str:
    """PASTE_INPUT state reader — sentinel-terminated multiline input.

    Never validates paths; EOF also terminates.
    """
    console.print(
        f"\nPaste the program policy. [cyan]{PASTE_SENTINEL}[/cyan] on a new "
        "line to finish (Ctrl+D also works).\n"
    )
    lines: list[str] = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line.strip() == PASTE_SENTINEL:
            break
        lines.append(line)
    return "\n".join(lines)


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
    parsed_policy=None,
):
    """Create an authorized engagement from the collected target/scope/document.

    ``parsed_policy`` (if given) is the already-parsed ProgramPolicy from the
    DOCUMENT_PARSE state — raw text and parsed policy are kept separate:
    the raw text is saved verbatim by the manager, the parsed policy is used
    for scope enforcement.
    """
    from demogorgon.core.engagement import AuthorizationStatus, EngagementStatus, ScopeAsset
    from demogorgon.core.engagement.manager import EngagementManager

    manager = (
        EngagementManager(workspace_root=workspace_root) if workspace_root else EngagementManager()
    )

    if parsed_policy is not None and program_text.strip():
        engagement = manager.create_from_parsed_policy(parsed_policy, program_text)
    elif program_text.strip():
        engagement = manager.create_from_policy(program_text)
    else:
        engagement = manager.create_from_url(target)

    engagement.target_url = target
    for pattern in extras:
        engagement.policy.in_scope.append(ScopeAsset(
            pattern=pattern,
            asset_type="url" if pattern.startswith(("http://", "https://")) else "domain",
            source="user_input",
            source_section="user_input",
            inclusion_state="in_scope",
            confidence=1.0,
            description="Added by user during guided hunt",
        ))
    if not engagement.policy.in_scope:
        engagement.policy.in_scope.append(ScopeAsset(
            pattern=target,
            asset_type="url",
            source="user_input",
            source_section="target_only",
            inclusion_state="in_scope",
            confidence=1.0,
            description="User-provided target (no assets found in document)",
        ))

    engagement.authorization_status = AuthorizationStatus.CONFIRMED
    engagement.status = EngagementStatus.ACTIVE
    engagement.save(str(Path(engagement.workspace_dir) / "engagement.json"))
    return engagement


async def guided_hunt(target: str | None = None) -> None:
    """State-machine guided flow: target → scope → document → review → hunt."""
    phase = HuntPhase.TARGET_INPUT
    try:
        print_banner()
        print_header("Guided Hunt")

        console.print(Panel(
            "[cyan]1[/cyan] Target  [cyan]2[/cyan] Scope  [cyan]3[/cyan] Program doc → Hunt",
            border_style="cyan",
            title="Steps",
            title_align="left",
        ))

        # ── TARGET_INPUT ───────────────────────────────────────────
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

        # ── SCOPE_SOURCE ───────────────────────────────────────────
        phase = HuntPhase.SCOPE_SOURCE
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
            # ── FILE_INPUT ─────────────────────────────────────────
            phase = HuntPhase.FILE_INPUT
            for attempt in range(MAX_FILE_ATTEMPTS):
                kind, value = _prompt_file_path()
                if kind == "paste":
                    # User pasted a policy instead of a path — switch state.
                    phase = HuntPhase.PASTE_INPUT
                    program_text = value
                    console.print(
                        f"  [green]✓[/green] Pasted {len(program_text):,} characters"
                    )
                    break
                try:
                    program_text = read_program_file(value)
                    console.print(f"  [green]✓[/green] Loaded {len(program_text):,} characters")
                    break
                except (FileNotFoundError, ValueError) as e:
                    console.print(f"  [red]✗ {e}[/red]")
                    remaining = MAX_FILE_ATTEMPTS - attempt - 1
                    if remaining and Confirm.ask(
                        "  Try another path?", default=True, console=console
                    ):
                        continue
                    console.print("  [yellow]Falling back to target-only scope.[/yellow]")
                    choice = "3"
                    break
            else:
                console.print("  [yellow]Too many failed attempts — target-only scope.[/yellow]")
                choice = "3"
        elif choice == "2":
            # ── PASTE_INPUT (never touches path validation) ─────────
            phase = HuntPhase.PASTE_INPUT
            program_text = _read_pasted_policy()
            if not program_text.strip():
                console.print("  [yellow]No text pasted — using target-only scope.[/yellow]")
                choice = "3"

        # ── DOCUMENT_PARSE ─────────────────────────────────────────
        phase = HuntPhase.DOCUMENT_PARSE
        policy = None
        validation = None
        if program_text.strip():
            with console.status("[cyan]Parsing program document…[/cyan]"):
                from demogorgon.core.scope.parser import parse_program_policy
                from demogorgon.core.scope.validator import PolicyValidator
                policy = parse_program_policy(program_text)
                validation = PolicyValidator().validate(policy)
            console.print("\n[green]✓ Program parsed successfully[/green]")
            show_policy(policy)
            for warning in validation.warnings:
                console.print(f"  [yellow]⚠ {warning}[/yellow]")
            if not policy.in_scope:
                console.print(
                    "  [yellow]⚠ No in-scope assets detected in the document — "
                    "the target itself will be used.[/yellow]"
                )

        # ── SCOPE_REVIEW ───────────────────────────────────────────
        phase = HuntPhase.SCOPE_REVIEW
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

        # ── AUTH_CONFIRM ───────────────────────────────────────────
        phase = HuntPhase.AUTH_CONFIRM
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
            phase = HuntPhase.ABORTED
            console.print("\n[red]Authorization not confirmed — hunt not started.[/red]")
            console.print("Run [cyan]demogorgon menu[/cyan] for all commands.")
            return

        # ── HUNT_START ─────────────────────────────────────────────
        phase = HuntPhase.HUNT_START
        engagement = _create_engagement(
            program_text, target, extras, parsed_policy=policy
        )

        console.print(f"\n[green]✓ Engagement [bold]{engagement.id}[/bold] authorized[/green]")
        console.print(f"  Workspace: [dim]{engagement.workspace_dir}[/dim]\n")

        from . import _run_engagement
        await _run_engagement(engagement)
    except (KeyboardInterrupt, EOFError):
        console.print(
            f"\n[yellow]Cancelled during {phase.value.replace('_', ' ')}.[/yellow]"
            " Run [cyan]demogorgon menu[/cyan] for all commands."
        )
