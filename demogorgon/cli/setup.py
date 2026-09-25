"""Setup Wizard for Demogorgon.

Thin wrapper around the canonical wizard in `demogorgon.config.terminal_setup`
so `demogorgon setup` and `python -m demogorgon setup` run the same flow:
provider → connect (test) → model discovery → save (~/.demogorgon + .env).
"""

from __future__ import annotations

from ..config.terminal_setup import run_setup_wizard as _run_wizard


async def run_setup_wizard():
    """Interactive wizard to configure providers and models."""
    return await _run_wizard()
