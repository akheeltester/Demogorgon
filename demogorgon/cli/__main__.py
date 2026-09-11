"""Demogorgon CLI — entry point for `python -m demogorgon`."""

from __future__ import annotations

import asyncio
from demogorgon.cli import main

if __name__ == "__main__":
    asyncio.run(main())
