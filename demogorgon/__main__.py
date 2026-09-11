"""Demogorgon — Autonomous Bug Bounty Researcher.

Usage:
    python -m demogorgon                              # Interactive menu
    python -m demogorgon https://example.com          # Quick scan
    python -m demogorgon --program                    # Paste program policy
    python -m demogorgon resume                       # Resume engagement
    python -m demogorgon doctor                       # Diagnostics
"""

import asyncio
from demogorgon.cli import main

if __name__ == "__main__":
    asyncio.run(main())
