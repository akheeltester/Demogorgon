"""Demogorgon — Autonomous Bug Bounty Researcher.

Usage:
    python -m demogorgon                              # Interactive menu
    python -m demogorgon agent                         # Interactive agent
    python -m demogorgon agent https://example.com     # Agent with target
    python -m demogorgon https://example.com           # Quick scan
    python -m demogorgon --program                     # Paste program policy
    python -m demogorgon resume                        # Resume engagement
    python -m demogorgon doctor                        # Diagnostics
"""

import asyncio
import sys


def main():
    # Check for agent mode
    if len(sys.argv) > 1 and sys.argv[1] == "agent":
        from demogorgon.agent.main import AgentMain

        agent = AgentMain()
        target = sys.argv[2] if len(sys.argv) > 2 else ""

        asyncio.run(agent.start(target=target, interactive=not bool(target)))
    else:
        from demogorgon.cli import main as cli_main
        asyncio.run(cli_main())


if __name__ == "__main__":
    main()
