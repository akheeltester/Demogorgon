"""Allow running as: python -m demogorgon"""

import asyncio
from demogorgon.main import main

if __name__ == "__main__":
    asyncio.run(main())
