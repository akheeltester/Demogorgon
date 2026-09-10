"""Allow running as: python -m sentinel_v2"""

import asyncio
from sentinel_v2.main import main

if __name__ == "__main__":
    asyncio.run(main())
