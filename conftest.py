"""Pytest-wide settings for the Demogorgon test suite.

Tests must never spend minutes waiting on live recon binaries (subfinder,
crt.sh, nmap) against unreachable test domains. Bound recon stages tightly
so the suite stays fast and deterministic.
"""

import os

# Seconds per recon stage during tests (0 = disabled). The production
# default is 60s; tests use 5s so a dead network cannot stall the suite.
os.environ.setdefault("DEMOGORGON_RECON_TIMEOUT", "5")
