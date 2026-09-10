"""
Demogorgon Programs — Bug Bounty Program-Specific Modules
========================================================
Each subfolder contains program-specific configurations, executors,
and report templates for a specific bug bounty program.

Available Programs:
    - vk: VK (vk.com) Bug Bounty Program
"""

from . import vk

__all__ = ["vk"]
