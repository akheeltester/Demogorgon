"""Tools available to the Researcher.

Each tool is a dumb function. The researcher decides when and how to use it.
"""

# Lazy imports — playwright is only needed when BrowserTool is actually used
__all__ = [
    "BrowserTool", "HTTPClient", "AuthManager", "AuthSession",
    "Crawler", "Checkpoint", "ToolBus", "Recon",
    "NucleiBridge", "FfufBridge", "KatanaBridge", "AmassBridge",
    "Reporter", "Notifier",
]


def __getattr__(name: str):
    if name == "BrowserTool":
        from sentinel_v2.tools.browser import BrowserTool
        return BrowserTool
    elif name == "HTTPClient":
        from sentinel_v2.tools.http_client import HTTPClient
        return HTTPClient
    elif name in ("AuthManager", "AuthSession"):
        from sentinel_v2.tools.auth import AuthManager, AuthSession
        return AuthManager if name == "AuthManager" else AuthSession
    elif name == "Crawler":
        from sentinel_v2.tools.crawler import Crawler
        return Crawler
    elif name == "Checkpoint":
        from sentinel_v2.tools.checkpoint import Checkpoint
        return Checkpoint
    elif name == "ToolBus":
        from sentinel_v2.tools.tool_bus import ToolBus
        return ToolBus
    elif name == "Recon":
        from sentinel_v2.tools.recon import Recon
        return Recon
    elif name == "NucleiBridge":
        from sentinel_v2.tools.nuclei_bridge import NucleiBridge
        return NucleiBridge
    elif name == "FfufBridge":
        from sentinel_v2.tools.ffuf_bridge import FfufBridge
        return FfufBridge
    elif name == "KatanaBridge":
        from sentinel_v2.tools.katana_bridge import KatanaBridge
        return KatanaBridge
    elif name == "AmassBridge":
        from sentinel_v2.tools.amass_bridge import AmassBridge
        return AmassBridge
    elif name == "Reporter":
        from sentinel_v2.tools.reporter import Reporter
        return Reporter
    elif name == "Notifier":
        from sentinel_v2.tools.notifier import Notifier
        return Notifier
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
