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
        from demogorgon.tools.browser import BrowserTool
        return BrowserTool
    elif name == "HTTPClient":
        from demogorgon.tools.http_client import HTTPClient
        return HTTPClient
    elif name in ("AuthManager", "AuthSession"):
        from demogorgon.tools.auth import AuthManager, AuthSession
        return AuthManager if name == "AuthManager" else AuthSession
    elif name == "Crawler":
        from demogorgon.tools.crawler import Crawler
        return Crawler
    elif name == "Checkpoint":
        from demogorgon.tools.checkpoint import Checkpoint
        return Checkpoint
    elif name == "ToolBus":
        from demogorgon.tools.tool_bus import ToolBus
        return ToolBus
    elif name == "Recon":
        from demogorgon.tools.recon import Recon
        return Recon
    elif name == "NucleiBridge":
        from demogorgon.tools.nuclei_bridge import NucleiBridge
        return NucleiBridge
    elif name == "FfufBridge":
        from demogorgon.tools.ffuf_bridge import FfufBridge
        return FfufBridge
    elif name == "KatanaBridge":
        from demogorgon.tools.katana_bridge import KatanaBridge
        return KatanaBridge
    elif name == "AmassBridge":
        from demogorgon.tools.amass_bridge import AmassBridge
        return AmassBridge
    elif name == "Reporter":
        from demogorgon.tools.reporter import Reporter
        return Reporter
    elif name == "Notifier":
        from demogorgon.tools.notifier import Notifier
        return Notifier
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
