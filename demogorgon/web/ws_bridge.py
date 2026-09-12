"""WebSocket Event Bridge — connects EventBus to browser clients.

Architecture:
    AgentSession
       ↓
    EventBus
       ↓
    WebSocketBridge (handler registered on EventBus)
       ↓
    Connected WebSocket clients (browser)

Do NOT create a parallel event system. This bridges the existing one.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

from fastapi import WebSocket, WebSocketDisconnect

logger = logging.getLogger(__name__)


class WebSocketBridge:
    """Bridges EventBus events to connected WebSocket clients.

    Usage:
        bridge = WebSocketBridge()
        # Register as EventBus handler
        event_bus.on_all(bridge.handle_event)
        # Connect WebSocket clients
        await bridge.connect(websocket)
    """

    def __init__(self):
        self._clients: list[WebSocket] = []
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    async def connect(self, websocket: WebSocket) -> None:
        """Accept a new WebSocket client connection."""
        await websocket.accept()
        self._clients.append(websocket)
        logger.info(f"WebSocket client connected ({len(self._clients)} total)")

        # Send recent event history to new client
        # (history is stored in EventBus, we'll send it on connect)

    async def disconnect(self, websocket: WebSocket) -> None:
        """Remove a WebSocket client."""
        if websocket in self._clients:
            self._clients.remove(websocket)
            logger.info(f"WebSocket client disconnected ({len(self._clients)} total)")

    async def handle_event(self, event: Any) -> None:
        """Handle an event from EventBus and broadcast to all clients.

        This is registered as a global handler on EventBus.
        """
        if not self._clients:
            return

        # Serialize event
        try:
            data = event.to_dict()
        except Exception:
            data = {"type": "unknown", "data": {}, "timestamp": time.time()}

        # Broadcast to all connected clients
        disconnected = []
        for client in self._clients:
            try:
                await client.send_json(data)
            except Exception:
                disconnected.append(client)

        # Clean up disconnected clients
        for client in disconnected:
            await self.disconnect(client)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    @property
    def is_active(self) -> bool:
        return self._running


# Global bridge instance
_web_bridge: WebSocketBridge | None = None


def get_web_bridge() -> WebSocketBridge:
    """Get the global WebSocket bridge instance."""
    global _web_bridge
    if _web_bridge is None:
        _web_bridge = WebSocketBridge()
    return _web_bridge
