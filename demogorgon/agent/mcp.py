"""MCP Client — generic Model Context Protocol client layer.

Provides a protocol-based interface for connecting to MCP servers.
MCP servers expose tools, resources, and prompts that the agent can use.
This enables the agent to use Burp Suite, custom tools, and external services
through a standardized protocol.

Usage:
    client = MCPClient("burp", command=["python", "mcp_burp_server.py"])
    await client.start()
    tools = await client.list_tools()
    result = await client.call_tool("burp_scan", {"url": "https://target.com"})
    await client.stop()
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class MCPTool:
    """A tool exposed by an MCP server."""
    name: str
    description: str = ""
    input_schema: dict[str, Any] = field(default_factory=dict)
    server_name: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
            "server_name": self.server_name,
        }


@dataclass
class MCPResource:
    """A resource exposed by an MCP server."""
    uri: str
    name: str = ""
    description: str = ""
    mime_type: str = ""
    server_name: str = ""


@dataclass
class MCPServerConfig:
    """Configuration for an MCP server."""
    name: str
    command: list[str] = field(default_factory=list)
    env: dict[str, str] = field(default_factory=dict)
    cwd: str = ""
    auto_start: bool = True
    timeout: float = 10.0

    # For Burp Suite integration
    burp_host: str = "127.0.0.1"
    burp_port: int = 1337


# Default MCP servers
DEFAULT_SERVERS: dict[str, MCPServerConfig] = {
    "burp": MCPServerConfig(
        name="burp",
        command=["python", "-m", "mcp_burp_server"],
        auto_start=False,  # User must start Burp MCP server manually
    ),
}


class MCPClient:
    """Generic MCP client that communicates via stdio JSON-RPC.

    Usage:
        client = MCPClient("my_server", command=["python", "server.py"])
        await client.start()
        tools = await client.list_tools()
        result = await client.call_tool("tool_name", {"arg": "value"})
        await client.stop()
    """

    def __init__(
        self,
        name: str,
        command: list[str] | None = None,
        env: dict[str, str] | None = None,
        cwd: str = "",
        timeout: float = 10.0,
    ):
        self.name = name
        self.command = command or []
        self.env = {**os.environ, **(env or {})}
        self.cwd = cwd
        self.timeout = timeout

        self._process: subprocess.Popen | None = None
        self._request_id = 0
        self._pending: dict[int, asyncio.Future] = {}
        self._reader_task: asyncio.Task | None = None
        self._tools: list[MCPTool] = []
        self._resources: list[MCPResource] = []
        self._connected = False

    async def start(self) -> bool:
        """Start the MCP server process."""
        if not self.command:
            logger.warning(f"MCP server '{self.name}': no command specified")
            return False

        try:
            self._process = subprocess.Popen(
                self.command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.env,
                cwd=self.cwd or None,
            )

            # Start reading responses
            self._reader_task = asyncio.create_task(self._read_loop())

            # Initialize
            result = await self._send_request("initialize", {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {
                    "name": "demogorgon",
                    "version": "1.0.0",
                },
            })

            if result and not result.get("error"):
                self._connected = True
                # Send initialized notification
                await self._send_notification("notifications/initialized", {})
                # List tools
                await self._list_tools()
                logger.info(f"MCP server '{self.name}' connected, {len(self._tools)} tools")
                return True

            return False

        except FileNotFoundError:
            logger.error(f"MCP server '{self.name}': command not found: {self.command}")
            return False
        except Exception as e:
            logger.error(f"MCP server '{self.name}' failed to start: {e}")
            return False

    async def stop(self):
        """Stop the MCP server process."""
        self._connected = False

        if self._reader_task:
            self._reader_task.cancel()
            try:
                await self._reader_task
            except asyncio.CancelledError:
                pass

        if self._process:
            try:
                self._process.terminate()
                self._process.wait(timeout=5.0)
            except Exception:
                self._process.kill()

        self._process = None
        logger.info(f"MCP server '{self.name}' stopped")

    async def list_tools(self) -> list[MCPTool]:
        """List available tools."""
        if not self._connected:
            await self._list_tools()
        return list(self._tools)

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Call a tool on the server."""
        if not self._connected:
            return {"error": f"MCP server '{self.name}' not connected"}

        result = await self._send_request("tools/call", {
            "name": name,
            "arguments": arguments,
        })

        if result is None:
            return {"error": "No response from MCP server"}

        if "error" in result:
            return {"error": result["error"]}

        # Extract content from MCP response
        content = result.get("result", {}).get("content", [])
        if content:
            # Return first text content
            for item in content:
                if item.get("type") == "text":
                    try:
                        return json.loads(item["text"])
                    except (json.JSONDecodeError, TypeError):
                        return {"text": item["text"]}
            return {"content": content}

        return result.get("result", {})

    async def list_resources(self) -> list[MCPResource]:
        """List available resources."""
        if not self._connected:
            return []

        result = await self._send_request("resources/list", {})
        if result and "resources" in result.get("result", {}):
            self._resources = [
                MCPResource(
                    uri=r.get("uri", ""),
                    name=r.get("name", ""),
                    description=r.get("description", ""),
                    mime_type=r.get("mimeType", ""),
                    server_name=self.name,
                )
                for r in result["result"]["resources"]
            ]

        return list(self._resources)

    async def read_resource(self, uri: str) -> dict[str, Any]:
        """Read a resource by URI."""
        if not self._connected:
            return {"error": "Not connected"}

        result = await self._send_request("resources/read", {"uri": uri})
        if result:
            return result.get("result", {})
        return {}

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def tools(self) -> list[MCPTool]:
        return list(self._tools)

    async def _list_tools(self):
        """Fetch tool list from server."""
        result = await self._send_request("tools/list", {})
        if result and "tools" in result.get("result", {}):
            self._tools = [
                MCPTool(
                    name=t.get("name", ""),
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                    server_name=self.name,
                )
                for t in result["result"]["tools"]
            ]

    async def _send_request(self, method: str, params: dict[str, Any]) -> dict | None:
        """Send a JSON-RPC request and wait for response."""
        self._request_id += 1
        req_id = self._request_id

        message = {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": method,
            "params": params,
        }

        future = asyncio.get_event_loop().create_future()
        self._pending[req_id] = future

        try:
            line = json.dumps(message) + "\n"
            self._process.stdin.write(line.encode())
            self._process.stdin.flush()
        except Exception as e:
            logger.error(f"MCP write error: {e}")
            self._pending.pop(req_id, None)
            return None

        try:
            return await asyncio.wait_for(future, timeout=self.timeout)
        except asyncio.TimeoutError:
            logger.warning(f"MCP request timeout: {method}")
            self._pending.pop(req_id, None)
            return None

    async def _send_notification(self, method: str, params: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no response expected)."""
        message = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        }
        try:
            line = json.dumps(message) + "\n"
            self._process.stdin.write(line.encode())
            self._process.stdin.flush()
        except Exception as e:
            logger.error(f"MCP notification error: {e}")

    async def _read_loop(self):
        """Read responses from the MCP server."""
        while self._process and self._process.poll() is None:
            try:
                line = await asyncio.get_event_loop().run_in_executor(
                    None, self._process.stdout.readline
                )
                if not line:
                    break

                message = json.loads(line.decode().strip())
                req_id = message.get("id")

                if req_id and req_id in self._pending:
                    future = self._pending.pop(req_id)
                    if not future.done():
                        future.set_result(message)
                elif "method" in message:
                    # Server-initiated notification
                    logger.debug(f"MCP notification: {message['method']}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"MCP read error: {e}")
                break


class MCPManager:
    """Manages multiple MCP server connections.

    Usage:
        manager = MCPManager()
        manager.add_server("burp", MCPServerConfig(name="burp", command=[...]))
        await manager.start_all()
        tools = manager.get_all_tools()
        result = await manager.call_tool("burp", "scan", {"url": "..."})
        await manager.stop_all()
    """

    def __init__(self):
        self._clients: dict[str, MCPClient] = {}
        self._configs: dict[str, MCPServerConfig] = {}

    def add_server(self, name: str, config: MCPServerConfig) -> None:
        """Register an MCP server."""
        self._configs[name] = config

    async def start_all(self) -> int:
        """Start all configured MCP servers. Returns count of successful connections."""
        connected = 0
        for name, config in self._configs.items():
            if not config.auto_start:
                continue

            client = MCPClient(
                name=name,
                command=config.command,
                env=config.env,
                cwd=config.cwd,
                timeout=config.timeout,
            )

            if await client.start():
                self._clients[name] = client
                connected += 1

        return connected

    async def start_server(self, name: str) -> bool:
        """Start a specific MCP server."""
        config = self._configs.get(name)
        if not config:
            return False

        client = MCPClient(
            name=name,
            command=config.command,
            env=config.env,
            cwd=config.cwd,
            timeout=config.timeout,
        )

        if await client.start():
            self._clients[name] = client
            return True
        return False

    async def stop_all(self):
        """Stop all MCP servers."""
        for client in self._clients.values():
            await client.stop()
        self._clients.clear()

    def get_all_tools(self) -> list[MCPTool]:
        """Get tools from all connected servers."""
        tools = []
        for client in self._clients.values():
            tools.extend(client.tools)
        return tools

    async def call_tool(
        self, server_name: str, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """Call a tool on a specific server."""
        client = self._clients.get(server_name)
        if not client:
            return {"error": f"MCP server '{server_name}' not connected"}
        return await client.call_tool(tool_name, arguments)

    def get_server_status(self) -> dict[str, dict[str, Any]]:
        """Get status of all servers."""
        status = {}
        for name, client in self._clients.items():
            status[name] = {
                "connected": client.is_connected,
                "tools": len(client.tools),
            }
        for name, config in self._configs.items():
            if name not in status:
                status[name] = {
                    "connected": False,
                    "tools": 0,
                    "auto_start": config.auto_start,
                }
        return status
