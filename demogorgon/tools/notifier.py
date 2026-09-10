"""Notifier — recovered from legacy notifier.py.

Discord and Telegram notifications for findings.
"""

from __future__ import annotations

import json
import os
from typing import Any

import httpx


class Notifier:
    def __init__(
        self,
        discord_webhook: str | None = None,
        telegram_bot_token: str | None = None,
        telegram_chat_id: str | None = None,
    ):
        self.discord_webhook = discord_webhook or os.getenv("DISCORD_WEBHOOK_URL")
        self.telegram_bot_token = telegram_bot_token or os.getenv("TELEGRAM_BOT_TOKEN")
        self.telegram_chat_id = telegram_chat_id or os.getenv("TELEGRAM_CHAT_ID")

    async def notify_finding(self, finding: dict[str, Any]) -> dict[str, bool]:
        results = {}
        if self.discord_webhook:
            results["discord"] = await self._discord_notify(finding)
        if self.telegram_bot_token and self.telegram_chat_id:
            results["telegram"] = await self._telegram_notify(finding)
        return results

    async def _discord_notify(self, finding: dict[str, Any]) -> bool:
        try:
            severity = finding.get("severity", "unknown").lower()
            color_map = {
                "critical": 0xFF0000,
                "high": 0xFF8800,
                "medium": 0xFFCC00,
                "low": 0x44AAFF,
                "informational": 0x888888,
            }
            embed = {
                "title": finding.get("title", "New Finding"),
                "description": finding.get("description", ""),
                "color": color_map.get(severity, 0x888888),
                "fields": [
                    {"name": "Severity", "value": severity, "inline": True},
                    {"name": "Type", "value": finding.get("type", "unknown"), "inline": True},
                    {"name": "URL", "value": finding.get("url", "N/A"), "inline": False},
                ],
            }
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    self.discord_webhook,
                    json={"embeds": [embed]},
                    timeout=10,
                )
                return resp.status_code in (200, 204)
        except Exception:
            return False

    async def _telegram_notify(self, finding: dict[str, Any]) -> bool:
        try:
            severity = finding.get("severity", "unknown").upper()
            text = (
                f"🚨 *Demogorgon Finding*\n\n"
                f"*{finding.get('title', 'New Finding')}*\n"
                f"Severity: {severity}\n"
                f"Type: {finding.get('type', 'unknown')}\n"
                f"URL: `{finding.get('url', 'N/A')}`\n"
                f"Parameter: `{finding.get('parameter', 'N/A')}`"
            )
            url = f"https://api.telegram.org/bot{self.telegram_bot_token}/sendMessage"
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    url,
                    json={"chat_id": self.telegram_chat_id, "text": text, "parse_mode": "Markdown"},
                    timeout=10,
                )
                return resp.status_code == 200
        except Exception:
            return False
