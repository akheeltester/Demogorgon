"""Recon — recovered from legacy recon.py.

Subdomain enumeration via crt.sh, HackerTarget, DNS brute force, and live probing.
"""

from __future__ import annotations

import asyncio
import logging
import re
from typing import Any
from urllib.parse import quote

import httpx

from sentinel_v2.tools.http_client import HTTPClient
from sentinel_v2.tools.tool_bus import ToolBus

logger = logging.getLogger("sentinel_v2.recon")


class Recon:
    def __init__(self, http: HTTPClient, tool_bus: ToolBus):
        self.http = http
        self.tool_bus = tool_bus

    async def discover_subdomains(self, domain: str) -> dict[str, Any]:
        all_subdomains: set[str] = set()
        methods_used: list[str] = []

        # crt.sh
        try:
            crt_subs = await self._crtsh(domain)
            all_subdomains.update(crt_subs)
            if crt_subs:
                methods_used.append(f"crt.sh ({len(crt_subs)} found)")
        except Exception as e:
            logger.debug(f"crt.sh failed: {e}")

        # HackerTarget
        try:
            ht_subs = await self._hackertarget(domain)
            all_subdomains.update(ht_subs)
            if ht_subs:
                methods_used.append(f"HackerTarget ({len(ht_subs)} found)")
        except Exception as e:
            logger.debug(f"HackerTarget failed: {e}")

        # subfinder (if available)
        if self.tool_bus.is_available("subfinder"):
            try:
                sf_subs = await self._subfinder(domain)
                all_subdomains.update(sf_subs)
                if sf_subs:
                    methods_used.append(f"subfinder ({len(sf_subs)} found)")
            except Exception as e:
                logger.debug(f"subfinder failed: {e}")

        # amass (if available)
        if self.tool_bus.is_available("amass"):
            try:
                amass_subs = await self._amass(domain)
                all_subdomains.update(amass_subs)
                if amass_subs:
                    methods_used.append(f"amass ({len(amass_subs)} found)")
            except Exception as e:
                logger.debug(f"amass failed: {e}")

        # DNS brute force
        try:
            brute_subs = await self._dns_brute(domain)
            all_subdomains.update(brute_subs)
            if brute_subs:
                methods_used.append(f"DNS brute ({len(brute_subs)} found)")
        except Exception as e:
            logger.debug(f"DNS brute failed: {e}")

        return {
            "domain": domain,
            "subdomains": sorted(all_subdomains),
            "total": len(all_subdomains),
            "methods": methods_used,
        }

    async def _crtsh(self, domain: str) -> set[str]:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = await self.http.request("GET", url, timeout=30)
        if response["error"] or response["status_code"] != 200:
            return set()

        try:
            data = response["json_data"] if "json_data" in response else None
            if data is None:
                import json
                data = json.loads(response["body"])
            subdomains = set()
            for entry in data:
                name = entry.get("name_value", "")
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") or sub == domain:
                        subdomains.add(sub)
            return subdomains
        except Exception:
            return set()

    async def _hackertarget(self, domain: str) -> set[str]:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        response = await self.http.request("GET", url, timeout=30)
        if response["error"] or response["status_code"] != 200:
            return set()

        subdomains = set()
        for line in response["body"].splitlines():
            parts = line.split(",")
            if parts:
                sub = parts[0].strip().lower()
                if sub.endswith(f".{domain}") or sub == domain:
                    subdomains.add(sub)
        return subdomains

    async def _subfinder(self, domain: str) -> set[str]:
        result = await self.tool_bus.execute("subfinder", ["-d", domain, "-silent"])
        if not result.success:
            return set()
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    async def _amass(self, domain: str) -> set[str]:
        result = await self.tool_bus.execute(
            "amass", ["enum", "-passive", "-d", domain],
            timeout=120,
        )
        if not result.success:
            return set()
        return {line.strip() for line in result.stdout.splitlines() if line.strip()}

    async def _dns_brute(self, domain: str) -> set[str]:
        prefixes = [
            "www", "mail", "ftp", "smtp", "pop", "ns1", "ns2", "dns",
            "dev", "test", "staging", "admin", "api", "app", "blog",
            "cdn", "cloud", "portal", "vpn", "webmail", "git", "gitlab",
        ]
        found = set()
        for prefix in prefixes:
            sub = f"{prefix}.{domain}"
            try:
                result = await self.tool_bus.execute("dnsx", ["-silent", "-a", sub])
                if result.success and result.stdout.strip():
                    found.add(sub)
            except Exception:
                pass
        return found

    async def probe_live(self, subdomains: list[str]) -> list[dict[str, Any]]:
        if self.tool_bus.is_available("httpx"):
            return await self._probe_httpx(subdomains)
        return await self._probe_direct(subdomains)

    async def _probe_httpx(self, subdomains: list[str]) -> list[dict[str, Any]]:
        stdin = "\n".join(subdomains)
        result = await self.tool_bus.execute(
            "httpx", ["-silent", "-json", "-status-code", "-title", "-tech-detect"],
            stdin_data=stdin,
        )
        if not result.success:
            return []

        live = []
        for line in result.stdout.splitlines():
            try:
                import json
                data = json.loads(line)
                live.append({
                    "url": data.get("url", ""),
                    "status_code": data.get("status_code", 0),
                    "title": data.get("title", ""),
                    "tech": data.get("tech", []),
                })
            except Exception:
                continue
        return live

    async def _probe_direct(self, subdomains: list[str]) -> list[dict[str, Any]]:
        live = []
        for sub in subdomains:
            for scheme in ["https", "http"]:
                url = f"{scheme}://{sub}"
                response = await self.http.request("GET", url)
                if not response["error"] and response["status_code"] > 0:
                    live.append({
                        "url": response["url"],
                        "status_code": response["status_code"],
                        "title": "",
                        "tech": [],
                    })
                    break
        return live
