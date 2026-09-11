#!/usr/bin/env python3
"""
VK IDOR Testing Suite
=====================
Tests for Insecure Direct Object Reference vulnerabilities across VK's API methods.

Usage:
    python3 vk_idor_test.py --attacker-file .private/vk/attacker.json --victim-file .private/vk/victim.json

Requirements:
    - Two VK accounts (attacker + victim)
    - Auth cookies (remixsid) for both accounts
    - Rate limit: max 10 req/sec (enforced internally at 6 req/sec)
"""

import asyncio
import json
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import httpx


# ─── Configuration ─────────────────────────────────────────────────────────────
RATE_LIMIT_DELAY = 0.15  # 150ms between requests = ~6.6 req/sec (safe under 10/sec limit)
VK_API_BASE = "https://api.vk.com/method"
VK_API_VERSION = "5.131"


@dataclass
class VKSession:
    """VK authenticated session."""
    label: str
    user_id: int = 0
    cookies: dict = field(default_factory=dict)
    access_token: Optional[str] = None

    @classmethod
    def from_file(cls, path: str) -> "VKSession":
        """Load session from JSON file."""
        with open(path) as f:
            data = json.load(f)
        return cls(
            label=data.get("label", "unknown"),
            user_id=data.get("user_id", 0),
            cookies=data.get("cookies", {}),
            access_token=data.get("access_token"),
        )


# ─── VK API Methods with User-ID Parameters ────────────────────────────────────
# These are the high-value methods that accept user_id / owner_id / peer_id
VK_IDOR_METHODS = [
    # ─── User Profile Methods ──────────────────────────────────────────────────
    {
        "method": "users.get",
        "params": {"user_ids": "VICTIM_ID", "fields": "photo_200,city,home_town,bdate,sex,online"},
        "category": "profile",
        "description": "Read user profile data",
        "id_param": "user_ids",
        "max_bounty": "MEDIUM",
    },
    {
        "method": "users.get",
        "params": {"user_ids": "VICTIM_ID", "fields": "connections,site,education,relation,personal"},
        "category": "profile_pii",
        "description": "Read extended PII (connections, education, personal)",
        "id_param": "user_ids",
        "max_bounty": "HIGH",
    },

    # ─── Friends Methods ───────────────────────────────────────────────────────
    {
        "method": "friends.get",
        "params": {"user_id": "VICTIM_ID", "order": "name", "count": "5"},
        "category": "social_graph",
        "description": "Read user's friends list",
        "id_param": "user_id",
        "max_bounty": "MEDIUM",
    },
    {
        "method": "friends.getMutual",
        "params": {"source_uid": "ATTACKER_ID", "target_uid": "VICTIM_ID"},
        "category": "social_graph",
        "description": "Read mutual friends with victim",
        "id_param": "target_uid",
        "max_bounty": "MEDIUM",
    },
    {
        "method": "friends.getOnline",
        "params": {"user_id": "VICTIM_ID"},
        "category": "social_graph",
        "description": "Read user's online friends",
        "id_param": "user_id",
        "max_bounty": "LOW",
    },

    # ─── Message Methods (HIGHEST VALUE) ───────────────────────────────────────
    {
        "method": "messages.getConversations",
        "params": {"count": "5"},
        "category": "messages",
        "description": "Get attacker's own conversations (baseline)",
        "id_param": None,
        "max_bounty": "INFO",
    },
    {
        "method": "messages.getHistory",
        "params": {"peer_id": "VICTIM_PEER_ID", "count": "5"},
        "category": "messages",
        "description": "Read message history with victim",
        "id_param": "peer_id",
        "max_bounty": "MAX",
    },
    {
        "method": "messages.get",
        "params": {"count": "5"},
        "category": "messages",
        "description": "Get attacker's own messages (baseline)",
        "id_param": None,
        "max_bounty": "INFO",
    },

    # ─── Wall Methods ──────────────────────────────────────────────────────────
    {
        "method": "wall.get",
        "params": {"owner_id": "VICTIM_ID", "count": "5"},
        "category": "wall",
        "description": "Read victim's wall posts",
        "id_param": "owner_id",
        "max_bounty": "MEDIUM",
    },
    {
        "method": "wall.getComments",
        "params": {"owner_id": "VICTIM_ID", "post_id": "1", "count": "5"},
        "category": "wall",
        "description": "Read comments on victim's wall",
        "id_param": "owner_id",
        "max_bounty": "LOW",
    },

    # ─── Photo Methods ─────────────────────────────────────────────────────────
    {
        "method": "photos.get",
        "params": {"owner_id": "VICTIM_ID", "count": "5", "album_id": "profile"},
        "category": "photos",
        "description": "Read victim's profile photos",
        "id_param": "owner_id",
        "max_bounty": "MEDIUM",
    },
    {
        "method": "photos.get",
        "params": {"owner_id": "VICTIM_ID", "count": "5", "album_id": "wall"},
        "category": "photos",
        "description": "Read victim's wall photos",
        "id_param": "owner_id",
        "max_bounty": "MEDIUM",
    },
    {
        "method": "photos.getAll",
        "params": {"owner_id": "VICTIM_ID", "count": "5"},
        "category": "photos",
        "description": "Read all victim's photos",
        "id_param": "owner_id",
        "max_bounty": "MEDIUM",
    },

    # ─── Video Methods ─────────────────────────────────────────────────────────
    {
        "method": "video.get",
        "params": {"owner_id": "VICTIM_ID", "count": "5"},
        "category": "video",
        "description": "Read victim's videos",
        "id_param": "owner_id",
        "max_bounty": "MEDIUM",
    },

    # ─── Document Methods ──────────────────────────────────────────────────────
    {
        "method": "docs.get",
        "params": {"count": "5"},
        "category": "docs",
        "description": "Get attacker's own docs (baseline)",
        "id_param": None,
        "max_bounty": "INFO",
    },

    # ─── Group Methods ─────────────────────────────────────────────────────────
    {
        "method": "groups.get",
        "params": {"user_id": "VICTIM_ID", "count": "5"},
        "category": "groups",
        "description": "Read victim's group memberships",
        "id_param": "user_id",
        "max_bounty": "MEDIUM",
    },

    # ─── Status Methods ────────────────────────────────────────────────────────
    {
        "method": "status.get",
        "params": {"user_id": "VICTIM_ID"},
        "category": "status",
        "description": "Read victim's status",
        "id_param": "user_id",
        "max_bounty": "LOW",
    },

    # ─── Account Methods (Sensitivity Check) ───────────────────────────────────
    {
        "method": "account.getAppPermissions",
        "params": {},
        "category": "account",
        "description": "Check attacker's own permissions (baseline)",
        "id_param": None,
        "max_bounty": "INFO",
    },
]


@dataclass
class IDORResult:
    """Result of an IDOR test."""
    method: str
    category: str
    description: str
    id_param: str
    vulnerable: bool
    severity: str
    evidence: str
    request_url: str
    response_snippet: str
    max_bounty: str


class VKIDORTester:
    """VK IDOR vulnerability tester."""

    def __init__(self, attacker: VKSession, victim: VKSession):
        self.attacker = attacker
        self.victim = victim
        self.results: list[IDORResult] = []
        self.request_count = 0
        self.last_request_time = 0.0

    async def _rate_limit_wait(self):
        """Enforce rate limit between requests."""
        elapsed = time.time() - self.last_request_time
        if elapsed < RATE_LIMIT_DELAY:
            await asyncio.sleep(RATE_LIMIT_DELAY - elapsed)
        self.last_request_time = time.time()
        self.request_count += 1

    async def _make_request(
        self,
        session: VKSession,
        method: str,
        params: dict,
    ) -> tuple[int, str]:
        """Make a VK API request with rate limiting."""
        await self._rate_limit_wait()

        url = f"{VK_API_BASE}/{method}"
        request_params = {
            "v": VK_API_VERSION,
            **params,
        }

        # Add access token if available
        if session.access_token:
            request_params["access_token"] = session.access_token

        # Prepare cookies
        cookies = session.cookies.copy()

        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            try:
                resp = await client.get(url, params=request_params, cookies=cookies)
                return resp.status_code, resp.text[:2000]
            except httpx.RequestError as e:
                return 0, str(e)

    def _check_idor_response(
        self,
        method: str,
        status_code: int,
        response: str,
        is_victim_data: bool,
    ) -> tuple[bool, str, str]:
        """
        Analyze response to determine if IDOR is present.

        Returns: (vulnerable, severity, evidence)
        """
        try:
            data = json.loads(response)
        except json.JSONDecodeError:
            return False, "info", "Invalid JSON response"

        # Check for error responses (not IDOR)
        if "error" in data:
            error_code = data.get("error", {}).get("error_code", 0)
            error_msg = data.get("error", {}).get("error_msg", "")

            # VK error codes:
            # 5 = Authorization failed
            # 7 = No access to method
            # 15 = Access denied
            # 100 = Parameter error
            # 113 = Invalid user id
            # 150 = Invalid hash
            # 214 = Access denied (user blocked)
            # 300 = Group is disabled

            if error_code in (5, 7, 15, 214):
                return False, "info", f"Properly blocked: {error_msg}"
            elif error_code == 113:
                return False, "info", f"Invalid user ID: {error_msg}"
            elif error_code == 100:
                return False, "info", f"Parameter error: {error_msg}"
            elif error_code == 300:
                return False, "info", f"Group disabled: {error_msg}"
            else:
                return False, "info", f"Error {error_code}: {error_msg}"

        # Check for successful response with data
        if "response" in data:
            response_data = data["response"]

            # For list responses, check if items exist
            if isinstance(response_data, dict) and "items" in response_data:
                items = response_data["items"]
                if items and len(items) > 0:
                    # If this is supposed to be victim's data, and we got items
                    if is_victim_data:
                        return True, "HIGH", f"Got {len(items)} items from victim's data"
                    else:
                        return False, "info", "Got own data (baseline)"
                else:
                    return False, "info", "Empty response"

            # For single object responses
            elif isinstance(response_data, list) and len(response_data) > 0:
                if is_victim_data:
                    return True, "HIGH", f"Got {len(response_data)} items from victim's data"
                else:
                    return False, "info", "Got own data (baseline)"

            # For count-only responses
            elif isinstance(response_data, int):
                if is_victim_data and response_data > 0:
                    return True, "MEDIUM", f"Got count {response_data} from victim's data"

        return False, "info", "No data exposed"

    async def _test_idor_method(self, method_config: dict) -> IDORResult:
        """Test a single VK API method for IDOR."""
        method = method_config["method"]
        category = method_config["category"]
        description = method_config["description"]
        id_param = method_config.get("id_param")
        max_bounty = method_config["max_bounty"]

        # Skip baseline methods (no victim ID to test)
        if not id_param:
            status_code, response = await self._make_request(
                self.attacker, method, method_config["params"]
            )
            return IDORResult(
                method=method,
                category=category,
                description=description,
                id_param="none",
                vulnerable=False,
                severity="info",
                evidence="Baseline test (no victim ID)",
                request_url=f"{VK_API_BASE}/{method}",
                response_snippet=response[:500],
                max_bounty=max_bounty,
            )

        # ─── Step 1: Test with attacker's own ID (baseline) ───────────────────
        attacker_params = method_config["params"].copy()
        for key, value in attacker_params.items():
            if value == "VICTIM_ID":
                attacker_params[key] = str(self.attacker.user_id)
            elif value == "ATTACKER_ID":
                attacker_params[key] = str(self.attacker.user_id)
            elif value == "VICTIM_PEER_ID":
                # VK peer_id for messages is typically 2000000000 + user_id
                attacker_params[key] = str(2000000000 + self.victim.user_id)

        status_code_attacker, response_attacker = await self._make_request(
            self.attacker, method, attacker_params
        )

        # ─── Step 2: Test with victim's ID (IDOR test) ────────────────────────
        victim_params = method_config["params"].copy()
        for key, value in victim_params.items():
            if value == "VICTIM_ID":
                victim_params[key] = str(self.victim.user_id)
            elif value == "ATTACKER_ID":
                victim_params[key] = str(self.attacker.user_id)
            elif value == "VICTIM_PEER_ID":
                victim_params[key] = str(2000000000 + self.victim.user_id)

        status_code_victim, response_victim = await self._make_request(
            self.attacker, method, victim_params
        )

        # ─── Step 3: Analyze results ──────────────────────────────────────────
        vulnerable, severity, evidence = self._check_idor_response(
            method, status_code_victim, response_victim, is_victim_data=True
        )

        # Build request URL for evidence
        request_params = "&".join(f"{k}={v}" for k, v in victim_params.items() if k != "access_token")
        request_url = f"{VK_API_BASE}/{method}?{request_params}"

        return IDORResult(
            method=method,
            category=category,
            description=description,
            id_param=id_param,
            vulnerable=vulnerable,
            severity=severity,
            evidence=evidence,
            request_url=request_url,
            response_snippet=response_victim[:500],
            max_bounty=max_bounty,
        )

    async def run_all_tests(self) -> list[IDORResult]:
        """Run IDOR tests on all configured VK API methods."""
        print(f"\n{'='*70}")
        print(f"VK IDOR TESTER")
        print(f"{'='*70}")
        print(f"Attacker User ID: {self.attacker.user_id}")
        print(f"Victim User ID:   {self.victim.user_id}")
        print(f"Methods to Test:  {len(VK_IDOR_METHODS)}")
        print(f"Rate Limit:       {RATE_LIMIT_DELAY}s between requests")
        print(f"{'='*70}\n")

        self.results = []

        for i, method_config in enumerate(VK_IDOR_METHODS, 1):
            print(f"[{i:2d}/{len(VK_IDOR_METHODS)}] Testing {method_config['method']} ({method_config['category']})...", end=" ", flush=True)

            result = await self._test_idor_method(method_config)
            self.results.append(result)

            if result.vulnerable:
                print(f"🔴 VULNERABLE — {result.severity}")
            else:
                print(f"✅ Secure — {result.evidence[:50]}")

        return self.results

    def print_summary(self):
        """Print a summary of all test results."""
        vulnerable = [r for r in self.results if r.vulnerable]
        secure = [r for r in self.results if not r.vulnerable]

        print(f"\n{'='*70}")
        print(f"TEST RESULTS SUMMARY")
        print(f"{'='*70}")
        print(f"Total Methods Tested: {len(self.results)}")
        print(f"Vulnerable:          {len(vulnerable)} 🔴")
        print(f"Secure:              {len(secure)} ✅")
        print(f"{'='*70}")

        if vulnerable:
            print(f"\n🔴 VULNERABLE FINDINGS:")
            print(f"{'-'*70}")
            for r in vulnerable:
                print(f"\n  Method:     {r.method}")
                print(f"  Category:   {r.category}")
                print(f"  Description: {r.description}")
                print(f"  ID Param:   {r.id_param}")
                print(f"  Severity:   {r.severity}")
                print(f"  Bounty:     {r.max_bounty}")
                print(f"  Evidence:   {r.evidence}")
                print(f"  Request:    {r.request_url}")
                print(f"  Response:   {r.response_snippet[:200]}...")

        print(f"\n{'='*70}")

    def export_results(self, path: str):
        """Export results to JSON."""
        data = {
            "test_config": {
                "attacker_user_id": self.attacker.user_id,
                "victim_user_id": self.victim.user_id,
                "total_requests": self.request_count,
                "rate_limit_delay": RATE_LIMIT_DELAY,
            },
            "results": [
                {
                    "method": r.method,
                    "category": r.category,
                    "description": r.description,
                    "id_param": r.id_param,
                    "vulnerable": r.vulnerable,
                    "severity": r.severity,
                    "evidence": r.evidence,
                    "request_url": r.request_url,
                    "response_snippet": r.response_snippet[:500],
                    "max_bounty": r.max_bounty,
                }
                for r in self.results
            ],
            "summary": {
                "total": len(self.results),
                "vulnerable": len([r for r in self.results if r.vulnerable]),
                "secure": len([r for r in self.results if not r.vulnerable]),
            },
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\nResults exported to: {path}")


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="VK IDOR Testing Suite")
    parser.add_argument("--attacker-file", required=True, help="Path to attacker auth file")
    parser.add_argument("--victim-file", required=True, help="Path to victim auth file")
    parser.add_argument("--output", default="vk_idor_results.json", help="Output file path")
    args = parser.parse_args()

    # Load sessions
    try:
        attacker = VKSession.from_file(args.attacker_file)
        victim = VKSession.from_file(args.victim_file)
    except FileNotFoundError as e:
        print(f"Error: {e}")
        print("Please create auth files first. See .private/vk/README.md")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in auth file: {e}")
        sys.exit(1)

    if attacker.user_id == 0 or victim.user_id == 0:
        print("Error: user_id must be set in auth files")
        print("To find your user_id, visit your VK profile and check the URL")
        print("Example: https://vk.com/id123456789 → user_id = 123456789")
        sys.exit(1)

    # Run tests
    tester = VKIDORTester(attacker, victim)
    await tester.run_all_tests()
    tester.print_summary()
    tester.export_results(args.output)


if __name__ == "__main__":
    asyncio.run(main())
