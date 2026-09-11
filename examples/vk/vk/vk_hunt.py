#!/usr/bin/env python3
"""
VK Bug Bounty Hunt Runner
==========================
Master script that runs all VK security tests in sequence.

Usage:
    # Full hunt (all tests)
    python3 vk_hunt.py --attacker-file .private/vk/attacker.json --victim-file .private/vk/victim.json

    # Individual tests
    python3 vk_hunt.py --mode idor --attacker-file .private/vk/attacker.json --victim-file .private/vk/victim.json
    python3 vk_hunt.py --mode cors
    python3 vk_hunt.py --mode oauth --access-token YOUR_TOKEN

    # Custom targets
    python3 vk_hunt.py --mode all --attacker-file .private/vk/attacker.json --victim-file .private/vk/victim.json
"""

import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from vk_idor_test import VKIDORTester, VKSession
from vk_cors_test import VKCORSTester
from vk_oauth_test import VKOAuthTester


class VKHuntRunner:
    """Master runner for VK bug bounty hunts."""

    def __init__(
        self,
        attacker_file: Optional[str] = None,
        victim_file: Optional[str] = None,
        access_token: Optional[str] = None,
    ):
        self.attacker_file = attacker_file
        self.victim_file = victim_file
        self.access_token = access_token
        self.start_time = None
        self.results = {}

    async def run_idor_tests(self) -> dict:
        """Run IDOR tests."""
        if not self.attacker_file or not self.victim_file:
            print("⚠️  Skipping IDOR tests: attacker/victim files not provided")
            return {"skipped": True, "reason": "No auth files"}

        try:
            attacker = VKSession.from_file(self.attacker_file)
            victim = VKSession.from_file(self.victim_file)
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"⚠️  Skipping IDOR tests: {e}")
            return {"skipped": True, "reason": str(e)}

        if attacker.user_id == 0 or victim.user_id == 0:
            print("⚠️  Skipping IDOR tests: user_id not set in auth files")
            return {"skipped": True, "reason": "user_id not set"}

        tester = VKIDORTester(attacker, victim)
        await tester.run_all_tests()
        tester.print_summary()

        output_path = "vk_idor_results.json"
        tester.export_results(output_path)

        return {
            "total": len(tester.results),
            "vulnerable": len([r for r in tester.results if r.vulnerable]),
            "output": output_path,
        }

    async def run_cors_tests(self) -> dict:
        """Run CORS tests."""
        tester = VKCORSTester()
        await tester.run_all_tests()
        tester.print_summary()

        output_path = "vk_cors_results.json"
        tester.export_results(output_path)

        return {
            "total": len(tester.results),
            "critical": len([r for r in tester.results if r.severity == "CRITICAL"]),
            "output": output_path,
        }

    async def run_oauth_tests(self) -> dict:
        """Run OAuth tests."""
        tester = VKOAuthTester(access_token=self.access_token)
        await tester.run_all_tests()
        tester.print_summary()

        output_path = "vk_oauth_results.json"
        tester.export_results(output_path)

        return {
            "total": len(tester.results),
            "critical": len([r for r in tester.results if r.severity == "CRITICAL"]),
            "output": output_path,
        }

    async def run_all(self) -> dict:
        """Run all VK security tests."""
        self.start_time = datetime.now()

        print(f"\n{'#'*70}")
        print(f"{'#'*70}")
        print(f"  VK BUG BOUNTY HUNT — FULL SCAN")
        print(f"  Started: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"{'#'*70}")
        print(f"{'#'*70}\n")

        # ─── Phase 1: IDOR Tests ───────────────────────────────────────────────
        print(f"\n{'='*70}")
        print(f"PHASE 1: IDOR TESTING")
        print(f"{'='*70}")
        self.results["idor"] = await self.run_idor_tests()

        # ─── Phase 2: CORS Tests ───────────────────────────────────────────────
        print(f"\n{'='*70}")
        print(f"PHASE 2: CORS TESTING")
        print(f"{'='*70}")
        self.results["cors"] = await self.run_cors_tests()

        # ─── Phase 3: OAuth Tests ──────────────────────────────────────────────
        print(f"\n{'='*70}")
        print(f"PHASE 3: OAUTH TESTING")
        print(f"{'='*70}")
        self.results["oauth"] = await self.run_oauth_tests()

        # ─── Final Summary ─────────────────────────────────────────────────────
        self._print_final_summary()

        return self.results

    def _print_final_summary(self):
        """Print final summary of all tests."""
        end_time = datetime.now()
        duration = (end_time - self.start_time).total_seconds()

        print(f"\n{'#'*70}")
        print(f"{'#'*70}")
        print(f"  VK BUG BOUNTY HUNT — FINAL SUMMARY")
        print(f"{'#'*70}")
        print(f"{'#'*70}")

        print(f"\n⏱️  Duration: {duration:.1f} seconds")

        # IDOR Summary
        idor = self.results.get("idor", {})
        if not idor.get("skipped"):
            print(f"\n🔴 IDOR Tests:")
            print(f"   Total: {idor.get('total', 0)}")
            print(f"   Vulnerable: {idor.get('vulnerable', 0)}")
            print(f"   Output: {idor.get('output', 'N/A')}")

        # CORS Summary
        cors = self.results.get("cors", {})
        if not cors.get("skipped"):
            print(f"\n🌐 CORS Tests:")
            print(f"   Total: {cors.get('total', 0)}")
            print(f"   Critical: {cors.get('critical', 0)}")
            print(f"   Output: {cors.get('output', 'N/A')}")

        # OAuth Summary
        oauth = self.results.get("oauth", {})
        if not oauth.get("skipped"):
            print(f"\n🔑 OAuth Tests:")
            print(f"   Total: {oauth.get('total', 0)}")
            print(f"   Critical: {oauth.get('critical', 0)}")
            print(f"   Output: {oauth.get('output', 'N/A')}")

        # Overall Assessment
        print(f"\n{'='*70}")
        print(f"OVERALL ASSESSMENT")
        print(f"{'='*70}")

        total_vulnerable = 0
        for test_type, data in self.results.items():
            if not data.get("skipped"):
                total_vulnerable += data.get("vulnerable", 0) + data.get("critical", 0)

        if total_vulnerable > 0:
            print(f"\n🔴 VULNERABILITIES FOUND: {total_vulnerable}")
            print(f"\n📋 NEXT STEPS:")
            print(f"   1. Review the output JSON files for detailed findings")
            print(f"   2. Manually verify each vulnerability")
            print(f"   3. Take screenshots/video evidence")
            print(f"   4. Write VK-formatted report")
            print(f"   5. Submit to VK bug bounty program")
        else:
            print(f"\n✅ No obvious vulnerabilities found")
            print(f"\n📋 RECOMMENDATIONS:")
            print(f"   1. Check the output files for edge cases")
            print(f"   2. Try manual testing on specific endpoints")
            print(f"   3. Test with different user roles/permissions")
            print(f"   4. Check for business logic vulnerabilities")

        print(f"\n{'='*70}")

        # Export final summary
        summary = {
            "hunt_date": self.start_time.isoformat(),
            "duration_seconds": duration,
            "results": self.results,
            "total_vulnerable": total_vulnerable,
        }

        with open("vk_hunt_summary.json", "w") as f:
            json.dump(summary, f, indent=2)
        print(f"\n📄 Full summary exported to: vk_hunt_summary.json")


async def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="VK Bug Bounty Hunt Runner")
    parser.add_argument("--mode", choices=["all", "idor", "cors", "oauth"], default="all",
                       help="Test mode: all, idor, cors, oauth")
    parser.add_argument("--attacker-file", help="Path to attacker auth file")
    parser.add_argument("--victim-file", help="Path to victim auth file")
    parser.add_argument("--access-token", help="VK access token (optional)")
    args = parser.parse_args()

    runner = VKHuntRunner(
        attacker_file=args.attacker_file,
        victim_file=args.victim_file,
        access_token=args.access_token,
    )

    if args.mode == "all":
        await runner.run_all()
    elif args.mode == "idor":
        await runner.run_idor_tests()
    elif args.mode == "cors":
        await runner.run_cors_tests()
    elif args.mode == "oauth":
        await runner.run_oauth_tests()


if __name__ == "__main__":
    asyncio.run(main())
