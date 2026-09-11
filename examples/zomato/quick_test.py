#!/usr/bin/env python3
"""
quick_test.py — Quick test of the Burp automation module
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from zomato_burp_automation import (
    BurpRestClient, BurpProxyClient, HITLAccountCreator,
    ZomatoVulnScanner, ZOMATO_TARGETS
)

def test_imports():
    print("[*] Testing imports...")
    print("    [+] All modules imported successfully")
    return True

def test_burp_connection():
    print("\n[*] Testing Burp Suite connection...")
    rest = BurpRestClient()
    proxy = BurpProxyClient()

    if rest.is_running():
        print("    [+] Burp REST API: CONNECTED")
    else:
        print("    [-] Burp REST API: NOT RUNNING (start Burp Suite)")

    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        result = sock.connect_ex(("127.0.0.1", 8080))
        sock.close()
        if result == 0:
            print("    [+] Burp Proxy: CONNECTED")
        else:
            print("    [-] Burp Proxy: NOT RUNNING")
    except:
        print("    [-] Burp Proxy: NOT RUNNING")

def test_hitl_creator():
    print("\n[*] Testing HITL Account Creator...")
    creator = HITLAccountCreator()
    account = creator.generate_account("test_target")
    print(f"    [+] Generated account: {account.username}")
    print(f"    [+] Email: {account.email}")
    print(f"    [+] Password: {account.password}")
    return account

def test_scanner():
    print("\n[*] Testing Vulnerability Scanner...")
    proxy = BurpProxyClient()
    rest = BurpRestClient()
    scanner = ZomatoVulnScanner(proxy, rest)
    print(f"    [+] Scanner initialized with {len(scanner.findings)} findings")
    return scanner

def test_targets():
    print("\n[*] Available Targets:")
    for name, url in ZOMATO_TARGETS.items():
        print(f"    {name}: {url}")

if __name__ == "__main__":
    print("="*60)
    print("  Zomato/Blinkit Burp Automation - Quick Test")
    print("="*60)

    test_imports()
    test_burp_connection()
    account = test_hitl_creator()
    scanner = test_scanner()
    test_targets()

    print("\n" + "="*60)
    print("  Quick test complete!")
    print("="*60)
    print("\nUsage:")
    print("  python3 zomato_burp_automation.py                    # Full automation")
    print("  python3 zomato_burp_automation.py --skip-accounts    # Skip HITL")
    print("  python3 zomato_burp_automation.py --target fleet_partner  # Single target")
    print("  python3 zomato_burp_automation.py --burp-only        # Burp scan only")
