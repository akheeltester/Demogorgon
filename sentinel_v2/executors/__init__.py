"""Executors — deterministic vulnerability testing engines.

Each executor tests for a specific vulnerability class.
The controller invokes the appropriate executor based on the hypothesis.
"""

from sentinel_v2.executors.cors_detector import CORSDetector
from sentinel_v2.executors.jwt_attacker import JWTAttacker
from sentinel_v2.executors.idor_tester import IDORTester
from sentinel_v2.executors.xss_detector import XSSDetector
from sentinel_v2.executors.auth_bypass_tester import AuthBypassTester
from sentinel_v2.executors.info_disclosure_detector import InfoDisclosureDetector

__all__ = [
    "CORSDetector",
    "JWTAttacker",
    "IDORTester",
    "XSSDetector",
    "AuthBypassTester",
    "InfoDisclosureDetector",
]
