"""Executors — deterministic vulnerability testing engines.

Each executor tests for a specific vulnerability class.
The controller invokes the appropriate executor based on the hypothesis.
"""

from demogorgon.executors.cors_detector import CORSDetector
from demogorgon.executors.jwt_attacker import JWTAttacker
from demogorgon.executors.idor_tester import IDORTester
from demogorgon.executors.xss_detector import XSSDetector
from demogorgon.executors.auth_bypass_tester import AuthBypassTester
from demogorgon.executors.info_disclosure_detector import InfoDisclosureDetector

__all__ = [
    "CORSDetector",
    "JWTAttacker",
    "IDORTester",
    "XSSDetector",
    "AuthBypassTester",
    "InfoDisclosureDetector",
]
