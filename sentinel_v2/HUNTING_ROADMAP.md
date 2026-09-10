# HackerOne Bug Bounty Hunting Roadmap & Master Checklist

**Version**: 1.0  
**Date**: August 5, 2026  
**Purpose**: Complete methodology for systematic bug bounty hunting on HackerOne

---

## TABLE OF CONTENTS

1. [Phase 0: Target Selection & Scoping](#phase-0-target-selection--scoping)
2. [Phase 1: Recon (30 min)](#phase-1-recon)
3. [Phase 2: Learn (15 min)](#phase-2-learn)
4. [Phase 3: Hunt (2-4 hours)](#phase-3-hunt)
5. [Phase 4: Validate (30 min)](#phase-4-validate)
6. [Phase 5: Report (30 min)](#phase-5-report)
7. [Tools Quick Reference](#tools-quick-reference)
8. [Vuln-Specific Checklists](#vuln-specific-checklists)

---

## PHASE 0: TARGET SELECTION & SCOPING

### Step 0.1: Read Program Page (10 min)

- [ ] **Scope**: List ALL in-scope assets (domains, apps, APIs)
- [ ] **Exclusions**: Note every out-of-scope item
- [ ] **Safe Harbor**: Confirm safe harbor statement exists
- [ ] **Bounty Range**: Note max bounty (skip if < $500)
- [ ] **Accepted Vulns**: What types do they accept?
- [ ] **Avg Payout**: Check disclosed reports for avg bounty

### Step 0.2: Target Scoring (5 min)

| Criterion | Points |
|---|---|
| Max bounty >= $5K | +2 |
| Large user base (>100K) or handles money | +2 |
| Program launched < 60 days ago | +2 |
| Complex features: API, OAuth, file upload, GraphQL | +1 |
| Recent code/feature changes (GitHub, changelog) | +1 |
| Private program (less competition) | +1 |
| Tech stack you know | +1 |
| Source code available | +1 |
| Prior disclosed reports to study | +1 |

**Score**:
- < 4: Skip
- 4-5: Only if nothing better available
- 6-8: Good — spend 1-3 days
- >= 9: Excellent — spend up to 1 week

### Step 0.3: Pre-Dive Kill Signals

- [ ] Max bounty < $500 → skip
- [ ] All recent reports are N/A or duplicate → saturated
- [ ] Scope is only a static marketing page → no attack surface
- [ ] Company < 5 employees with no revenue → won't pay
- [ ] Explicitly excludes your planned bug class

---

## PHASE 1: RECON

### Step 1.1: Subdomain Enumeration (5 min)

```bash
TARGET="example.com"
mkdir -p /tmp/hunt-$TARGET

# Source 1: crt.sh (certificate transparency)
curl -s "https://crt.sh/?q=%.${TARGET}&output=json" \
  | jq -r '.[].name_value' \
  | sed 's/\*\.//g' \
  | sort -u > /tmp/hunt-$TARGET/subs.txt

# Source 2: subfinder (passive multi-source)
subfinder -d $TARGET -silent | anew /tmp/hunt-$TARGET/subs.txt

# Source 3: assetfinder
assetfinder --subs-only $TARGET | anew /tmp/hunt-$TARGET/subs.txt

echo "[+] Total subdomains: $(wc -l < /tmp/hunt-$TARGET/subs.txt)"
```

- [ ] Run all three sources
- [ ] Deduplicate with `sort -u`
- [ ] Total subdomains: ___

### Step 1.2: DNS Resolution + Live Host Discovery (5 min)

```bash
cat /tmp/hunt-$TARGET/subs.txt | dnsx -silent | httpx -silent -status-code -title -tech-detect | tee /tmp/hunt-$TARGET/live.txt
```

- [ ] Run dnsx + httpx pipeline
- [ ] Note total live hosts: ___
- [ ] Note tech stack detected: ___

### Step 1.3: URL Collection (5 min)

```bash
# Crawl live hosts
cat /tmp/hunt-$TARGET/live.txt | awk '{print $1}' | katana -d 3 -jc -kf all -silent | anew /tmp/hunt-$TARGET/urls.txt

# Historical URLs
echo $TARGET | gau --subs | anew /tmp/hunt-$TARGET/urls.txt
```

- [ ] Run katana crawl
- [ ] Run gau for historical URLs
- [ ] Total URLs collected: ___

### Step 1.4: Surface Analysis (5 min)

```bash
# Parameters worth testing
cat /tmp/hunt-$TARGET/urls.txt | grep -E "[?&](id|user|file|path|url|redirect|next|src|token|key|api_key)=" | tee /tmp/hunt-$TARGET/interesting-params.txt

# API endpoints
cat /tmp/hunt-$TARGET/urls.txt | grep -E "/api/|/v1/|/v2/|/v3/|/graphql|/rest/|/gql" | tee /tmp/hunt-$TARGET/api-endpoints.txt

# File upload endpoints
cat /tmp/hunt-$TARGET/urls.txt | grep -E "upload|file|attachment|document|image|avatar|photo|media" | tee /tmp/hunt-$TARGET/uploads.txt

# Admin/internal paths
cat /tmp/hunt-$TARGET/urls.txt | grep -E "/admin|/internal|/debug|/test|/staging|/dev|/management|/console" | tee /tmp/hunt-$TARGET/admin-paths.txt

# Auth endpoints
cat /tmp/hunt-$TARGET/urls.txt | grep -E "/oauth|/login|/auth|/sso|/saml|/oidc|/callback|/token" | tee /tmp/hunt-$TARGET/auth-paths.txt
```

- [ ] Run all grep filters
- [ ] Note interesting parameters found: ___
- [ ] Note API endpoints found: ___
- [ ] Note upload endpoints found: ___
- [ ] Note admin paths found: ___
- [ ] Note auth paths found: ___

### Step 1.5: gf Pattern Classification (5 min)

```bash
cat /tmp/hunt-$TARGET/urls.txt | gf xss | tee /tmp/hunt-$TARGET/xss-candidates.txt
cat /tmp/hunt-$TARGET/urls.txt | gf ssrf | tee /tmp/hunt-$TARGET/ssrf-candidates.txt
cat /tmp/hunt-$TARGET/urls.txt | gf idor | tee /tmp/hunt-$TARGET/idor-candidates.txt
cat /tmp/hunt-$TARGET/urls.txt | gf sqli | tee /tmp/hunt-$TARGET/sqli-candidates.txt
cat /tmp/hunt-$TARGET/urls.txt | gf redirect | tee /tmp/hunt-$TARGET/redirect-candidates.txt
cat /tmp/hunt-$TARGET/urls.txt | gf lfi | tee /tmp/hunt-$TARGET/lfi-candidates.txt
cat /tmp/hunt-$TARGET/urls.txt | gf rce | tee /tmp/hunt-$TARGET/rce-candidates.txt
```

- [ ] Run all gf patterns
- [ ] Note candidates per vuln class: XSS___ SSRF___ IDOR___ SQLi___ Redirect___ LFI___ RCE___

### Step 1.6: Nuclei Scan (5 min)

```bash
nuclei -l /tmp/hunt-$TARGET/live.txt -severity critical,high,medium -silent -o /tmp/hunt-$TARGET/nuclei.txt
```

- [ ] Run nuclei scan
- [ ] Note findings: ___

### Step 1.7: JS Analysis (if applicable)

```bash
cat /tmp/hunt-$TARGET/urls.txt | grep "\.js$" | sort -u > /tmp/hunt-$TARGET/jsfiles.txt

# SecretFinder (activate venv first)
source ~/tools/SecretFinder/.venv/bin/activate
cat /tmp/hunt-$TARGET/jsfiles.txt | head -50 | while read url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$url" -o cli 2>/dev/null
done
deactivate
```

- [ ] Run SecretFinder on JS bundles
- [ ] Note secrets found: ___

### Step 1.8: Port Scanning (5 min)

```bash
cat /tmp/hunt-$TARGET/live.txt | awk '{print $1}' | naabu -port 80,443,8080,8443,3000,4000,5000,8000,8888,9000,9090,9200,6379 -silent | tee /tmp/hunt-$TARGET/open-ports.txt
```

- [ ] Run naabu port scan
- [ ] Note open ports found: ___

---

## PHASE 2: LEARN

### Step 2.1: Read Disclosed Reports (10 min)

```bash
# Fetch disclosed reports from HackerOne
curl -s "https://hackerone.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{ hacktivity_items(first:25, order_by:{field:popular, direction:DESC}, where:{team:{handle:{_eq:\"PROGRAM_HANDLE\"}}}) { nodes { ... on HacktivityDocument { report { title severity_rating } } } } }"}' \
  | jq '.data.hacktivity_items.nodes[].report'
```

- [ ] Read at least 5 disclosed reports
- [ ] Note common vuln classes: ___
- [ ] Note tech stack from reports: ___
- [ ] Note bypass techniques used: ___

### Step 2.2: "What Changed" Method (5 min)

- [ ] Find disclosed report for similar tech
- [ ] Get the fix commit
- [ ] Read the diff — identify the anti-pattern
- [ ] Grep target for that same anti-pattern

### Step 2.3: Build Threat Model (5 min)

```
TARGET: _______________
CROWN JEWELS: 1.___ 2.___ 3.___
ATTACK SURFACE:
  [ ] Unauthenticated: login, register, password reset, public APIs
  [ ] Authenticated: all user-facing endpoints, file uploads, API calls
  [ ] Cross-tenant: org/team/workspace ID parameters
  [ ] Admin: /admin, /internal, /debug
HIGHEST PRIORITY (crown jewel x easiest entry):
  1.___ 2.___ 3.___
```

### Step 2.4: Tech Stack → Bug Class Map

| Stack | Hunt First | Hunt Second |
|---|---|---|
| Ruby on Rails | Mass assignment | IDOR (`:id` routes) |
| Django | IDOR (ModelViewSet, no object perms) | SSTI (mark_safe) |
| Flask | SSTI (render_template_string) | SSRF (requests lib) |
| Laravel | Mass assignment ($fillable) | IDOR (Eloquent, no ownership) |
| Express (Node.js) | Prototype pollution | Path traversal |
| Spring Boot | Actuator endpoints (/actuator/env) | SSTI (Thymeleaf) |
| ASP.NET | ViewState deserialization | Open redirect (ReturnUrl) |
| Next.js | SSRF via Server Actions | Open redirect via redirect() |
| GraphQL | Introspection → auth bypass on mutations | IDOR via node(id:) |
| WordPress | Plugin SQLi | REST API auth bypass |

---

## PHASE 3: HUNT

### Session Setup

- [ ] Create 2 test accounts (attacker + victim)
- [ ] Set up Burp Suite proxy
- [ ] Start note-taking system
- [ ] Define primary target: ONE crown jewel to hunt

### Note-Taking Template

```markdown
# TARGET: company.com -- SESSION 1

## Interesting Leads (not confirmed bugs yet)
- [14:22] /api/v2/invoices/{id} -- no auth check visible, testing...

## Dead Ends (don't revisit)
- /admin -> IP restricted, confirmed by trying 15+ bypass headers

## Anomalies
- GET /api/export returns 200 even when session cookie is missing
- Response time: POST /api/check-user -> 150ms (exists) vs 8ms (doesn't)

## Rabbit Holes (time-boxed, max 15 min each)
- [ ] 10 min: JWT kid injection on auth endpoint

## Confirmed Bugs
- [15:10] IDOR on /api/invoices/{id} -- read+write
```

### Subdomain Type → Hunt Strategy

| Subdomain Type | Strategy |
|---|---|
| dev/staging/test | Debug endpoints, disabled auth, verbose errors |
| admin/internal | Default creds, IP bypass headers (`X-Forwarded-For: 127.0.0.1`) |
| api/api-v2 | Enumerate with kiterunner, check older unprotected versions |
| auth/sso | OAuth misconfigs, open redirect in `redirect_uri` |
| upload/cdn | CORS, path traversal, stored XSS |

### Quick Wins Checklist

- [ ] Subdomain takeover (`subjack`, `subzy`)
- [ ] Exposed `.git` (`/.git/config`)
- [ ] Exposed env files (`/.env`, `/.env.local`)
- [ ] Default credentials on admin panels
- [ ] JS secrets (SecretFinder, jsluice)
- [ ] Open redirects (`?redirect=`, `?next=`, `?url=`)
- [ ] CORS misconfig (test `Origin: https://evil.com` + credentials)
- [ ] S3/cloud buckets
- [ ] GraphQL introspection enabled
- [ ] Spring actuators (`/actuator/env`, `/actuator/heapdump`)
- [ ] Firebase open read (`https://TARGET.firebaseio.com/.json`)

---

## PHASE 4: VALIDATE

### 7-Question Gate (MUST answer YES to ALL)

1. **Is this a real bug?** (not theoretical, not "could potentially")
2. **Can an attacker do this RIGHT NOW?** (not with hypothetical conditions)
3. **Does it cause real harm?** (stolen money, leaked PII, account takeover, code execution)
4. **Is the asset in scope?** (verify against program page)
5. **Is this already disclosed?** (check HackerOne disclosed reports)
6. **Is this already public?** (check if data is already accessible via web UI)
7. **Can I write a clear PoC?** (step-by-step reproduction)

**If ANY answer is NO → KILL THE FINDING**

### Pre-Submission Gates

- [ ] **Gate 1**: Verified with 2 different accounts (attacker + victim)
- [ ] **Gate 2**: Tested with different HTTP methods (GET, POST, PUT, DELETE, PATCH)
- [ ] **Gate 3**: Checked for rate limiting / WAF
- [ ] **Gate 4**: Confirmed impact (not just "access" but "what can you DO with access")

### Always-Rejected List (DON'T SUBMIT)

- [ ] CORS wildcard on public API without credentials
- [ ] Missing security headers without impact
- [ ] Version disclosure without exploitation path
- [ ] Open redirect without OAuth/ATO chain
- [ ] Self-XSS (only affects the attacker)
- [ ] CSRF on logout
- [ ] Clickjacking on non-sensitive page
- [ ] Information disclosure without sensitive data

---

## PHASE 5: REPORT

### Report Template

```markdown
# [Vuln Class] on [Endpoint] — [Impact Summary]

## Summary
One sentence: what, where, impact.

## Severity: [Critical/High/Medium/Low]
CVSS: X.X

## Vulnerability Details

### Endpoint
`[METHOD] https://target.com/path`

### Steps to Reproduce
1. Login as user A
2. Navigate to X
3. Intercept request to /api/endpoint
4. Change parameter from A's ID to B's ID
5. Observe: B's data is returned

### Impact
- What data is exposed?
- How many users affected?
- What can an attacker do with this?

### Proof of Concept
[Request/Response pairs with evidence]

### Remediation
[Specific fix recommendation]
```

### Report Quality Checklist

- [ ] Title is clear and specific
- [ ] Impact is business-relevant (not just "security risk")
- [ ] PoC is step-by-step (anyone can reproduce)
- [ ] Evidence includes request/response pairs
- [ ] No "could potentially" — prove it works
- [ ] CVSS score is justified
- [ ] Remediation is specific

---

## TOOLS QUICK REFERENCE

### Available Tools (installed)

| Tool | Path | Use |
|------|------|-----|
| subfinder | `/home/akheel/go/bin/subfinder` | Passive subdomain enum |
| httpx | `/home/akheel/go/bin/httpx` | Probe live hosts |
| nuclei | `/home/akheel/go/bin/nuclei` | Template scanner |
| katana | `/home/akheel/go/bin/katana` | Crawl |
| gau | `/home/akheel/go/bin/gau` | Known URLs |
| dalfox | `/home/akheel/go/bin/dalfox` | XSS scanner |
| ffuf | `/usr/bin/ffuf` | Fuzzer |
| gf | `/home/akheel/go/bin/gf` | Grep patterns |

### Sentinel v2 Tools (Python)

| Tool | Path | Use |
|------|------|-----|
| recon.py | `sentinel_v2/tools/recon.py` | Recon automation |
| crawler.py | `sentinel_v2/tools/crawler.py` | Web crawling |
| ffuf_bridge.py | `sentinel_v2/tools/ffuf_bridge.py` | Fuzzing |
| nuclei_bridge.py | `sentinel_v2/tools/nuclei_bridge.py` | Vulnerability scanning |
| http_client.py | `sentinel_v2/tools/http_client.py` | HTTP requests |
| browser.py | `sentinel_v2/tools/browser.py` | Browser automation |
| auth.py | `sentinel_v2/tools/auth.py` | Authentication handling |
| reporter.py | `sentinel_v2/tools/reporter.py` | Report generation |

### Missing Tools (install if needed)

```bash
# waybackurls (Wayback Machine URLs)
go install github.com/tomnomnom/waybackurls@latest

# interactsh-client (OOB callbacks)
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest

# kiterunner (API endpoint brute)
go install github.com/assetnote/kiterunner/cmd/kr@latest

# subzy (subdomain takeover check)
go install github.com/LukaSikic/subzy@latest

# arjun (hidden parameter discovery)
pip3 install arjun

# paramspider (URL parameter mining)
pip3 install paramspider

# SecretFinder (JS secret extraction)
git clone https://github.com/m4ll0k/SecretFinder.git ~/tools/SecretFinder
cd ~/tools/SecretFinder && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

# LinkFinder (endpoints in JS)
git clone https://github.com/GerbenJavado/LinkFinder.git ~/tools/LinkFinder
cd ~/tools/LinkFinder && python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt
```

---

## VULN-SPECIFIC CHECKLISTS

### IDOR Checklist

- [ ] Create two accounts (A = attacker, B = victim)
- [ ] Log in as A, note all IDs in requests
- [ ] Log in as B, replay A's requests with A's IDs
- [ ] Test EVERY endpoint with swapped IDs
- [ ] Try PUT/PATCH/DELETE (not just GET)
- [ ] Check API v1/v2 differences
- [ ] Check GraphQL node() queries
- [ ] Check WebSocket messages
- [ ] Test batch endpoints (`?ids=1,2,3,4,5`)
- [ ] Try adding unexpected params: `?user_id=other_user`

**Escalation**: IDOR + Write = High | IDOR + Admin = Critical | IDOR + ATO = Critical

### SSRF Checklist

- [ ] Try cloud metadata: `http://169.254.169.254/latest/meta-data/`
- [ ] Try internal services: `http://127.0.0.1:6379/` (Redis)
- [ ] Test all IP bypass techniques (decimal, hex, octal, short, IPv6)
- [ ] Test protocol bypass: `file://`, `dict://`, `gopher://`
- [ ] Look in: webhook URLs, import from URL, profile picture URL, PDF generators

**Escalation**: DNS-only = Info | Internal service = Medium | Cloud metadata = High | Keys + exfil = Critical

### XSS Checklist

- [ ] Test reflected XSS via URL parameters
- [ ] Test stored XSS via form inputs
- [ ] Test DOM-based XSS via JavaScript
- [ ] Check if HttpOnly is set on session cookie
- [ ] Test CSP bypass techniques

**Escalation**: Self-XSS = N/A | XSS + sensitive page = High | XSS + CSRF token theft = Critical

### OAuth/OIDC Checklist

- [ ] Missing `state` parameter → CSRF
- [ ] `redirect_uri` accepts wildcards → ATO
- [ ] Missing PKCE → code theft
- [ ] Open redirect in post-auth redirect → OAuth token theft chain

**Escalation**: Open redirect alone = Low | Open redirect + OAuth = Critical

### Race Condition Checklist

- [ ] Coupon codes / promo codes
- [ ] Gift card redemption
- [ ] Fund transfer / withdrawal
- [ ] Voting / rating limits
- [ ] OTP verification brute via race

```bash
# Quick race test
seq 20 | xargs -P 20 -I {} curl -s -POST https://TARGET/redeem \
  -H "Authorization: Bearer $TOKEN" -d 'code=PROMO10' &
wait
```

### File Upload Checklist

- [ ] Double extension: `file.php.jpg`
- [ ] Case variation: `file.pHp`
- [ ] Content-Type spoof: `image/jpeg` header with PHP content
- [ ] Magic bytes: `GIF89a; <?php system($_GET['c']); ?>`
- [ ] SVG XSS: `<svg onload=alert(1)>`
- [ ] Zip slip: `../../etc/cron.d/shell` in filename inside archive

### GraphQL Checklist

- [ ] Test introspection: `{ __schema { types { name } } }`
- [ ] Test node() bypass for per-object auth
- [ ] Test batching attack (rate limit bypass)
- [ ] Test field suggestions (information disclosure)

---

## A→B BUG CHAIN TABLE

| Bug A (Signal) | Hunt for Bug B | Escalate to C |
|----------------|---------------|---------------|
| IDOR (read) | PUT/DELETE on same endpoint | Full account data manipulation |
| SSRF (any) | Cloud metadata 169.254.169.254 | IAM credential exfil → RCE |
| XSS (stored) | Check if HttpOnly is set on session cookie | Session hijack → ATO |
| Open redirect | OAuth redirect_uri accepts your domain | Auth code theft → ATO |
| S3 bucket listing | Enumerate JS bundles | Grep for OAuth client_secret → OAuth chain |
| Rate limit bypass | OTP brute force | Account takeover |
| GraphQL introspection | Missing field-level auth | Mass PII exfil |
| Debug endpoint | Leaked environment variables | Cloud credential → infrastructure access |
| CORS reflects origin | Test with credentials: include | Credentialed data theft |
| Host header injection | Password reset poisoning | ATO via reset link |

---

## TIMING GUIDE

| Phase | Time | Goal |
|-------|------|------|
| Phase 0: Target Selection | 15 min | Go/No-Go decision |
| Phase 1: Recon | 30 min | Asset discovery, surface mapping |
| Phase 2: Learn | 15 min | Understand the app like a real user |
| Phase 3: Hunt | 2-4 hours | Find vulnerabilities |
| Phase 4: Validate | 30 min | Confirm impact, 7-Question Gate |
| Phase 5: Report | 30 min | Write clear, actionable report |

**Total per target**: 3-5 hours

**5-Minute Rule**: If target shows nothing after 5 min probing (all 401/403/404), MOVE ON.

**1-Hour Rule**: Stuck on one target for an hour with no progress? SWITCH CONTEXT.

---

## DAILY HUNTING ROUTINE

### Morning (30 min)
1. Check for new subdomains on targets (continuous monitoring)
2. Read HackerOne activity feed
3. Pick 1-2 targets for the day

### Day (3-4 hours)
1. Run full recon pipeline on selected targets
2. Hunt top 3 vuln classes per target
3. Validate any findings

### Evening (30 min)
1. Write reports for confirmed findings
2. Submit to HackerOne
3. Review N/A responses for lessons learned

---

## EMERGENCY RESPONSE

### If You Find Critical Vuln
1. **STOP** — don't panic
2. **Document everything** — screenshots, requests, responses
3. **Write report immediately** — don't wait
4. **Submit via HackerOne** — use their template
5. **Don't disclose publicly** — wait for triage

### If You Get N/A Response
1. **Read the triage reason carefully**
2. **Check if your PoC was clear enough**
3. **Ask for clarification** if needed
4. **Don't resubmit** unless you have new evidence
5. **Move on** — don't argue

---

*Last Updated: August 5, 2026*
