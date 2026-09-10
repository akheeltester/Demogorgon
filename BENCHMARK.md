# BENCHMARK.md — Industry Tool Comparison

## Comparison Framework

Compare Sentinel V2 against established tools on identical targets.

---

## Tool Profiles

| Tool | Purpose | Strength | Weakness |
|---|---|---|---|
| **Sentinel V2** | Autonomous bug bounty hunter | End-to-end: recon → test → report | LLM-dependent, unvalidated |
| **Burp Suite Pro** | Web vulnerability scanner | Deep crawling, active scanning, proven | Manual setup, not autonomous |
| **Katana** | Web crawler | Fast, headless/non-headless, recursive | Crawl only, no vuln detection |
| **Feroxbuster** | Directory fuzzer | Fast, recursive, filter patterns | No auth, no JS rendering |
| **Nuclei** | Vulnerability scanner | Template-based, 1000+ vuln templates | Requires known patterns |
| **Gau** | URL fetcher | Historical URLs from multiple sources | No live testing |
| **Wayback** | Historical URLs | Wayback Machine + Common Crawl | No live testing |
| **ffuf** | Web fuzzer | Fast, filter by response size/status | No auth, no JS |
| **httpx** | HTTP prober | Fast, tech detection, status codes | No vuln detection |

---

## Target: DVWA (Damn Vulnerable Web Application)

### Known Vulnerabilities

- SQL Injection (GET/POST)
- Reflected/Stored XSS
- Command Injection
- File Inclusion
- File Upload
- CSRF
- Weak Session IDs
- Information Disclosure

### Expected Results by Tool

| Capability | Sentinel V2 | Burp Suite | Katana | Feroxbuster | Nuclei | Gau | ffuf |
|---|---|---|---|---|---|---|---|
| Crawl pages | Browser render | Deep crawl | Fast crawl | Dir brute | Template match | Historical | N/A |
| Discover endpoints | ~7 (homepage) | 50+ | 100+ | 200+ (dirs) | Template endpoints | 1000+ | 200+ |
| Detect SQLi | LLM-dependent | Active scan | No | No | Template | No | No |
| Detect XSS | LLM-dependent | Active scan | No | No | Template | No | No |
| Detect CSRF | Replay engine | Manual | No | No | Template | No | No |
| Auth testing | Multi-session | Manual | No | No | Template | No | No |
| Report quality | Markdown | Professional | None | None | JSON | None | None |
| Runtime | ~5min | 30min+ | 1min | 2min | 5min | 30s | 1min |

### Sentinel V2 Advantages over Traditional Tools

1. **JS rendering** — Can discover SPA routes invisible to crawlers
2. **Business logic understanding** — LLM can identify workflows and ownership
3. **Automated testing** — Replays requests with mutations
4. **End-to-end** — Single command from recon to report
5. **Adaptive** — Can change strategy based on findings

### Sentinel V2 Disadvantages over Traditional Tools

1. **No deterministic crawling** — Relies on LLM to choose pages
2. **No brute-force discovery** — No wordlist-based directory scanning
3. **No template matching** — Can't match known vulnerability patterns
4. **No parallel testing** — Sequential iteration loop
5. **No proven detection** — All capabilities unvalidated

---

## Target: Juice Shop (OWASP)

### Known Vulnerabilities

- SQL Injection on login
- XSS (reflected/stored)
- Broken Access Control (IDOR)
- Insecure Direct Object Reference
- Unprotected file upload
- Exposed API documentation
- JWT weaknesses
- Privacy violation
- Missing rate limiting

### Expected Results by Tool

| Capability | Sentinel V2 | Burp Suite | Nuclei | Katana |
|---|---|---|---|---|
| Discover API endpoints | ~5 (if LLM navigates) | 100+ | Template-based | 200+ |
| Extract __NEXT_DATA__ | YES (if called) | Partial | No | No |
| Detect SQLi on login | LLM-dependent | Active scan | Template | No |
| Detect IDOR | Multi-session replay | Manual | Template | No |
| Extract JWT | Token extraction works | Manual | No | No |
| Test JWT weaknesses | LLM-dependent | Extensions | Template | No |
| Find admin panels | Admin path discovery (if called) | Crawl | Template | No |
| Detect file upload vuln | LLM-dependent | Active scan | Template | No |

---

## Target: crAPI (Completely Ridiculous API)

### Known Vulnerabilities

- IDOR on vehicle/user endpoints
- Mass assignment on user profile
- SSRF via webhook
- Broken authentication
- No rate limiting on API keys
- Verbose error messages

### Expected Results by Tool

| Capability | Sentinel V2 | Burp Suite | Nuclei | ffuf |
|---|---|---|---|---|
| Discover API endpoints | ~5 (if LLM navigates) | 50+ | Template | 100+ |
| Test IDOR | Multi-session replay | Manual | Template | No |
| Test mass assignment | LLM-dependent | Extensions | No | No |
| Detect SSRF | LLM-dependent | Active scan | Template | No |
| Rate limit testing | Race mode exists | Extensions | No | ffuf speed |
| Error message analysis | diff_responses() | Manual | Template | No |

---

## Target: GraphQLGoat

### Known Vulnerabilities

- Introspection enabled
- Query batching abuse
- Nested query DoS
- Field suggestion information disclosure
- Authorization bypass on mutations

### Expected Results by Tool

| Capability | Sentinel V2 | Burp Suite | Nuclei | Katana |
|---|---|---|---|---|
| Schema introspection | graphql_introspect() (if called) | Extensions | Template | No |
| Query batching | graphql_test_batching() (if called) | Extensions | No | No |
| Field suggestions | graphql_test_field_suggestion() (if called) | Extensions | No | No |
| Auth testing | Multi-session replay | Manual | No | No |

---

## Comparison Summary

| Dimension | Sentinel V2 | Traditional Tools |
|---|---|---|
| **Setup time** | 1 command | Configure per tool |
| **Recon quality** | Unknown (LLM-dependent) | Proven (deterministic) |
| **Vuln detection** | Unknown (LLM-dependent) | Proven (pattern/template) |
| **False positive rate** | Unknown | Low (validated templates) |
| **Novel vuln detection** | Potentially high (LLM reasoning) | Low (pattern matching) |
| **Business logic bugs** | Potentially high (LLM understanding) | None |
| **Speed** | Slow (sequential, LLM latency) | Fast (parallel, compiled) |
| **Reliability** | Low (LLM failures) | High (deterministic) |
| **Coverage** | Low (7 endpoints) | High (100+ endpoints) |
| **Report quality** | Unknown | Proven (Burp) |

---

## Key Insight

Sentinel V2's unique value proposition is **autonomous business logic understanding + adaptive testing**. Traditional tools are better at **deterministic discovery + pattern matching**. The ideal approach combines both.

Sentinel V2 should NOT try to replace Burp Suite or Nuclei. It should:
1. Use deterministic tools (ffuf, httpx, katana) for endpoint discovery
2. Use LLM for business logic understanding and hypothesis generation
3. Use replay engine for mutation testing
4. Use authcore for multi-user testing
