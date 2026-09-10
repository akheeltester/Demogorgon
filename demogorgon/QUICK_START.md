# QUICK START: First Target on HackerOne

**Pick a program, then run this exact sequence:**

---

## STEP 1: SCOPE (5 min)

```bash
# Pick a program from hackerone.com/hacktivity/leaderboard
# Or check: hackerone.com/directory/programs
TARGET="example.com"  # Replace with actual target
```

- [ ] Read program page
- [ ] Note scope, exclusions, max bounty
- [ ] Score target (aim for 6+)

---

## STEP 2: RECON (30 min)

```bash
mkdir -p /tmp/hunt-$TARGET

# Subdomains
subfinder -d $TARGET -silent | anew /tmp/hunt-$TARGET/subs.txt

# Live hosts
cat /tmp/hunt-$TARGET/subs.txt | httpx -silent -status-code -title -tech-detect | tee /tmp/hunt-$TARGET/live.txt

# URLs
cat /tmp/hunt-$TARGET/live.txt | awk '{print $1}' | katana -d 3 -silent | anew /tmp/hunt-$TARGET/urls.txt
echo $TARGET | gau --subs | anew /tmp/hunt-$TARGET/urls.txt

# Nuclei
nuclei -l /tmp/hunt-$TARGET/live.txt -severity critical,high,medium -o /tmp/hunt-$TARGET/nuclei.txt

# Quick surface analysis
cat /tmp/hunt-$TARGET/urls.txt | grep -E "/api/|/graphql|upload|admin|oauth" | tee /tmp/hunt-$TARGET/high-value.txt
```

---

## STEP 3: LEARN (15 min)

- [ ] Read 5 disclosed reports for this program
- [ ] Note common vuln classes
- [ ] Note tech stack
- [ ] Build threat model

---

## STEP 4: HUNT (2-4 hours)

**Pick ONE of these based on your finding from Step 3:**

### If you found API endpoints → Hunt IDOR
```bash
# Test with two accounts
# Account A: note all IDs
# Account B: replay A's requests with A's IDs
```

### If you found file upload → Hunt XSS/RCE
```bash
# Test upload with:
# - SVG: <svg onload=alert(1)>
# - Double extension: file.php.jpg
# - Magic bytes bypass
```

### If you found OAuth → Hunt Open Redirect
```bash
# Test redirect_uri validation
# Try: https://evil.com
# Try: https://target.com@evil.com
# Try: //evil.com
```

### If you found GraphQL → Hunt Introspection
```bash
# Test: { __schema { types { name } } }
# Test: node(id: "base64(User:123)") { ... }
```

---

## STEP 5: VALIDATE (30 min)

- [ ] 7-Question Gate: ALL answers must be YES
- [ ] Test with 2 accounts
- [ ] Test different HTTP methods
- [ ] Confirm impact

---

## STEP 6: REPORT (30 min)

- [ ] Write clear title
- [ ] One sentence summary
- [ ] Step-by-step PoC
- [ ] Request/response evidence
- [ ] Impact statement
- [ ] Submit via HackerOne

---

## EMERGENCY COMMANDS

```bash
# If target shows nothing after 5 min
echo "Moving on to next target"

# If stuck for 1 hour
echo "Switching context"

# If you find something
echo "STOP. Document everything. Write report NOW."
```

---

*Good luck! Remember: Can an attacker do this RIGHT NOW against a real user? If no, STOP.*
