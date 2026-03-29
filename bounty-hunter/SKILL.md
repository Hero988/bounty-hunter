---
name: bounty-hunter
description: >-
  Automated bug bounty hunting from program URL to submission-ready report.
  Parses HackerOne/Bugcrowd/Intigriti/Immunefi program scope, runs full
  reconnaissance (subdomain enum, HTTP probing, tech fingerprinting, content
  discovery), scans for 20+ vulnerability classes with nuclei and custom checks,
  guides manual testing for business logic and auth flaws, validates findings
  with PoC generation, and produces platform-specific reports with CVSS scoring.
  Use when hunting bugs, starting a new target, doing security recon, testing
  for vulnerabilities, writing bug bounty reports, or any offensive security testing.
allowed-tools: Bash Read Write Edit Glob Grep WebFetch WebSearch Agent
---

# Bounty Hunter

Automated 8-phase bug bounty pipeline. Pass a program URL or domain and this skill handles everything from reconnaissance to report generation.

**Usage:** `/bounty-hunter <program-url-or-domain> [--phase recon|scan|report] [--resume]`

## Automatic Bootstrap (runs silently on every invocation)

The following status is detected at invocation time:

!`python -c "
import os, json, time, shutil, subprocess
home = os.path.expanduser('~')
tk = os.path.join(home, '.bounty-hunter-toolkit')
exists = os.path.isdir(tk)
needs_update = False
if exists:
    vf = os.path.join(tk, 'version.json')
    if os.path.isfile(vf):
        with open(vf) as f: v = json.load(f)
        print(f'TOOLKIT=installed VERSION={v.get(\"version\",\"?\")}')
    else: print('TOOLKIT=installed VERSION=unknown')
    # Compare local HEAD vs remote HEAD to detect updates
    try:
        local = subprocess.run('git -C \"'+tk+'\" rev-parse HEAD', shell=True, capture_output=True, text=True, timeout=5).stdout.strip()
        remote = subprocess.run('git -C \"'+tk+'\" ls-remote origin HEAD', shell=True, capture_output=True, text=True, timeout=10).stdout.split()[0] if subprocess.run('git -C \"'+tk+'\" ls-remote origin HEAD', shell=True, capture_output=True, text=True, timeout=10).stdout else ''
        if local and remote and local != remote:
            print('TOOLKIT_UPDATE=available')
            needs_update = True
        else:
            print('TOOLKIT_UPDATE=up_to_date')
    except: print('TOOLKIT_UPDATE=check_failed')
else: print('TOOLKIT=missing')
tools = {t: bool(shutil.which(t)) for t in ['nuclei','subfinder','httpx','ffuf','katana','nmap']}
m = [t for t,v in tools.items() if not v]
print(f'CORE_TOOLS={len(tools)-len(m)}/6 MISSING={\" \".join(m) or \"none\"}')
# Check nuclei templates
import glob
tdir = os.path.join(home, 'nuclei-templates')
tcount = len(glob.glob(os.path.join(tdir, '**', '*.yaml'), recursive=True)) if os.path.isdir(tdir) else 0
print(f'NUCLEI_TEMPLATES={tcount}')
" 2>/dev/null || echo "TOOLKIT=check_failed"`

**You MUST execute ALL of the following steps automatically and silently before doing anything else. Do NOT ask the user — just do it. Only inform the user if something fails.**

1. **Set TK variable** for all subsequent commands:
   ```bash
   TK="$HOME/.bounty-hunter-toolkit"
   ```

2. **If TOOLKIT=missing**: Clone the toolkit silently:
   ```bash
   git clone https://github.com/Hero988/bounty-hunter-toolkit "$TK"
   ```

3. **If TOOLKIT_UPDATE=available** (remote has new commits): Pull latest updates silently:
   ```bash
   git -C "$TK" pull 2>/dev/null || true
   ```
   This ensures users get toolkit updates immediately on next invocation — not on a delay.

4. **If MISSING is not "none"**: Install missing tools automatically:
   ```bash
   python "$TK/scripts/setup.py" --install-missing
   ```

5. **If NUCLEI_TEMPLATES < 5000**: Update nuclei templates automatically:
   ```bash
   nuclei -update-templates 2>/dev/null || true
   ```

6. **Run quick health check** (output is for your reference only, do NOT show to user unless there are failures):
   ```bash
   python "$TK/scripts/health_check.py" --quick 2>/dev/null
   ```

After all bootstrap steps complete, proceed directly to mode detection. The user never needs to run setup, update, or health check manually — it all happens automatically every time the skill is invoked.

---

## Mode Detection

Parse `$ARGUMENTS` to determine mode:
- **No args or `--help`**: Show usage and available commands
- **`--resume`**: Run `python $TK/scripts/session_manager.py list` and resume the latest active session
- **URL or domain**: Start full 8-phase hunt (default)
- **`--phase recon`**: Run only Phases 1-4
- **`--phase scan`**: Run only Phase 5
- **`--phase report`**: Run only Phase 8 from existing findings

---

## SAFETY RULES — ABSOLUTE, NEVER VIOLATE

1. **NEVER** test any asset not confirmed in-scope by scope_guard.py
2. **NEVER** modify or delete data on the target — read-only testing only
3. **NEVER** perform denial-of-service or load testing
4. **NEVER** exceed rate limits (default: 50 requests/second)
5. **NEVER** access real user data beyond minimum needed for PoC — use test accounts
6. **NEVER** exfiltrate data from the target
7. **ALWAYS** run `python $TK/scripts/scope_guard.py scope.json <target>` before any network request to a new host
8. **ALWAYS** respect the program's excluded vulnerability types
9. **STOP** immediately if the user reports the target is having issues
10. **ASK** the user before performing any active exploitation or submitting reports
11. **DISPLAY** a legal disclaimer at session start: "This tool is for authorized security testing only. Only use on targets where you have explicit permission (bug bounty programs, your own assets)."

---

## Phase 1: Program Scope Parsing

**Goal:** Parse the program scope into a structured scope.json file.

1. Detect platform: `python $TK/scripts/scope_parser.py --detect "$ARGUMENTS"`
2. If **HackerOne URL**:
   - **Use the GraphQL API first** (more reliable than WebFetch, HackerOne pages require JS rendering):
     ```bash
     curl -s 'https://hackerone.com/graphql' -H 'Content-Type: application/json' \
       -d '{"query":"query {team(handle:\"<handle>\"){name handle policy structured_scopes(first:100){edges{node{asset_identifier asset_type eligible_for_bounty max_severity instruction}}}}}"}'
     ```
   - Parse the response to extract in-scope/out-of-scope assets, bounty eligibility, and severity caps
   - **If asset_type is GOOGLE_PLAY_APP_ID**: note the package name — APK analysis will be prioritized in Phase 3.5
   - Fallback to `WebFetch` if GraphQL fails
   - Create scope.json: `python $TK/scripts/scope_parser.py --from-json '<json>' hunt-<target>-$(date +%Y%m%d)/scope.json`
3. If **Bugcrowd/Intigriti/Immunefi URL**:
   - Use `WebFetch` to retrieve the program page
   - Extract: in-scope assets, out-of-scope, bounty table, excluded vuln types, program rules
   - Create scope.json: `python $TK/scripts/scope_parser.py --from-json '<json>' hunt-<target>-$(date +%Y%m%d)/scope.json`
4. If **raw domain**:
   - Run: `python $TK/scripts/scope_parser.py <domain> hunt-<target>-$(date +%Y%m%d)/scope.json`
   - **ASK the user to confirm scope before proceeding**
5. **Check scope type**: `python $TK/scripts/scope_guard.py scope.json --scope-type`
   - If `SCOPE_TYPE=specific_urls` → skip subdomain enumeration in Phase 2 (waste of time), focus on the specific in-scope URLs
   - If `SCOPE_TYPE=wildcard_or_cidr` → proceed with full subdomain enumeration
6. Create session: `python $TK/scripts/session_manager.py create <target> hunt-<target>-$(date +%Y%m%d) scope.json`
7. Display scope summary and get user confirmation

**Output:** `hunt-<target>/scope.json`, `hunt-<target>/session.json`

---

## Phase 2: Passive Reconnaissance

**Goal:** Discover all assets without touching the target. This is the foundation — 80% of success depends on recon quality.

1. Run the recon orchestrator:
   ```bash
   bash $TK/scripts/recon_orchestrator.sh <primary-domain> hunt-<target>-$(date +%Y%m%d) scope.json
   ```
   This runs: subfinder, assetfinder, crt.sh, gau, waybackurls, httpx, nmap

2. **OSINT enrichment** (Claude does this manually):
   - Use `WebSearch` to find: `"<target>" CVE 2025 2026` — recent CVEs affecting the target
   - Use `WebSearch` to find: `site:hackerone.com "<target>" disclosed` — disclosed reports
   - Use `WebSearch` to find: `"<target>" vulnerability writeup` — public writeups
   - Use `WebSearch` to find: `site:github.com "<target>" password OR secret OR api_key` — leaked credentials
   - Document findings in `hunt-<target>/recon/osint-notes.md`

3. Review tech profile: `cat hunt-<target>/recon/tech-profile.md`
4. **Check for geo-restrictions**: Read `hunt-<target>/recon/geo-report.md` if it exists
   - If targets are geo-blocked: reprioritize to accessible targets + mobile APK analysis
   - **WARNING:** "Virtual" VPN servers (e.g., NordVPN "India - Virtual") route through other countries and will NOT bypass geo-restrictions. Use a cloud VPS with a real IP in the target region (GCP asia-south1, AWS ap-south-1, etc.) or prioritize APK analysis which bypasses geo-restrictions entirely.
5. **Analyze historical URLs**: `python $TK/scripts/wayback_analyzer.py hunt-<target>/recon/urls.txt hunt-<target>-$(date +%Y%m%d)`
   - Review the prioritized report for API endpoints, admin panels, PII in URLs, sensitive files
6. Update session: `python $TK/scripts/session_manager.py update <session-id> passive_recon --completed`

**Key outputs:** `recon/subdomains.txt`, `recon/live-hosts.json`, `recon/tech-profile.md`, `recon/urls.txt`, `recon/geo-report.md`

---

## Phase 3: Active Reconnaissance

**Goal:** Probe live hosts for detailed fingerprinting and port information.

The recon orchestrator already handles httpx probing and nmap scanning. Review the results:

1. Read `hunt-<target>/recon/live-hosts.json` — examine status codes, titles, technologies
2. Read `hunt-<target>/recon/tech-profile.md` — understand the technology stack
3. Read `hunt-<target>/recon/nmap-results.txt` (if exists) — check for unusual open ports
4. Identify **high-value targets**: admin panels, API endpoints, login pages, file upload forms, GraphQL endpoints, older/legacy systems
5. Create `hunt-<target>/recon/priority-targets.md` listing the most promising hosts to test
6. Update session phase

**Decision tree for prioritization:**
- Status 200 + login form → HIGH (test auth bypass, credential stuffing)
- Status 200 + API/GraphQL → HIGH (test IDOR, mass assignment, auth)
- Status 200 + file upload → HIGH (test upload bypass, SSRF)
- Status 403 → MEDIUM (test bypass: path traversal, verb tampering, header manipulation)
- Status 301/302 → LOW (check redirect destination, open redirect)
- Status 500 → MEDIUM (check for error-based info disclosure)

---

## Phase 3.5: Mobile App Analysis (when mobile apps are in scope)

**Goal:** Analyze Android APKs for hardcoded secrets, API endpoints, and misconfigurations. This phase often yields the highest-value findings — APK analysis found 3 reportable bugs in the Meesho engagement while web recon found only low-severity issues.

**Run this phase BEFORE vulnerability scanning if any of these are true:**
- scope.json contains assets with type `GOOGLE_PLAY_APP_ID`
- The target has a known mobile app
- Web targets are geo-blocked (APK analysis bypasses geo-restrictions)
- The user mentions mobile testing

1. **Download and analyze the APK**:
   ```bash
   python $TK/scripts/apk_analyzer.py <package-name-or-apk-path> hunt-<target>-$(date +%Y%m%d)
   ```
   This decompiles the APK, scans for secrets, extracts API endpoints, and analyzes the manifest.

2. **Review findings**: Read `hunt-<target>/apk-analysis/report.md` and `hunt-<target>/apk-analysis/findings.json`

3. **For each hardcoded token/key found** (this is critical — read `$TK/references/methodology/apk-analysis-checklist.md`):
   - Test against every discovered API endpoint
   - Use mobile User-Agent headers: `-H "User-Agent: okhttp/4.x"`
   - Check if the token bypasses WAF/geo-restrictions
   - Document what data each token provides access to
   - Check read-only vs read-write access
   - Test if it can access other users' data (IDOR)

4. **Check exported components**: Test exported activities via deep links for auth bypass

5. **Check JS interfaces in WebViews**: If `@JavascriptInterface` is found, test for XSS-to-native-bridge attacks

6. **If APK download fails** (geo-restricted Play Store): Try fallback sources (APKPure, APKCombo) or analyze the web/WebView version instead

**Reference:** `$TK/references/methodology/apk-analysis-checklist.md` — full checklist with grep patterns and report templates

---

## Phase 4: Content Discovery

**Goal:** Find hidden directories, endpoints, parameters, and JavaScript files.

1. Run content discovery:
   ```bash
   bash $TK/scripts/content_discovery.sh hunt-<target>/recon/live-hosts.txt hunt-<target>-$(date +%Y%m%d) scope.json
   ```
   This runs: ffuf directory fuzzing, katana crawling, parameter extraction

2. **JavaScript analysis** (Claude does this):
   - Read JS files listed in `recon/endpoints/js-files.txt`
   - Search for: API endpoints, hardcoded secrets, internal URLs, debug flags, commented credentials
   - Use `WebFetch` to retrieve and analyze significant JS files
   - Document findings in `hunt-<target>/recon/js-analysis.md`

3. Review discovered parameters: `cat hunt-<target>/recon/parameters.json`
   - Flag interesting parameters: `id`, `user`, `account`, `file`, `path`, `url`, `redirect`, `callback`, `template`, `query`, `search`, `cmd`, `exec`

4. Update session phase

---

## Phase 5: Vulnerability Scanning

**Goal:** Run automated scanners with tech-aware template selection.

1. Run the vulnerability scanner:
   ```bash
   bash $TK/scripts/vuln_scanner.sh hunt-<target>/recon/live-hosts.txt hunt-<target>-$(date +%Y%m%d) scope.json hunt-<target>/recon/tech-profile.md
   ```
   This runs nuclei in 4 layers: exposures → CVEs (tech-targeted) → vulnerabilities → custom templates

2. Review findings: Read `hunt-<target>/findings/automated-findings.json`
3. Triage results:
   - **Critical/High**: Investigate immediately, validate manually
   - **Medium**: Investigate if time allows, check for chaining potential
   - **Low/Info**: Note for later, check chain-building reference
4. For each promising finding, run scope guard: `python $TK/scripts/scope_guard.py scope.json <target-url>`
5. Update session phase

---

## Phase 6: Manual-Guided Testing

**Goal:** Test for vulnerabilities that scanners miss — business logic, auth flaws, IDOR, and complex injection. This is where the money is.

### Step 1: Understand the Application
Use `WebFetch` to read the target's main pages and understand:
- What does this application do? (e-commerce, SaaS, social, financial, etc.)
- What user roles exist? (admin, user, moderator, etc.)
- What are the high-value features? (payments, user data, file handling, AI features)
- What authentication/authorization model is used?

### Step 2: Select Testing Areas Based on Features

**For each feature present, load the relevant reference and test:**

| Feature Present | Load Reference | Priority Tests |
|----------------|---------------|----------------|
| User accounts | `$TK/references/vuln-classes/access-control.md` | IDOR, privilege escalation, auth bypass |
| Login/signup | `$TK/references/vuln-classes/access-control.md` | Credential stuffing, password reset, session fixation |
| Search/filter | `$TK/references/vuln-classes/injection.md` | SQLi, XSS, SSTI |
| File upload | `$TK/references/vuln-classes/server-side.md` | Upload bypass, SSRF, path traversal |
| Payments | `$TK/references/vuln-classes/business-logic.md` | Price manipulation, race conditions, workflow bypass |
| API endpoints | `$TK/references/vuln-classes/api-security.md` | Mass assignment, broken auth, rate limiting |
| GraphQL | `$TK/references/vuln-classes/api-security.md` | Introspection, field-level auth, nested query DoS |
| AI/chatbot | `$TK/references/vuln-classes/ai-llm.md` | Prompt injection, data exfiltration, agent abuse |
| Redirects | `$TK/references/vuln-classes/client-side.md` | Open redirect, CSPT, OAuth flow abuse |
| Admin panel | `$TK/references/vuln-classes/access-control.md` | Auth bypass, vertical privilege escalation |

### Step 3: Execute Testing
For each selected area:
1. Read the relevant vuln-class reference file for testing checklist and payloads
2. Also read the relevant payload file from `$TK/references/payloads/`
3. Test systematically following the checklist
4. Document each test attempt and result
5. If you find something, immediately validate and check for chain opportunities

### Step 4: Chain Building
Read `$TK/references/methodology/chain-building.md` for:
- Combining low-severity findings into high-impact reports
- Common chain patterns (open redirect + OAuth = ATO, etc.)
- When chaining is worth the effort

---

## Phase 7: Validation & PoC Creation

**Goal:** Validate findings, create reproducible PoCs, and check for duplicates.

### 7-Question Gate — ALL must pass before creating a report:

1. **Can a real attacker do this RIGHT NOW** against a real user who took no unusual actions?
2. **Does this cause concrete harm?** (data leak, money loss, account takeover, code execution)
3. **Is this likely NOT a duplicate?** Run: `python $TK/scripts/dedup_checker.py "<vuln_type>" "<target>" "<component>"`
4. **Is this in scope AND not in excluded vulnerability types?** Run: `python $TK/scripts/scope_guard.py scope.json <target>` AND `python $TK/scripts/scope_guard.py scope.json --check-vuln "<vuln_type>"`
5. **Is severity >= medium?** (or does it chain to >= medium?)
6. **Can you write clear reproduction steps** a triager can follow in under 5 minutes?
7. **Does the PoC prove IMPACT**, not just existence?

**If any answer is NO**: Discard (move to `findings/discarded/`) or investigate chaining potential.

### PoC Creation:
- Write exact curl commands that reproduce the issue
- Include HTTP request/response pairs
- Create step-by-step reproduction with exact URLs and parameters
- Show the impact (what data was accessed, what action was performed)
- Save to `hunt-<target>/findings/manual-findings/<finding-name>/`

### Duplicate Check:
Use the search queries from dedup_checker.py with `WebSearch` to check:
- HackerOne hacktivity for the same program
- Public writeups mentioning the same vulnerability
- Known CVEs for the same component

---

## Phase 8: Report Generation

**Goal:** Create submission-ready reports that maximize acceptance probability.

1. Get the report template: `python $TK/scripts/report_generator.py --template <platform>`
2. Fill in finding data and generate: `python $TK/scripts/report_generator.py finding.json --platform <platform> --output report.md`
3. Read the platform guide: `$TK/references/platforms/<platform>.md`
4. Read the report template: `$TK/references/report-templates/<platform-abbrev>-template.md`

### Report Quality Rules:
- **Title**: `[Vuln Type] in [Component] allows [Impact]` — clear, specific, under 80 chars
- **CVSS**: Calculate with `python $TK/scripts/report_generator.py --cvss '<vector>'` — justify every metric choice
- **Steps to Reproduce**: Numbered, a triager must be able to follow in <5 minutes
- **Impact**: Concrete business impact, not theoretical risk
- **Tone**: Professional, human, concise — not robotic or verbose
- **Evidence**: curl commands, HTTP logs, screenshots (describe what they show)
- **Remediation**: Optional but increases credibility — suggest a specific fix

### Before Submission:
- Re-read the entire report from a triager's perspective
- Verify all URLs/payloads still work
- Confirm scope and excluded vuln types one final time
- **ASK the user for final approval before any submission**

---

## Session Management

- **Save progress**: Session auto-saves after each phase via session_manager.py
- **Resume**: `/bounty-hunter --resume` lists sessions and resumes the latest
- **List sessions**: `python $TK/scripts/session_manager.py list`
- **Load specific**: `python $TK/scripts/session_manager.py load <session-id>`

---

## Auto-Update (fully automatic)

Everything stays current without user intervention:

1. **Toolkit repo**: `git pull` runs automatically at the start of every session when remote has new commits — updates all scripts, references, payloads, and methodology instantly
2. **Tool binaries + nuclei templates**: The bootstrap checks for missing/outdated tools and templates on every invocation and updates them silently
3. **Runtime intelligence**: During every engagement, use `WebSearch` to pull latest CVEs, disclosed reports, and new techniques for the specific target — this is live, no install needed

---

## Reference File Index

Load these on demand when needed during testing:

### Vulnerability Classes
| File | When to Read |
|------|-------------|
| `$TK/references/vuln-classes/injection.md` | Testing search, forms, template rendering, file paths |
| `$TK/references/vuln-classes/client-side.md` | Testing reflected/stored content, redirects, forms |
| `$TK/references/vuln-classes/access-control.md` | Testing user accounts, permissions, auth flows |
| `$TK/references/vuln-classes/server-side.md` | Testing URL fetching, file ops, concurrent requests |
| `$TK/references/vuln-classes/api-security.md` | Testing REST/GraphQL/WebSocket APIs |
| `$TK/references/vuln-classes/ai-llm.md` | Testing AI chatbots, copilots, agent features |
| `$TK/references/vuln-classes/infrastructure.md` | Testing subdomains, cloud, exposed services |
| `$TK/references/vuln-classes/business-logic.md` | Testing payments, workflows, rate limits |

### Methodology
| File | When to Read |
|------|-------------|
| `$TK/references/methodology/recon-playbook.md` | Planning and executing reconnaissance |
| `$TK/references/methodology/manual-testing-guide.md` | Deciding what to test manually + token validation |
| `$TK/references/methodology/chain-building.md` | Found a low-severity bug, looking to chain |
| `$TK/references/methodology/target-prioritization.md` | Choosing programs or features to test |
| `$TK/references/methodology/apk-analysis-checklist.md` | Mobile APK analysis, secret scanning, token testing |

### Payloads
| File | When to Read |
|------|-------------|
| `$TK/references/payloads/xss-payloads.md` | XSS testing with WAF bypass variants |
| `$TK/references/payloads/sqli-payloads.md` | SQL injection by database type |
| `$TK/references/payloads/ssrf-payloads.md` | SSRF with cloud metadata and IP tricks |
| `$TK/references/payloads/ssti-payloads.md` | Template injection by engine |
| `$TK/references/payloads/prompt-injection-payloads.md` | LLM prompt injection techniques |

### Platform Guides & Templates
Read the relevant platform guide before submitting: `$TK/references/platforms/<platform>.md`
Use the matching report template: `$TK/references/report-templates/<abbrev>-template.md`
