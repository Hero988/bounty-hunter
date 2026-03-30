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

**CRITICAL: Run the ENTIRE pipeline end-to-end without stopping.** Do NOT pause between phases to ask for confirmation. Do NOT ask "should I proceed?" or "do you want me to continue?". Just execute every phase in sequence automatically. The ONLY time you stop and ask the user is at the very end in Phase 8, before actually submitting reports to a bug bounty platform. Everything else runs uninterrupted.

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
# Check ZAP availability
zap_paths = [shutil.which('zap.sh'), shutil.which('zap')]
zap_ok = any(zap_paths) or shutil.which('docker')
print(f'ZAP={\"installed\" if any(zap_paths) else \"docker\" if shutil.which(\"docker\") else \"missing\"}')
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

7. **Check HackerOne API token** (for HackerOne programs — enables API submission, scope fetching, dedup checking):
   ```bash
   python "$TK/scripts/h1_api.py" --test 2>/dev/null
   ```
   - If `API connection: OK` → great, H1 API is available for scope fetching, hacktivity search, and report submission
   - If no token configured → inform user ONCE: "For HackerOne programs, you can set up an API token for direct report submission. Create one at https://hackerone.com/settings/api_token/edit then run: `python $TK/scripts/h1_api.py --setup <identifier> <token>`". Then continue without it — the API is optional, not required.

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
   - **If H1 API token is configured**, use the REST API for structured scope (most reliable):
     ```bash
     python $TK/scripts/h1_api.py --scopes <handle>
     ```
     This returns scope IDs, asset identifiers, bounty eligibility, and max severity — ready for scope.json.
     Also fetch weaknesses: `python $TK/scripts/h1_api.py --weaknesses <handle>`
   - **If no API token**, use the GraphQL API (no auth needed):
     ```bash
     curl -s 'https://hackerone.com/graphql' -H 'Content-Type: application/json' \
       -d '{"query":"query {team(handle:\"<handle>\"){name handle policy structured_scopes(first:100){edges{node{asset_identifier asset_type eligible_for_bounty max_severity instruction}}}}}"}'
     ```
   - Parse the response to extract in-scope/out-of-scope assets, bounty eligibility, and severity caps
   - **If asset_type is GOOGLE_PLAY_APP_ID**: note the package name — APK analysis will be prioritized in Phase 3.5
   - Fallback to `WebFetch` if both APIs fail
   - Create scope.json: `python $TK/scripts/scope_parser.py --from-json '<json>' hunt-<target>-$(date +%Y%m%d)/scope.json`
3. If **Intigriti URL**:
   - **If Intigriti API token is available** (check `$TK/.intigriti-token` or environment variable `INTIGRITI_TOKEN`):
     ```bash
     # Step 1: Find program by handle from the URL
     HANDLE=$(echo "$URL" | grep -oE 'programs/[^/]+/[^/]+' | cut -d/ -f3)
     COMPANY=$(echo "$URL" | grep -oE 'programs/[^/]+' | cut -d/ -f2)

     # Step 2: Search for the program ID
     curl -s -H "Authorization: Bearer $INTIGRITI_TOKEN" \
       "https://api.intigriti.com/external/researcher/v1/programs?statusId=3&limit=500" \
       | python -c "import json,sys; programs=json.load(sys.stdin)['records']; match=[p for p in programs if p['handle']=='$HANDLE']; print(json.dumps(match[0]) if match else 'NOT_FOUND')"

     # Step 3: Get full program details with scope
     curl -s -H "Authorization: Bearer $INTIGRITI_TOKEN" \
       "https://api.intigriti.com/external/researcher/v1/programs/$PROGRAM_ID"
     ```
     The response includes `domains.content[]` with each asset's `endpoint`, `type` (Url=1, Android=2, iOS=3, IpRange=4, Wildcard=7), and `tier` (Tier1=4, Tier2=3, Tier3=2, NoBounty=1, OutOfScope=5).
     Also check `rulesOfEngagement.content.testingRequirements` for:
     - `automatedTooling` — scanner policy
     - `userAgent` — required User-Agent header
     - `requestHeader` — required custom header
   - **If no API token**, inform user ONCE: "For Intigriti programs, set up an API token at https://app.intigriti.com/researcher/personal-access-tokens then save it: `echo 'YOUR_TOKEN' > $TK/.intigriti-token`". Then fall back to `WebFetch`.
   - Create scope.json from the API response
4. If **Bugcrowd/Immunefi URL**:
   - Use `WebFetch` to retrieve the program page
   - Extract: in-scope assets, out-of-scope, bounty table, excluded vuln types, program rules
   - Create scope.json: `python $TK/scripts/scope_parser.py --from-json '<json>' hunt-<target>-$(date +%Y%m%d)/scope.json`
5. If **raw domain**:
   - Run: `python $TK/scripts/scope_parser.py <domain> hunt-<target>-$(date +%Y%m%d)/scope.json`
   - Show the scope briefly and continue (do NOT stop to ask for confirmation)
6. **Check scope type**: `python $TK/scripts/scope_guard.py scope.json --scope-type`
   - If `SCOPE_TYPE=specific_urls` → skip subdomain enumeration in Phase 2 (waste of time), focus on the specific in-scope URLs
   - If `SCOPE_TYPE=wildcard_or_cidr` → proceed with full subdomain enumeration
7. Create session: `python $TK/scripts/session_manager.py create <target> hunt-<target>-$(date +%Y%m%d) scope.json`
8. Display a brief scope summary (high-value targets, mobile apps, exclusions) and **immediately continue to Phase 2** — do NOT wait for user confirmation

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
6. **If Cloudflare blocks active probing**: Skip httpx/nmap, focus on passive techniques (Wayback Machine, JS bundle analysis, GitHub OSINT, APK analysis). Set up CDP browser bridge for later authenticated testing.
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

3. **SPA Bundle API Extraction** (most productive technique for modern SPAs):
   - Download the main JS bundle: `curl -s TARGET/main.*.js > bundle.js`
   - Extract ALL API endpoints: `grep -oE '/api/v[0-9]+/[a-zA-Z0-9_/]+' bundle.js | sort -u`
   - Find separate API domains: `grep -oE '(apiUrl|publicApiUrl|baseUrl)[^,}]*' bundle.js`
   - Find auth mechanism: `grep -oE '.{0,80}(X-API-KEY|Authorization|sign\().{0,80}' bundle.js`
   - **This often discovers 100-200+ endpoints** including internal/undocumented ones
   - Check for multiple API namespaces (e.g., `/api/v3/`, `/api/v4/`, `/public_api/v1/`)
   - Save to `hunt-<target>/recon/api-endpoints.txt`

4. **SPA Catch-All Detection**: Test if random paths return 200 — if so, the app uses client-side routing and non-API 200s are false positives

5. **SAP/OData API Discovery** (when SAP technology detected — look for `sap-server`, `sap-client` headers, `/sap/` paths):
   - Fetch OData `$metadata`: `curl -H "Cookie: $COOKIES" "$TARGET/\$metadata"` (usually 10-100KB XML with full entity model)
   - Run the OData analyzer: `python $TK/scripts/odata_analyzer.py <metadata-url-or-file> hunt-<target>/recon --cookies hunt-<target>/auth/cookies.txt`
   - This extracts all entity types, writable fields, function imports, and generates test commands
   - Fetch `manifest.json` for SAP UI5 apps — reveals routes with `{account}` and `{id}` parameters (IDOR candidates), additional data sources, and model bindings
   - Fetch `Component-preload.js` — contains ALL bundled app logic (controllers, views, services)
   - Search the JS bundle for: OData entity reads/writes, navigation patterns with ID parameters, payment flows, admin URLs, dev/QA server hostnames
   - **Reference:** `$TK/references/methodology/sap-odata-testing-guide.md`

6. Review discovered parameters: `cat hunt-<target>/recon/parameters.json`
   - Flag interesting parameters: `id`, `user`, `account`, `file`, `path`, `url`, `redirect`, `callback`, `template`, `query`, `search`, `cmd`, `exec`

4. Update session phase

---

## Phase 5: Vulnerability Scanning

**Goal:** Run automated scanners — nuclei for known CVEs, OWASP ZAP for active web app testing.

### Step 0: Check Scanner Policy
**CRITICAL**: Some programs explicitly ban automated scanners ("Do not use scanners or automated tools"). If the program policy says this:
- **SKIP** nuclei, nmap, ffuf, katana, and all automated scanning
- **FOCUS ON**: JS bundle analysis for API endpoint discovery, APK analysis (offline), manual testing via CDP browser bridge
- **USE**: `curl -s TARGET/main.*.js | grep -oE '/api/v[0-9]+/[a-zA-Z0-9_/]+'` to discover API endpoints from the SPA JavaScript bundle — this is often MORE productive than scanner-based discovery
- The JS bundle typically reveals the COMPLETE API surface including internal/undocumented endpoints

### Step 1: Nuclei Scanning (known vulnerabilities)
```bash
bash $TK/scripts/vuln_scanner.sh hunt-<target>/recon/live-hosts.txt hunt-<target>-$(date +%Y%m%d) scope.json hunt-<target>/recon/tech-profile.md
```
This runs nuclei in 4 layers: exposures → CVEs (tech-targeted) → vulnerabilities → custom templates

### Step 2: OWASP ZAP Active Scanning (web app vulnerabilities)
ZAP finds what nuclei misses: XSS, SQLi, CSRF, path traversal, and other dynamic vulnerabilities.

1. **Check if ZAP is available**:
   ```bash
   python $TK/scripts/zap_controller.py --status
   ```
   - If not running: `python $TK/scripts/zap_controller.py --start`
   - If ZAP not installed: the script suggests Docker (`docker run -d owasp/zap2docker-stable zap.sh -daemon`) or manual install. Skip ZAP scanning if unavailable — nuclei results are still valuable.

2. **Run ZAP full pipeline on scope**:
   ```bash
   python $TK/scripts/zap_controller.py --hunt hunt-<target>-$(date +%Y%m%d)/scope.json hunt-<target>-$(date +%Y%m%d)
   ```
   This automatically: reads scope.json → loads auth cookies (if available from Phase 5.5) → spiders all in-scope URLs → runs active scan → exports alerts → generates report.

3. **If auth cookies are available** (from Phase 5.5), ZAP loads them automatically from `hunt-<target>/auth/cookies.json`. For manual cookie loading:
   ```bash
   python $TK/scripts/zap_controller.py --set-cookies <domain> hunt-<target>/auth/cookies.json
   ```

4. **Review ZAP findings**: Read `hunt-<target>/zap/alerts.json` and `hunt-<target>/zap/report.html`

### Step 3: Triage Combined Results
Review findings from BOTH nuclei and ZAP:
- **Critical/High**: Investigate immediately, validate manually
- **Medium**: Investigate if time allows, check for chaining potential
- **Low/Info**: Note for later, check chain-building reference
- For each promising finding, run scope guard: `python $TK/scripts/scope_guard.py scope.json <target-url>`
- Update session phase

---

## Phase 5.5: Automatic Authentication (runs automatically)

**Goal:** Obtain authenticated sessions for deeper testing. This runs automatically.

**IMPORTANT LESSON LEARNED:** Playwright does NOT work for login on sites with Cloudflare/Arkose bot protection (they detect automated browsers and block OAuth flows). Chrome 130+ on Windows encrypts cookies so `browser_cookie3`/`rookiepy` often fail too. The most reliable fallback is: open user's real browser → user logs in → paste Cookie header from Network tab. This is ONE step and gets ALL cookies including HttpOnly session tokens.

1. **Run auto-authentication**:
   ```bash
   python $TK/scripts/auth_manager.py <primary-domain> hunt-<target>-$(date +%Y%m%d)
   ```
   This tries:
   - **Layer 1 — Browser cookies (zero effort)**: Extracts from Firefox/Chrome/Edge/Brave using `browser_cookie3`/`rookiepy`. Works on Firefox and older Chrome. May fail on Chrome 130+ Windows (app-bound encryption).
   - **Layer 3 — APK tokens**: Uses hardcoded tokens found during Phase 3.5 APK analysis.
   - **Layer 4 — CDP Browser Bridge**: When Cloudflare blocks all automated tools, launch a real browser with remote debugging and connect via CDP:
     ```bash
     # Launch Edge (Windows) or Chrome as separate debug instance
     msedge --remote-debugging-port=9222 --user-data-dir="$HUNT_DIR/edge-profile" "$TARGET_URL"
     ```
     User logs in manually, then Claude Code connects via Playwright CDP to make authenticated requests through the real browser, bypassing Cloudflare's TLS fingerprinting.

2. **If auto-auth succeeds** (`AUTH_SUCCESS=true`):
   - Cookies saved to `hunt-<target>/auth/cookies.json` + `hunt-<target>/auth/cookies.txt` (curl format)
   - Use `curl -b hunt-<target>/auth/cookies.txt` for all authenticated requests
   - Proceed directly to Phase 6

3. **If auto-auth fails** (most common on Windows with Chrome):
   The script will open the target in the user's default browser automatically. Then do this **ONE step**:
   - Tell the user: "I've opened `<domain>` in your browser. Please log in if not already. Then press F12 -> Network tab -> refresh (F5) -> click first request -> find the `Cookie:` line in Request Headers -> right-click Copy value -> paste it here."
   - **IMPORTANT: Do NOT use `document.cookie` from the Console tab** — it misses HttpOnly cookies (SSO/JWT tokens). Always use the Network tab Cookie header.
   - When user pastes the cookie string, save it immediately:
     ```bash
     python $TK/scripts/auth_manager.py --parse-header '<pasted-cookie-string>' hunt-<target>/auth <domain>
     ```
   - This creates `cookies.json`, `cookies.txt`, and `cookie-header-full.txt` in one shot
   - Use `curl -H "Cookie: $(cat hunt-<target>/auth/cookie-header-full.txt)"` for all subsequent requests

4. **SAML/SSO-protected targets** (common with SAP, enterprise apps):
   - Auto-auth almost always fails on SAML targets — browser_cookie3 can't extract HttpOnly SAML session cookies on modern Chrome
   - The SAML redirect page (HTTP 200 with auto-submitting POST form to IdP) is a reliable indicator
   - Key cookies to look for: `MYSAPSSO2` (SAP SSO token), `SAP_SESSIONID_*` (SAP session), `sap-usercontext` (client/language)
   - When user pastes cookies, verify auth works by checking if the OData `$metadata` or app `index.html` returns actual content instead of the SAML redirect page
   - SAML session cookies typically expire in 8-12 hours — note this for long testing sessions

5. **Even without authentication, continue to Phase 6** — unauthenticated testing still finds bugs. Note which tests need auth for later.

---

## Phase 6: Manual-Guided Testing

**Goal:** Test for vulnerabilities that scanners miss — business logic, auth flaws, IDOR, and complex injection. This is where the money is.

### Step 0: Use Authenticated Session (if available)
If Phase 5.5 obtained cookies, use them for ALL testing in this phase:
- For curl: `curl -b hunt-<target>/auth/cookies.txt <url>`
- For API testing: include the Cookie or Authorization header from auth results
- If APK tokens were found: use them as `Authorization: Bearer <token>` or appropriate header
- **Authenticated testing finds IDOR, privilege escalation, and business logic bugs — the highest-paying categories**

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
| Signed API auth (X-API-KEY) | `$TK/references/vuln-classes/api-security.md` | Replay attack, timestamp bypass, algorithm confusion, key storage |
| SAP/OData API | `$TK/references/methodology/sap-odata-testing-guide.md` | IDOR via entity keys, XSS in free-text fields, $filter injection, function import abuse, CSRF bypass |

### Step 3: Execute Testing
For each selected area:
1. Read the relevant vuln-class reference file for testing checklist and payloads
2. Also read the relevant payload file from `$TK/references/payloads/`
3. Test systematically following the checklist
4. Document each test attempt and result
5. If you find something, immediately validate and check for chain opportunities

### Step 3.5: GraphQL IDOR Testing (when GraphQL is present)

**IMPORTANT LESSONS LEARNED from real-world testing:**

**Cloudflare WAF Bypass:** Many GraphQL endpoints behind Cloudflare return empty responses unless `operationName` is passed as a URL query parameter. Always use:
```
POST https://api.target.com/graphql/?operationName=OperationName
```
instead of just `POST https://api.target.com/graphql/`

**Two-Account IDOR Testing Strategy:**
1. Create two test accounts (use email aliasing: `user@wearehackerone.com` and `user+test2@wearehackerone.com`)
2. Use `token_refresh.py` to manage short-lived tokens:
   ```bash
   python $TK/scripts/token_refresh.py setup target1 <refresh-endpoint> <refresh-token> --header "Authorization: Bearer {refresh_token}"
   ```
3. Run automated IDOR testing with the GraphQL IDOR tester:
   ```bash
   python $TK/scripts/graphql_idor_tester.py <endpoint> "$TOKEN1" "$TOKEN2" --auto-extract <decompiled-dir>
   ```
4. For manual testing: create data on Account 1 (addresses, orders, listings), then try accessing it from Account 2
5. Test BOTH read IDOR (can you view?) AND write IDOR (can you modify/delete?)

**APK Query Extraction:** When mobile apps use Apollo GraphQL, the decompiled APK contains the EXACT query strings with correct field names. Use `graphql_idor_tester.py --auto-extract` to find all queries with ID parameters automatically.

**Web vs Mobile GraphQL Endpoints:** Some targets serve GraphQL at different paths for web vs mobile:
- Web: `/services/graphql/` (cookie auth)
- Mobile: `/graphql/` (Bearer token auth)
- Seller API: `/seller-api/graphql/` (OAuth)
Always check for multiple GraphQL endpoints.

### Step 3.6: SAP OData IDOR & XSS Testing (when SAP/OData is present)

**IMPORTANT LESSONS LEARNED from real-world testing (KU Leuven engagement):**

**SAP Backend Key Override Pattern:** Many SAP custom Z-services override the requested entity key with the current authenticated user's ID server-side. For example, requesting `Applicants('ANOTHER_USER_ID')` still returns YOUR data. Test this by comparing the requested key with the response `__metadata.id` — if they differ, the backend is overriding the key (IDOR is blocked).

**OData IDOR Testing Strategy:**
1. Read `$metadata` to identify all entity types and their key fields
2. Get your own data first (use key `'0'` — SAP often maps this to current user)
3. Try adjacent/sequential IDs: if your ID is `IN00966041`, try `IN00966040`
4. Compare the response's `__metadata.id` with your request — if it always maps to your own ID, the backend enforces user-level isolation
5. Test BOTH read IDOR (GET entity) AND write IDOR (MERGE/PUT with another user's key)
6. Test navigation properties: `Applicants('OTHER_ID')/PersInfos` may have different auth than `PersInfos('OTHER_ID')`

**OData XSS via Write Operations:**
1. Use the OData analyzer output to identify writable text fields with no MaxLength constraint
2. Target `additionalRemarks`, notes, comments, description fields — these accept free text
3. Inject payloads via MERGE (partial update): `curl -X MERGE -H "x-csrf-token: $TOKEN" -d '{"additionalRemarks":"<img src=x onerror=alert(document.domain)>"}' "$ENDPOINT/Entity('0')"`
4. Verify storage by reading back: if the GET response contains raw HTML, XSS is stored
5. **"Stored but Frontend-Escaped" Pattern:** SAP UI5 `sap.m.TextArea` controls escape HTML on output. But the XSS IS still stored in the database and is reportable because:
   - Admin staff view applicant data via SAP GUI/WebDynpro which commonly renders HTML
   - Data exports (PDF, Excel) may include unsanitized HTML
   - Other API consumers trust and render the data
   - Check the UI5 views for `FormattedText` controls with `htmlText` binding — these render HTML directly
6. **Business validation workaround:** If entity updates fail with "data not complete", try simpler entities first (Language, Scholarship have fewer required fields than PersInfo/Address)

**CSRF Token Flow:**
```bash
# Fetch token
CSRF=$(curl -s -D - -H "x-csrf-token: fetch" "$ODATA_URL/" | grep -i "x-csrf-token" | awk '{print $2}' | tr -d '\r')
# Use in write operations
curl -X MERGE -H "x-csrf-token: $CSRF" -H "Content-Type: application/json" -d '...' "$ODATA_URL/Entity('0')"
```
Test without CSRF token to verify enforcement. Also test `X-HTTP-Method-Override` bypass.

### Step 4: Chain Building
Read `$TK/references/methodology/chain-building.md` for:
- Combining low-severity findings into high-impact reports
- Common chain patterns (open redirect + OAuth = ATO, etc.)
- When chaining is worth the effort

---

## Phase 7: Validation & PoC Creation

**Goal:** Validate findings, create reproducible PoCs, and check for duplicates.

### Gate 1: 7-Question Technical Gate — ALL must pass:

1. **Can a real attacker do this RIGHT NOW** against a real user who took no unusual actions?
2. **Does this cause concrete harm?** (data leak, money loss, account takeover, code execution)
3. **Is this likely NOT a duplicate?** Run: `python $TK/scripts/dedup_checker.py "<vuln_type>" "<target>" "<component>"`
4. **Is this in scope AND not in excluded vulnerability types?** Run: `python $TK/scripts/scope_guard.py scope.json <target>` AND `python $TK/scripts/scope_guard.py scope.json --check-vuln "<vuln_type>"`
5. **Is severity >= medium?** (or does it chain to >= medium?)
6. **Can you write clear reproduction steps** a triager can follow in under 5 minutes?
7. **Does the PoC prove IMPACT**, not just existence?

### Gate 2: Bounty Probability Gate — MUST pass before generating a report

**CRITICAL: The goal is MONEY without losing reputation. Generating reports that get closed as "Informative" or "N/A" hurts the user's signal-to-noise ratio on HackerOne/Bugcrowd, which reduces access to private programs and lowers future earnings. It is BETTER to submit 1 strong report than 8 weak ones.**

For each finding that passed Gate 1, honestly assess bounty probability:

**AUTO-REJECT — These almost always get closed as Informative (do NOT generate reports):**
- Missing security headers (CSP, HSTS, X-Frame-Options, etc.)
- Missing certificate pinning WITHOUT a custom Network Security Config that trusts user CAs (Android 9+ defaults already block user CAs)
- CORS misconfiguration where you cannot demonstrate actual cross-origin data theft with a working PoC
- Open redirect that is explicitly excluded or where impact is only phishing
- Clickjacking on non-sensitive pages
- Information disclosure of software versions only
- Rate limiting bypass (frequently excluded)
- Self-XSS (requires victim to paste payload into their own console)
- Theoretical attacks without demonstrated data access ("if the WebSocket authenticates via cookies..." — prove it or don't report it)
- Missing best practices / defense-in-depth improvements (these are NOT vulnerabilities)
- Internal infrastructure hostnames in headers/CSP without demonstrated access
- Raw API endpoints without WAF where auth still works correctly

**REQUIRE DEMONSTRATED PROOF for these (do NOT report on theory alone):**
- CSWSH: Must prove the WebSocket actually processes authenticated commands from evil origin, not just that the 101 handshake completes
- IDOR: Must show data from ANOTHER user's account, not just a 404/400 on a random UUID
- SSRF: Must show internal data retrieved, not just that a URL parameter exists
- Auth bypass: Must show access to protected resources, not just unusual response codes
- Business logic: Must show actual financial/data impact, not just unexpected behavior

**HIGH PROBABILITY — Generate reports for these:**
- Working IDOR with demonstrated data access from another user's account
- Account takeover with full PoC (OAuth redirect, session fixation, etc.)
- SQL injection with extracted data
- RCE with command output
- SSRF with internal data retrieved
- Hardcoded credentials/tokens that provide actual data access (proven with curl)
- Privilege escalation with demonstrated elevated access
- Stored XSS on high-traffic pages with cookie theft PoC
- **Stored XSS in API fields (even if frontend escapes):** If an API stores raw HTML/JS without sanitization and the data is viewed by admins/staff through backend interfaces (SAP GUI, admin dashboards, exports), this IS reportable as Stored XSS targeting admin users. The frontend escaping is a control, not a fix — the server-side vulnerability exists regardless. Frame the impact around admin-facing rendering and downstream data consumers.

**Rate each finding: SUBMIT / HOLD / DISCARD**
- **SUBMIT**: Clear reproduction, demonstrated impact, high bounty probability
- **HOLD**: Promising but needs more evidence (second account for IDOR, device testing, etc.). Save in findings/ but do NOT generate a report yet. Tell the user what additional testing would upgrade it to SUBMIT.
- **DISCARD**: Low probability of bounty, would hurt reputation. Move to findings/discarded/ with the reason.

### PoC Requirements (for SUBMIT findings only):
- Write exact curl commands that reproduce the issue and show data in the response
- Include the actual HTTP response proving the impact (not a theoretical description)
- Create step-by-step reproduction with exact URLs and parameters
- The PoC must be self-contained — a triager can copy-paste and see the bug in under 5 minutes
- Save to `hunt-<target>/findings/manual-findings/<finding-name>/`

### Duplicate Check (for SUBMIT findings only):
Use the search queries from dedup_checker.py with `WebSearch` to check:
- HackerOne hacktivity for the same program
- Public writeups mentioning the same vulnerability
- Known CVEs for the same component

---

## Phase 8: Report Generation

**Goal:** Create reports ONLY for findings rated SUBMIT in Phase 7 Gate 2. Quality over quantity — 1 strong report beats 8 weak ones.

### Step 0: Summary Table
Before generating any reports, display a summary of ALL findings with their Gate 2 rating:

```
| Finding | Severity | Gate 2 Rating | Reason |
|---------|----------|---------------|--------|
| ...     | ...      | SUBMIT/HOLD/DISCARD | ... |
```

**Only proceed to generate reports for SUBMIT findings.**
For HOLD findings, explain what additional testing would upgrade them.
For DISCARD findings, explain why they'd likely be closed as Informative.

### Step 1: Generate Individual Report Files
For EACH finding rated SUBMIT:

1. Read the platform guide: `$TK/references/platforms/<platform>.md`
2. Read the report template: `$TK/references/report-templates/<platform-abbrev>-template.md`
3. Write a complete `.md` report file to `hunt-<target>/reports/report-<letter>-<short-name>.md`

Each report file MUST contain these sections (mapped to HackerOne/Bugcrowd form fields):

```markdown
# HackerOne Report - Finding <Letter>

## Asset
`<asset>` (<asset type>)

## Weakness
CWE-<number>: <name>

## Severity
**<Rating>** (CVSS <score>)
Vector: `CVSS:3.1/AV:.../AC:.../PR:.../UI:.../S:.../C:.../I:.../A:...`

## Title
<Concise title under 80 chars>

## Description
<What the vulnerability is, where it exists, why it matters>

## Steps to Reproduce
1. <Step with exact URLs, parameters, payloads>
2. <Include curl commands that a triager can copy-paste>
3. <Show the vulnerable response>

## Impact
<Concrete business impact - what an attacker could do>

## Remediation (optional)
<Suggested fix>
```

### Step 2: Report Quality Rules
- **Title**: `[Vuln Type] in [Component] allows [Impact]` — clear, specific
- **CVSS**: Calculate with `python $TK/scripts/report_generator.py --cvss '<vector>'` — justify every metric choice
- **Steps to Reproduce**: Numbered, a triager must follow in <5 minutes. Include copy-pasteable curl commands.
- **Impact**: Concrete business impact, not theoretical risk
- **Tone**: Professional, human, concise — not robotic or verbose
- **Evidence**: curl commands with actual responses, HTTP logs

### Step 3: Show Submission Guide
After generating all reports, display a summary table:

```
| Form Field         | Report Section                               |
|--------------------|----------------------------------------------|
| Asset              | ## Asset value                                |
| Weakness           | CWE number from ## Weakness                  |
| Severity           | Use the CVSS vector string in the calculator |
| Title              | The ## Title line                             |
| Description        | Everything under ## Description               |
| Impact             | The ## Impact section                         |
| Steps to Reproduce | The numbered steps with curl commands         |
```

And recommend a **submission order** (strongest PoC first, dependencies noted).

### Step 4: Submit Reports

**The report .md files are ALWAYS saved regardless of whether API submission works.** They are the source of truth. The API is a convenience — if it fails, the .md files have everything needed for manual submission.

**For HackerOne programs with API token configured:**
1. Re-read each report from a triager's perspective
2. Verify all URLs/payloads still work
3. Confirm scope and excluded vuln types one final time
4. **DRY RUN first** (safe — nothing is submitted):
   ```bash
   python $TK/scripts/h1_api.py --submit hunt-<target>/reports/report-<letter>-<name>.md <program-handle>
   ```
5. Show the user the dry-run summary
6. **ASK the user for approval**
7. If approved, submit with `--confirm`:
   ```bash
   python $TK/scripts/h1_api.py --submit hunt-<target>/reports/report-<letter>-<name>.md <program-handle> --confirm
   ```
8. **If API succeeds**: Display report ID and URL
9. **If API fails (500, timeout, any error)**: Do NOT retry. Instead:
   - Tell the user: "API submission failed. The complete report is saved at `hunt-<target>/reports/report-<letter>-<name>.md`"
   - Open the HackerOne web form in their browser: `python $TK/scripts/auth_manager.py --open-browser "https://hackerone.com/<program>/reports/new?type=team&report_type=vulnerability"`
   - Show the form-field mapping table so they can copy-paste from the .md file

**For HackerOne programs WITHOUT API token, or any other platform:**
- The report .md files are already saved — that's the deliverable
- Open the platform's report form in the user's browser
- Show the mapping table for copy-paste

```
| Form Field         | Copy from .md section                        |
|--------------------|----------------------------------------------|
| Asset              | ## Asset value                                |
| Weakness           | CWE number from ## Weakness                  |
| Severity           | Use the CVSS vector string in the calculator |
| Title              | ## Title                                      |
| Description        | ## Description + ## Steps to Reproduce        |
| Impact             | ## Impact                                     |
```

### Step 5: Post-Submission Monitoring (HackerOne API only)
If API submission succeeded, check report status:
```bash
python $TK/scripts/h1_api.py --status <report-id>
```

---

## Phase 9: Audit Trail & Documentation (automatic)

**Goal:** Create comprehensive documentation of everything done during the hunt. This phase runs automatically after reports are generated — do NOT wait for the user to ask.

### Step 1: Create Full Audit Trail
Write `hunt-<target>/FULL-AUDIT-TRAIL.md` containing:

1. **Session Summary** — Target, platform, dates, scope
2. **Scope Analysis** — Complete scope.json contents, which assets were tested, which were skipped and why
3. **Methodology** — Which phases ran, which tools were used, configurations
4. **All Findings** — Both reported AND excluded findings
5. **Excluded Findings** — For each finding NOT reported: the specific program exclusion or 7-question gate failure that ruled it out
6. **Evidence Index** — Every file in the hunt directory with its purpose
7. **Potential Challenges** — Pre-written counter-arguments for likely triager pushback:
   - "This is informational" → counter with the working PoC and concrete impact
   - "This is out of scope" → cite the exact scope entry that includes it
   - "This is a duplicate" → show the dedup check results
   - "This has no impact" → demonstrate the data/access the vulnerability provides
8. **Recommendations** — What to test next, what was blocked (geo, time), what showed promise

### Step 2: Create Raw Session Log
Write `hunt-<target>/RAW-SESSION-LOG.md` containing:
- Chronological record of every action taken, every command run, every response received
- Every decision point and the reasoning behind it
- All tool outputs (summarized for large outputs, full for key evidence)
- Timestamps for each phase

### Step 3: Show Final Summary
Display a table of all generated files:
```
hunt-<target>/
├── FULL-AUDIT-TRAIL.md          ← Defense document
├── RAW-SESSION-LOG.md           ← Complete session log
├── reports/
│   ├── report-A-<name>.md       ← Submission-ready reports
│   ├── report-B-<name>.md
│   └── ...
├── findings/                    ← All finding evidence
├── recon/                       ← All recon data
└── scope.json                   ← Program scope
```

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
| `$TK/references/methodology/sap-odata-testing-guide.md` | SAP OData API testing, IDOR, XSS in MERGE/PUT, CSRF, $filter injection |

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
