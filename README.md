# Bounty Hunter Skill

AI agent skill for automated bug bounty hunting. Parses HackerOne/Bugcrowd/Intigriti/Immunefi program scope, runs full reconnaissance (subdomain enumeration, HTTP probing, tech fingerprinting, content discovery), scans for 20+ vulnerability classes with tech-aware nuclei templates, guides manual testing for business logic and auth flaws, validates findings with PoC generation, and produces platform-specific submission-ready reports with CVSS scoring.

## Installation

### Claude Code

**Git Bash / macOS / Linux:**
```bash
mkdir -p ~/.claude/skills/bounty-hunter && curl -sL https://raw.githubusercontent.com/Hero988/bounty-hunter/master/bounty-hunter/SKILL.md -o ~/.claude/skills/bounty-hunter/SKILL.md
```

**PowerShell (Windows):**
```powershell
New-Item -ItemType Directory -Force -Path "$HOME/.claude/skills/bounty-hunter" | Out-Null; Invoke-WebRequest -Uri "https://raw.githubusercontent.com/Hero988/bounty-hunter/master/bounty-hunter/SKILL.md" -OutFile "$HOME/.claude/skills/bounty-hunter/SKILL.md"
```

The skill auto-loads in every Claude Code session. Verify with: "What skills are available?"

### Other Agents (Cursor, Codex, Gemini CLI, Copilot, etc.)

```bash
npx skills add Hero988/bounty-hunter
```

Works with 40+ agents via [skills.sh](https://skills.sh).

## Usage

Invoke the skill by asking the agent:

> /bounty-hunter https://hackerone.com/company

```
/bounty-hunter https://hackerone.com/company         # Full 8-phase hunt on a HackerOne program
/bounty-hunter https://bugcrowd.com/tesla            # Full hunt on a Bugcrowd program
/bounty-hunter example.com                           # Hunt a raw domain
/bounty-hunter --phase recon https://hackerone.com/x  # Run only reconnaissance (Phases 1-4)
/bounty-hunter --phase scan                          # Run only vulnerability scanning (Phase 5)
/bounty-hunter --phase report                        # Generate reports from existing findings
/bounty-hunter --resume                              # Resume the most recent hunting session
/bounty-hunter setup                                 # Install all required security tools
/bounty-hunter health                                # Check tool status and template freshness
/bounty-hunter update                                # Update tools, nuclei templates, and wordlists
```

On first run, the skill will:
1. Clone the [companion toolkit](https://github.com/Hero988/bounty-hunter-toolkit) to `~/.bounty-hunter-toolkit/`
2. Check that required security tools are installed (nuclei, subfinder, httpx, ffuf, katana, nmap)
3. Offer to install any missing tools and download wordlists

## What It Does

**8-Phase Pipeline:**

1. **Scope Parsing** — Auto-parse program scope from HackerOne/Bugcrowd/Intigriti/Immunefi URL, build structured `scope.json`
2. **Passive Recon** — Subdomain enumeration (subfinder, assetfinder, crt.sh), historical URLs (gau, waybackurls), OSINT via WebSearch
3. **Active Recon** — HTTP probing with tech fingerprinting (httpx), port scanning (nmap), CMS identification
4. **Content Discovery** — Directory fuzzing (ffuf), deep crawling with JS analysis (katana), parameter mining
5. **Vulnerability Scanning** — Tech-aware nuclei scanning in layers (exposures → CVEs → vulnerabilities → custom), 80% noise reduction by matching templates to detected stack
6. **Manual-Guided Testing** — AI reads the target via WebFetch, understands business logic, creates attack map, tests for IDOR/auth/business logic/prompt injection using curated reference files
7. **Validation & PoC** — 7-question gate before any report, duplicate checking via hacktivity search, reproducible PoC creation with curl commands
8. **Report Generation** — Platform-specific reports with CVSS 3.1 scoring, human-tone writing, evidence-backed impact statements

## Supported Platforms

Ships with scope parsers, report templates, and platform guides for:
- **HackerOne** — CVSS 3.1 severity, hacktivity dedup checking
- **Bugcrowd** — VRT taxonomy, P1-P5 priority mapping
- **Intigriti** — European platform specifics, GDPR-aware reporting
- **Immunefi** — Web3/DeFi smart contract bounties, higher reward ranges

## Safety

- **Deterministic scope enforcement** — code-based (not LLM-based) scope guard with anchored wildcard matching, CIDR support, deny-list checked before allow-list
- **Rate limiting** on all network operations (default 50 req/s)
- **User confirmation** required before active exploitation or report submission
- **Audit logging** of all network requests
- **Circuit breaker** — auto-pause on repeated 429/503 responses

## Requirements

- Python 3.10+
- Go 1.21+ (for tool installation)
- Git

**Core tools** (auto-installed via `setup`): nuclei, subfinder, httpx, ffuf, katana, nmap

**Extended tools** (optional): dalfox, gau, waybackurls, assetfinder, subjack, dnsx, naabu, interactsh-client

## Companion Toolkit

The skill uses a companion repo for scripts, references, payloads, and templates:

- **Repo:** [Hero988/bounty-hunter-toolkit](https://github.com/Hero988/bounty-hunter-toolkit)
- Auto-cloned on first invocation to `~/.bounty-hunter-toolkit/`
- Updates via `git pull` — push changes to the toolkit repo and all users get them automatically

**What's inside:**
```
scripts/          12 Python/Bash automation scripts
references/       21 reference files covering 20+ vulnerability classes
  vuln-classes/   8 files — testing checklists, payloads, bypass techniques
  methodology/    4 files — recon playbook, manual testing, chain building
  platforms/      4 files — HackerOne, Bugcrowd, Intigriti, Immunefi guides
  report-templates/ 4 files — platform-specific report templates
  payloads/       5 files — curated payloads (XSS, SQLi, SSRF, SSTI, prompt injection)
```

## License

Apache-2.0
