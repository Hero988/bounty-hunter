# Bounty Hunter

A Claude Code skill for automated bug bounty hunting. From program URL to submission-ready report.

## Install

```bash
npx skills add Hero988/bounty-hunter
```

## Usage

```
/bounty-hunter https://hackerone.com/company
/bounty-hunter example.com
/bounty-hunter --phase recon https://hackerone.com/company
/bounty-hunter --resume
/bounty-hunter setup
/bounty-hunter health
/bounty-hunter update
```

## What It Does

**8-Phase Pipeline:**

1. **Scope Parsing** — Auto-parse HackerOne/Bugcrowd/Intigriti/Immunefi program scope
2. **Passive Recon** — Subdomain enum, cert transparency, historical URLs, OSINT
3. **Active Recon** — HTTP probing, port scanning, tech fingerprinting
4. **Content Discovery** — Directory fuzzing, JS analysis, parameter mining
5. **Vulnerability Scanning** — Tech-aware nuclei scanning (80% noise reduction)
6. **Manual-Guided Testing** — Business logic, auth, IDOR with AI-powered analysis
7. **Validation & PoC** — 7-question gate, duplicate checking, PoC creation
8. **Report Generation** — Platform-specific reports with CVSS scoring

## Requirements

- [Claude Code](https://claude.ai/code)
- Go 1.21+ (for tool installation)
- Python 3.10+
- Git

Core tools (auto-installed): nuclei, subfinder, httpx, ffuf, katana, nmap

## Architecture

This skill auto-clones the [bounty-hunter-toolkit](https://github.com/Hero988/bounty-hunter-toolkit) on first run, which contains all scripts, references, and payloads. The toolkit updates independently via `git pull`.

## Safety

- Deterministic scope enforcement (code-based, not LLM-based)
- Deny-list checked before allow-list
- Rate limiting on all network operations
- User confirmation required before active exploitation
- Audit logging of all network requests

## License

Apache-2.0
