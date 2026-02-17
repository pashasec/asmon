# ASMON — Attack Surface Monitor

<img width="818" height="253" alt="Screenshot_2026-02-17_124832-removebg-preview" src="https://github.com/user-attachments/assets/a6e789d6-36fa-4f0b-b666-7e0daeefef2c" />



A security research tool for passive attack surface discovery and change-detection. Discovers exposed assets via certificate transparency logs (crt.sh), enriches them with Shodan, InternetDB, CISA KEV, and EPSS data, and diffs snapshots over time to surface new exposures and changes. Includes a web dashboard for browser-based scanning, multi-target scheduling, Slack alerting, and downloadable HTML reports.

**For educational and research purposes only.** This tool is designed for security professionals conducting authorized assessments on systems they own or have explicit written permission to test.

**Not a replacement for:** Enterprise EASM platforms (Rapid7, Palo Alto Xpanse, Microsoft Defender EASM, Qualys EASM), Shodan, or other commercial attack surface monitoring solutions.


<img width="1920" height="1044" alt="image" src="https://github.com/user-attachments/assets/fa9675d5-7d76-4be6-849d-ecb2e827b128" />


---

## What it does

1. **Discovers** subdomains passively via certificate transparency (crt.sh). No packets touch the target network.
2. **Enriches** discovered IPs with Shodan — ports, services, banners, SSL certs, CVEs.
3. **Analyzes web risk** passively — missing security headers, exposed endpoints, insecure cookies.
4. **Scans actively** (when authorized) — port discovery, service fingerprinting, CVE correlation.
5. **Tests for vulnerabilities** (when authorized) — SQL injection, XSS, RCE, path traversal, and more.
6. **Enriches** with InternetDB (free, no API key), CISA KEV, and EPSS exploitation probability scores.
7. **Checks DNS security** — SPF, DMARC, DNSSEC, CAA records.
8. **Scores risk** with a hybrid engine (CVE severity + service exposure + web signals, 0-100).
9. **Snapshots** the current state to disk as structured JSON.
10. **Diffs** the current snapshot against a previous one, detecting new assets, removed assets, and service changes.
11. **Summarises** changes with an optional AI layer (OpenAI or Anthropic). AI output is clearly separated from raw data and explicitly marked advisory.
12. **Web dashboard** — scan from the browser, view results, download HTML reports.
13. **Multi-target scheduling** — define targets in `targets.yaml`, run on cron intervals.
14. **Slack alerting** — severity-filtered notifications with deduplication.


<img width="1920" height="996" alt="image" src="https://github.com/user-attachments/assets/5e6f58ed-e2a3-42e3-96c6-a380006a0f7e" />

---

## Scan Types Explained

### Passive Discovery (`--target`)
- **What:** Uses certificate transparency logs (crt.sh) to discover subdomains and IPs.
- **Network impact:** None. All data comes from public, historical sources.
- **Authorization needed:** No.
- **Typical use:** Initial reconnaissance, attack surface baseline.

```bash
python -m asmon.asmon --target example.com
```

### Passive Web Risk Analysis (`--web-risk`)
- **What:** Makes HEAD/GET requests to discovered hosts to analyze HTTP headers, cookies, and common endpoints.
- **Network impact:** Minimal. No payloads, no fuzzing.
- **Authorization needed:** Recommended.
- **Detects:** Missing HSTS, CSP, insecure cookies, exposed debug endpoints, tech stack disclosure.

```bash
python -m asmon.asmon --target example.com --shodan --web-risk
```

### Active Port Scanning (`--active`)
- **What:** Performs TCP connect scanning on discovered IPs to find open ports and fingerprint services (banner grabbing).
- **Network impact:** Moderate. Sends SYN packets, connection attempts, reads banners.
- **Authorization needed:** **REQUIRED.** Only use on systems you own or have written authorization to scan.
- **Rate-limited:** Default 100 connections/sec (configurable with `--active-rate-limit`).
- **Relates to passive discovery:** Active scan only runs if passive discovery found at least one IP. If 0 IPs found, active scan is skipped.

```bash
python -m asmon.asmon --target example.com --active --active-ports top100
```

### Active Vulnerability Scanning (`--vuln-scan`)
- **What:** Tests for common web vulnerabilities (SQLi, XSS, RCE, path traversal, SSL/TLS weaknesses, etc.).
- **Network impact:** High. Sends payloads designed to detect weaknesses.
- **Authorization needed:** **REQUIRED.** Only use on systems you own or have explicit written authorization to test.
- **Parameter discovery:** Automatically crawls target to discover URLs with parameters using `--vuln-crawl`, or accepts specific URLs via `--vuln-url`.
- **Relates to passive discovery:** Uses discovered hosts to build scanning targets.

```bash
# Auto-discover parameters via crawling
python -m asmon.asmon --target example.com --vuln-scan --vuln-crawl

# Test specific URLs
python -m asmon.asmon --target example.com --vuln-scan \
  --vuln-url "http://example.com/search?q=test" \
  --vuln-url "http://example.com/api?id=1"
```

---

## Architecture

```
asmon/                           ← Python package
│
├── __init__.py                  ← Package initialization
├── asmon.py                     ← CLI entry point, orchestration
├── config.py                    ← env vars, paths, logging bootstrap
├── models.py                    ← canonical Pydantic models
├── discovery.py                 ← passive subdomain discovery (crt.sh + DNS)
├── shodan.py                    ← Shodan API client + response normalisation
├── diff.py                      ← snapshot comparison engine
├── output.py                    ← rendering: text (terminal) and JSON
├── analysis.py                  ← optional LLM summarisation
├── scoring.py                   ← risk scoring engine
├── internetdb.py                ← InternetDB enrichment (free, no key)
├── cisa_kev.py                  ← CISA Known Exploited Vulnerabilities
├── epss.py                      ← EPSS exploitation probability scores
├── dns_security.py              ← DNS security checks (SPF, DMARC, DNSSEC, CAA)
├── report.py                    ← HTML report generation
├── targets.py                   ← Multi-target YAML config loader
├── orchestrator.py              ← Automated scan pipeline orchestrator
├── scheduler.py                 ← Cron-based scheduling engine
│
├── alerters/                    ← Alert notifications
│   ├── slack.py                 ← Slack webhook integration
│   ├── filters.py               ← Severity-based alert filtering
│   ├── messages.py              ← Alert message formatting
│   └── state.py                 ← Deduplication state tracking
│
├── dashboard/                   ← Web dashboard (FastAPI)
│   ├── __main__.py              ← Standalone runner (python -m asmon.dashboard)
│   ├── app.py                   ← API endpoints and scan worker
│   └── static/                  ← Frontend (HTML/CSS/JS)
│       ├── index.html           ← Main dashboard page
│       └── detail.html          ← Scan detail page with scoring
│
├── active/                      ← Active port scanning
│   ├── scanner.py               ← Orchestrator
│   ├── ports.py                 ← TCP connect scanner
│   ├── services.py              ← Banner grabbing
│   └── cve.py                   ← CVE correlation
│
├── web/                         ← Web risk analysis
│   ├── analyzer.py              ← Orchestrator
│   └── signals.py               ← Risk signal detection
│
├── modules/                     ← Vulnerability testing modules
│   ├── base.py                  ← BaseModule, Finding
│   ├── http_utils.py            ← SecurityHTTPClient
│   ├── ssl_analysis.py          ← SSL/TLS weaknesses
│   ├── endpoint_discovery.py    ← Admin panels, backups
│   ├── subdomain_takeover.py    ← Dangling DNS
│   ├── sqli_detection.py        ← SQL injection
│   ├── xss_detection.py         ← Cross-site scripting
│   ├── lfi_detection.py         ← Path traversal / LFI
│   ├── rce_detection.py         ← Remote code execution
│   ├── oob_detection.py         ← Out-of-band (SSRF, XXE)
│   ├── crawler.py               ← Web crawling for parameter discovery
│   └── orchestrator.py          ← Module execution coordinator
│
└── storage/
    ├── __init__.py
    └── snapshots.py             ← flat-file JSON persistence

data/
├── snapshots/                   ← persisted snapshots (gitignored)
└── logs/                        ← asmon.log

targets.yaml                     ← multi-target config (user-created)
targets.yaml.example             ← example config template
requirements.txt                 ← core dependencies
```

### Data flow

```
User input (domain or targets.yaml)
        │
        ▼
┌──────────────────────┐
│  PassiveDiscovery    │  (crt.sh + DNS)
│  → list of IPs       │
└──────────┬───────────┘
           │
           ├─→ (if 0 IPs: stop here)
           │
           ├─→ InternetDB ────→ ports, CVEs, hostnames (free, no key)
           ├─→ CISA KEV ──────→ known exploited vulnerability flags
           ├─→ EPSS ──────────→ exploitation probability scores
           ├─→ DNS Security ──→ SPF, DMARC, DNSSEC, CAA checks
           │
           ├─→ (if --shodan) ──→ ShodanClient → services, banners, CVEs
           ├─→ (if --web-risk) → WebAnalyzer  → headers, cookies, signals
           ├─→ (if --active) ──→ ActiveScanner → ports, fingerprints
           └─→ (if --vuln-scan) → ModuleOrch.  → SQLi, XSS, RCE, etc.
                                        │
                                 ┌──────▼────────┐
                                 │  Risk Scoring  │ (0-100)
                                 └──────┬────────┘
                                        │
                                 ┌──────▼────────┐
                                 │   Snapshot    │──→ SnapshotStore (disk)
                                 └──────┬────────┘
                                        │
                       ┌────────────────┼──────────────────┐
                       │ (if --diff)    │                   │
                       ▼                ▼                   ▼
                   load baseline   compute_diff      render output
                                       │              (text/json/html)
                                       ▼
                             ┌──────────────────┐
                             │  AI Analysis     │  (if --ai-summary)
                             │  (advisory only) │
                             └────────┬─────────┘
                                      │
                       ┌──────────────┼──────────────┐
                       ▼              ▼              ▼
                  Slack Alert    HTML Report    Web Dashboard
                (--slack-webhook) (--report)   (--dashboard)
```

---

## Setup

```bash
git clone https://github.com/pashasec/asmon.git
cd asmon

pip install -r requirements.txt

# Optional: Install AI summary dependencies
pip install -r requirements-ai.txt

# Create venv
python3 -m venv venv

source venv/bin/activate 

# Install deps
pip install requests shodan pydantic

# Run
python -m asmon.asmon --help
```

---

## Configuration

All configuration is via environment variables. CLI flags override where noted.

| Variable              | Required | Default            | Description                          |
|-----------------------|----------|--------------------|--------------------------------------|
| `SHODAN_API_KEY`      | Yes*     | —                  | Shodan API key (`--shodan-key` alt)  |
| `ASMON_AI_PROVIDER`   | No       | `openai`           | `openai` or `anthropic`              |
| `ASMON_AI_API_KEY`    | Yes**    | —                  | API key for the AI provider          |
| `ASMON_AI_MODEL`      | No       | `gpt-4o-mini`      | Model name                           |
| `ASMON_DATA_DIR`      | No       | `./data`           | Where snapshots and logs are stored  |
| `ASMON_LOG_LEVEL`     | No       | `INFO`             | `DEBUG`, `INFO`, `WARNING`, `ERROR`  |
| `ASMON_SLACK_WEBHOOK` | No       | —                  | Slack webhook URL for alerting       |

\* Required only if `--shodan` is used.
\** Required only if `--ai-summary` is used.

---

## Usage

### 1. Baseline passive scan with enrichment

```bash
export SHODAN_API_KEY="your_key_here"

python -m asmon.asmon --target example.com --shodan
```

### 2. Scan with web risk analysis

```bash
python -m asmon.asmon --target example.com --shodan --web-risk
```

### 3. Diff and detect changes

```bash
python -m asmon.asmon --target example.com --shodan --diff
```

Output will be exit code 0 (no changes) or 1 (changes detected). Integrates well with monitoring pipelines.

### 4. Diff with AI summary

```bash
export ASMON_AI_API_KEY="your_openai_key"

python -m asmon.asmon --target example.com --shodan --diff --ai-summary
```

### 5. Active port scanning (requires authorization)

```bash
# Scan top 100 common ports
python -m asmon.asmon --target example.com --active --active-ports top100

# Scan with CVE correlation
python -m asmon.asmon --target example.com --active --active-cve-check

# Custom port range
python -m asmon.asmon --target example.com --active --active-ports 1-1024

# Specific ports
python -m asmon.asmon --target example.com --active --active-ports 22,80,443,3306
```

### 6. Vulnerability scanning (requires authorization)

```bash
# Auto-discover parameters and test
python -m asmon.asmon --target example.com --vuln-scan --vuln-crawl

# Test specific URLs
python -m asmon.asmon --target example.com --vuln-scan \
  --vuln-url "http://example.com/search?q=test" \
  --vuln-url "http://example.com/product?id=1"

# Run specific modules only
python -m asmon.asmon --target example.com --vuln-scan \
  --vuln-modules ssl_analysis,sqli_detection,xss_detection

# With manual confirmation (automation-friendly)
python -m asmon.asmon --target example.com --vuln-scan --vuln-crawl --vuln-skip-warning
```

### 7. Full security assessment

```bash
export SHODAN_API_KEY="your_key_here"
export ASMON_AI_API_KEY="your_openai_key"

python -m asmon.asmon --target example.com \
  --shodan \
  --web-risk \
  --active --active-cve-check \
  --vuln-scan --vuln-crawl \
  --diff \
  --ai-summary
```

### 8. JSON output for integration

```bash
python -m asmon.asmon --target example.com --shodan --diff --output json > report.json
```

### 9. List stored snapshots

```bash
python -m asmon.asmon --target example.com --list
```

### 10. Diff against a specific baseline

```bash
python -m asmon.asmon --target example.com --shodan --diff --baseline abc12345
```

### 11. Clean up snapshots after run

```bash
# Snapshot is created, output is printed, then snapshot is deleted
python -m asmon.asmon --target example.com --shodan --clean
```

### 12. Web dashboard

```bash
# Start the web dashboard (default: http://localhost:8000)
python -m asmon.asmon --dashboard

# Custom host and port
python -m asmon.asmon --dashboard --dashboard-host 0.0.0.0 --dashboard-port 9000

# Or run standalone
python -m asmon.dashboard
```

Open `http://localhost:8000` in a browser to scan targets, view results with risk scoring, and download HTML reports.

### 13. Multi-target scheduling

Define targets in `targets.yaml`:

```yaml
targets:
  - domain: example.com
    schedule: "*/30 * * * *"    # every 30 minutes
    mode: passive
  - domain: myapp.io
    schedule: "0 */6 * * *"    # every 6 hours
    mode: passive
```

```bash
# Run the scheduler
python -m asmon.asmon --scheduler

# Or run the orchestrator for a single pass
python -m asmon.asmon --orchestrate
```

### 14. Slack alerting

```bash
# Via environment variable
export ASMON_SLACK_WEBHOOK="https://hooks.slack.com/services/..."
python -m asmon.asmon --target example.com --shodan --diff

# Or pass directly
python -m asmon.asmon --target example.com --shodan --diff \
  --slack-webhook "https://hooks.slack.com/services/..."
```

### 15. Scheduled scanning

```bash
# Re-run scan every 6 hours
python -m asmon.asmon --target example.com --shodan --diff --schedule 360

# With Slack alerts, stop after 10 cycles
python -m asmon.asmon --target example.com --shodan --diff \
  --slack-webhook "https://hooks.slack.com/services/..." \
  --schedule 360 --max-cycles 10
```

### 16. Snapshot retention

```bash
# Keep only the 10 most recent snapshots per target
python -m asmon.asmon --target example.com --shodan --retain 10

# Delete snapshots older than 30 days
python -m asmon.asmon --target example.com --shodan --retain-days 30

# View storage usage
python -m asmon.asmon --storage-info
```

### 17. HTML report generation

```bash
# Generate a downloadable HTML report
python -m asmon.asmon --target example.com --report html
```

Reports include risk scoring breakdown, CVE tables, service exposure, DNS security status, and step-by-step remediation instructions.

---

## CLI Reference

### Core flags

| Flag               | Description                                                      |
|--------------------|------------------------------------------------------------------|
| `--target`         | Domain, URL, or organisation name (required)                     |
| `--mode`           | Scan mode. Only `passive` currently supported                    |
| `--output`         | `text` (default) or `json`                                       |
| `--list`           | Print stored snapshots for target and exit                       |
| `--log-level`      | Override log verbosity                                           |
| `--clean`          | Delete snapshot created during this run (after output printed)   |

### Enrichment

| Flag               | Description                                                      |
|--------------------|------------------------------------------------------------------|
| `--shodan`         | Enable Shodan enrichment (requires API key)                      |
| `--shodan-key`     | Shodan API key (overrides `SHODAN_API_KEY` env var)              |

### Web Risk Analysis (passive)

| Flag                      | Description                                                      |
|---------------------------|------------------------------------------------------------------|
| `--web-risk`              | Analyze HTTP headers, cookies, endpoints for risk signals        |
| `--web-risk-timeout`      | HTTP request timeout in seconds (default: 10)                    |
| `--web-risk-no-endpoints` | Skip checking for exposed sensitive endpoints                     |

### Active Port Scanning (requires authorization)

| Flag                  | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `--active`            | Enable port scanning and service fingerprinting                  |
| `--active-ports`      | Port specification: `top100` (default), `1-65535`, or `22,80,443`|
| `--active-rate-limit` | Max connections per second (default: 100)                        |
| `--active-timeout`    | Connection timeout in seconds (default: 3)                       |
| `--active-cve-check`  | Correlate detected services with CVE database (metadata only)    |

### Vulnerability Scanning (requires authorization)

| Flag                   | Description                                                      |
|------------------------|------------------------------------------------------------------|
| `--vuln-scan`          | Enable vulnerability testing modules                             |
| `--vuln-url`           | Specific URL with parameters to test (repeatable)                |
| `--vuln-crawl`         | Auto-crawl target to discover URLs with injectable parameters    |
| `--vuln-crawl-depth`   | Max crawl depth (default: 3)                                      |
| `--vuln-crawl-pages`   | Max pages to crawl (default: 50)                                  |
| `--vuln-modules`       | Comma-separated module list. Options: `ssl_analysis`, `endpoint_discovery`, `subdomain_takeover`, `sqli_detection`, `xss_detection`, `lfi_detection`, `rce_detection`, `oob_detection` |
| `--vuln-rate-limit`    | Max requests per second (default: 10)                            |
| `--vuln-timeout`       | Request timeout in seconds (default: 10)                         |
| `--vuln-skip-warning`  | Skip authorization confirmation prompt (for automation)          |
| `--callback-url`       | OOB callback server URL for blind vulnerability detection        |

### Slack Alerting

| Flag                  | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `--slack-webhook`     | Slack incoming webhook URL. Requires `--diff`. Env: `ASMON_SLACK_WEBHOOK` |

### Scheduling

| Flag                  | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `--schedule MINUTES`  | Re-run the scan every N minutes (e.g. `360` for every 6 hours)  |
| `--max-cycles N`      | Stop after N cycles (default: `0` = unlimited)                   |

### Snapshot Retention

| Flag                  | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `--retain N`          | Keep only the N most recent snapshots per target (0 = unlimited) |
| `--retain-days DAYS`  | Delete snapshots older than N days (most recent always kept)     |
| `--storage-info`      | Show snapshot storage usage and exit                             |

### Dashboard

| Flag                  | Description                                                      |
|-----------------------|------------------------------------------------------------------|
| `--dashboard`         | Start the web dashboard                                          |
| `--dashboard-host`    | Bind address (default: `0.0.0.0`)                                |
| `--dashboard-port`    | Port number (default: `8000`)                                    |

### Diff and Analysis

| Flag               | Description                                                      |
|--------------------|------------------------------------------------------------------|
| `--diff`           | Compare current scan vs previous snapshot                        |
| `--baseline ID`    | Use specific snapshot ID as baseline (default: most recent)      |
| `--ai-summary`     | Generate AI-assisted summary of changes (requires `--diff`)      |
| `--ai-key`         | AI provider API key (overrides env var)                          |
| `--ai-provider`    | `openai` or `anthropic` (default: `openai`)                      |
| `--ai-model`       | Model identifier (e.g. `gpt-4o-mini`, `haiku-3`)                 |

---

## Exit Codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | Success. No changes detected (or no diff requested) |
| 1    | Success. Changes were detected (exit code 1)        |
| 2    | User error (bad arguments, missing API key)         |
| 3    | Runtime error (API failure, I/O error)              |

Exit code 1 on changes is intentional — it lets you integrate this into CI/CD or monitoring pipelines that trigger on non-zero exit.

---

## Common Pitfalls

### "Passive discovery found 0 IPs"

**Problem:** Running `--target example.com` returns no results.

**Causes:**
- The domain has very few subdomains (legitimate for small sites)
- Certificate transparency logs haven't indexed recent certs
- The domain is new or rarely issued new certificates
- DNS resolution failed

**Solution:**
- Use `--shodan` to query Shodan's IP index directly (requires API key)
- Check if your domain actually has external assets
- Use `--list` to see previous snapshots for comparison

### "Active scan didn't run even though --active was specified"

**Problem:** Passive discovery found 0 IPs, so active scan was skipped.

**Cause:** Active scanning depends on at least one IP discovered by passive discovery. If passive discovery fails, active scan has nothing to scan.

**Solution:** Ensure passive discovery is working. Run without `--active` first to see discovery results.

### "Vulnerability scan found 0 issues"

**Problem:** Ran `--vuln-scan` but no findings reported.

**Causes:**
- No URLs with injectable parameters were discovered or provided
- `--vuln-crawl` failed (network issues, wrong target)
- Target doesn't have vulnerable parameters
- Payloads were filtered/blocked

**Solution:**
- Use `--vuln-url` to manually specify URLs with query parameters
- Use `--vuln-crawl` to auto-discover injectable targets
- Check logs with `--log-level DEBUG` to see what was tested

### "AI summary failed: API quota exceeded"

**Problem:** Ran with `--ai-summary` and got an error.

**Causes:**
- OpenAI/Anthropic API key is invalid or revoked
- Monthly token quota is exhausted
- Network connectivity issue

**Solution:**
- Verify API key is set correctly: `echo $ASMON_AI_API_KEY`
- Check quota on your provider's dashboard
- Try without `--ai-summary` to verify other parts work
- Use `--log-level DEBUG` to see the actual API error

### "Snapshot cleanup (--clean) didn't delete the file"

**Problem:** Used `--clean` but snapshot file still exists.

**Cause:** `--clean` only deletes the snapshot created during that specific run, not older snapshots.

**Solution:** To delete all snapshots for a target, manually delete files in `asmon/data/snapshots/` matching the target name.

---

## Design Decisions

**Flat-file storage, not a database.** This is a single-user tool. JSON files are portable, debuggable, and require no infrastructure. If you need multi-user or high-volume storage, swap `SnapshotStore` for a database-backed implementation — the interface is small.

**Normalisation at the boundary.** Raw Shodan responses are never stored. Everything is normalised into `HostRecord` / `ServiceInfo` at the integration layer. This decouples the diff engine from Shodan's API version.

**Passive discovery first.** Active scanning and vulnerability testing depend on targets discovered during passive discovery. This ensures you're only scanning assets your organization actually uses.

**Authorization gates on active scans.** Flags like `--active` and `--vuln-scan` trigger explicit warnings. Modules require written authorization confirmation before proceeding.

**AI is opt-in and isolated.** The `AIAnalysis` model is a separate envelope. It's never mixed with raw data in the output. The prompt is logged verbatim. If the AI call fails, the tool continues and reports the failure in the envelope.

**Atomic writes.** Snapshots are written to a `.tmp` file first, then atomically replaced. A crash mid-write won't corrupt your history.

**Exit code 1 on changes.** Unconventional but deliberate. Makes this tool composable in scripts and CI pipelines.

---

## Scope and Limitations

- **Passive discovery is incomplete.** Certificate transparency logs may miss assets. Use `--shodan` for broader coverage.
- **Shodan data may be outdated.** Shodan's crawl index is not real-time. Recent changes won't be reflected immediately.
- **Active scanning has rate limits.** Default 100 conn/sec. Reduce with `--active-rate-limit` if target rate-limits you.
- **Vulnerability detection is heuristic.** Payloads are matched against response content. Obfuscation or WAF rules may cause false negatives.
- **Multi-target support.** Define multiple targets in `targets.yaml` with individual schedules.
- **Slack alerting.** Severity-filtered alerts with deduplication. Additional integrations (email, PagerDuty) can be added.
- **No deduplication across targets.** If the same IP appears under two targets, it's stored independently.

---

## Legal Disclaimer

**This tool is for educational and research purposes only.** It is designed for:
- Security professionals conducting authorized assessments
- Defenders monitoring their own infrastructure
- Researchers studying attack surface methodologies
- Educational purposes in controlled environments

**This tool is not:**
- A replacement for commercial attack surface management platforms (Rapid7, Palo Alto Xpanse, Microsoft Defender EASM, Qualys EASM, Censys, etc.)
- Intended for unauthorized network reconnaissance
- Suitable for non-consensual security testing
- A production-grade monitoring solution

**Responsibility and Legal Compliance:**

You are solely responsible for ensuring your use of this tool complies with applicable laws and regulations. Unauthorized network scanning, access attempts, or data collection may violate:
- Computer Fraud and Abuse Act (CFAA) — United States
- Computer Misuse Act — United Kingdom
- GDPR and ePrivacy Directive — European Union
- Similar laws in other jurisdictions

**Only scan systems you own or have explicit, written authorization to test.** Always obtain proper authorization before conducting any security assessment, even passive reconnaissance. Unauthorized scanning, port enumeration, or vulnerability testing is illegal and unethical.

---

## Running Tests

```bash
python -m pytest tests/
```

Tests are self-contained. No network calls, no API keys required.

---

## Contributing

This is a personal research project. Contributions and forks are welcome.

