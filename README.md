# Attack Surface DIFF Engine

Passive attack surface discovery and change-detection for domains and organisations. Discovers exposed assets via certificate transparency and enriches them with Shodan. Stores snapshots locally and diffs them over time to surface what changed and why.

This is a personal research tool. It is not a replacement for enterprise EASM platforms.

---

## What it does

1. **Discovers** subdomains passively via certificate transparency (crt.sh). No packets touch the target network.
2. **Enriches** discovered IPs with Shodan — ports, services, banners, SSL certs, CVEs.
3. **Snapshots** the current state to disk as structured JSON.
4. **Diffs** the current snapshot against a previous one, detecting new assets, removed assets, and service changes.
5. **Summarises** changes with an optional AI layer (OpenAI or Anthropic). AI output is clearly separated from raw data and explicitly marked advisory.

---

## Architecture

```
asmon/                      ← Python package
│
├── __init__.py             ← Package initialization
├── asmon.py                ← CLI entry point, orchestration
├── config.py               ← env vars, paths, logging bootstrap
├── models.py               ← canonical Pydantic models (single source of truth)
├── discovery.py            ← passive subdomain discovery (crt.sh + DNS)
├── shodan.py               ← Shodan API client + response normalisation
├── diff.py                 ← snapshot comparison engine (pure, no I/O)
├── output.py               ← rendering: text (terminal) and JSON
├── analysis.py             ← optional LLM summarisation (OpenAI / Anthropic)
│
└── storage/
    ├── __init__.py
    └── snapshots.py        ← flat-file JSON persistence, atomic writes

tests/
└── test_diff.py            ← unit tests for the diff engine

data/
├── snapshots/              ← persisted snapshots (gitignored)
└── logs/                   ← asmon.log

requirements.txt            ← core dependencies
requirements-ai.txt         ← optional AI dependencies
```

### Data flow

```
User input (domain/URL)
        │
        ▼
┌─────────────────┐     ┌──────────────┐
│  PassiveDiscover │────▶│  ShodanClient │
│  (crt.sh + DNS)  │     │  (enrich IPs) │
└─────────────────┘     └──────┬───────┘
                                │  list[HostRecord]
                                ▼
                        ┌──────────────┐
                        │   Snapshot   │──▶ SnapshotStore (disk)
                        └──────┬───────┘
                               │
              ┌────────────────┼────────────────┐
              │ (if --diff)    │                 │
              ▼                ▼                 ▼
      load baseline      compute_diff      render output
                              │                 (text/json)
                              ▼
                    ┌──────────────────┐
                    │  AI Analysis     │  (if --ai-summary)
                    │  (advisory only) │
                    └──────────────────┘
```

---

## Setup

```bash
git clone https://github.com/pashasec/Attack-Surface-DIFF-Engine.git
cd Attack-Surface-DIFF-Engine

pip install -r requirements.txt

# If you want AI summaries:
pip install -r requirements-ai.txt
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

\* Required only if `--shodan` is used.
\** Required only if `--ai-summary` is used.

---

## Usage

### Basic passive scan with Shodan enrichment

```bash
export SHODAN_API_KEY="your_key_here"

python -m asmon.asmon --target tesla.com --shodan
```

### Scan and diff against previous snapshot

```bash
python -m asmon.asmon --target tesla.com --shodan --diff
```

### Diff with AI summary, JSON output

```bash
export ASMON_AI_API_KEY="your_openai_key"

python -m asmon.asmon --target tesla.com --shodan --diff --ai-summary --output json
```

### Use Anthropic instead of OpenAI

```bash
export ASMON_AI_PROVIDER=anthropic
export ASMON_AI_API_KEY="your_anthropic_key"
export ASMON_AI_MODEL=claude-haiku-3

python -m asmon.asmon --target tesla.com --shodan --diff --ai-summary
```

### List stored snapshots

```bash
python -m asmon.asmon --target tesla.com --list
```

### Diff against a specific baseline (not just the most recent)

```bash
python -m asmon.asmon --target tesla.com --shodan --diff --baseline abc12345
```

---

## CLI reference

| Flag               | Description                                                      |
|--------------------|------------------------------------------------------------------|
| `--target`         | Domain, URL, or organisation name (required)                     |
| `--mode`           | Scan mode. Only `passive` currently supported                    |
| `--shodan`         | Enable Shodan enrichment                                         |
| `--shodan-key`     | Shodan API key (overrides env var)                               |
| `--diff`           | Diff current scan vs previous snapshot                           |
| `--baseline ID`    | Specific snapshot ID to use as baseline                          |
| `--ai-summary`     | Append AI analysis (requires `--diff`)                           |
| `--ai-key`         | AI API key (overrides env var)                                   |
| `--ai-provider`    | `openai` or `anthropic`                                          |
| `--ai-model`       | Model identifier                                                 |
| `--output`         | `text` (default) or `json`                                       |
| `--list`           | Print stored snapshots for target and exit                       |
| `--log-level`      | Override log verbosity                                           |

---

## Exit codes

| Code | Meaning                                              |
|------|------------------------------------------------------|
| 0    | Success. No changes detected (or no diff requested) |
| 1    | Success. Changes were detected                       |
| 2    | User error (bad arguments, missing API key)          |
| 3    | Runtime error (API failure, I/O error)               |

Exit code 1 is intentional — it lets you integrate this into CI/CD or monitoring pipelines that trigger on non-zero exit when the attack surface changes.

---

## Running tests

```bash
python -m tests.test_diff
```

Tests are self-contained. No network calls, no API keys required.

---

## Design decisions

**Flat-file storage, not a database.** This is a single-user tool. JSON files are portable, debuggable, and require no infrastructure. If you need multi-user or high-volume storage, swap `SnapshotStore` for a database-backed implementation — the interface is small.

**Normalisation at the boundary.** Raw Shodan responses are never stored. Everything is normalised into `HostRecord` / `ServiceInfo` at the integration layer. This decouples the diff engine from Shodan's API version.

**AI is opt-in and isolated.** The `AIAnalysis` model is a separate envelope. It's never mixed with raw data in the output. The prompt is logged verbatim. If the AI call fails, the tool continues and reports the failure in the envelope.

**Atomic writes.** Snapshots are written to a `.tmp` file first, then atomically replaced. A crash mid-write won't corrupt your history.

**Exit code 1 on changes.** Unconventional but deliberate. Makes this tool composable in scripts and CI pipelines.

---

## Scope and limitations

- **Passive only.** No active scanning. No packets are sent to the target network. All data comes from third-party passive sources (crt.sh, Shodan's crawl index).
- **Single-target per run.** One `--target` per invocation. Loop externally if you monitor multiple targets.
- **No alerting.** This tool detects and reports. Alerting (email, Slack, PagerDuty) is out of scope — wire it up yourself using the JSON output and exit codes.
- **No deduplication across targets.** If the same IP appears under two different target scans, it's stored independently.

---

## Legal disclaimer

This tool is a **personal research and learning project**. It is built for experimentation and self-education in the area of attack surface monitoring.

It is **not** intended to compete with, replace, or replicate enterprise External Attack Surface Management (EASM) platforms. Production solutions in this space include (but are not limited to):

- Microsoft Defender EASM
- Rapid7 Attack Surface Management
- Palo Alto Cortex Xpanse
- Qualys External Attack Surface Management
- Censys Attack Surface Management

These platforms provide continuous monitoring, alerting, enterprise integrations, and scale that are far beyond the scope of this project.

**Use responsibly.** Only scan targets you own or have explicit written authorisation to test. Unauthorised scanning may violate laws and terms of service, regardless of how the scanning is performed.
