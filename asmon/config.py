"""
config.py — Central configuration and environment resolution.

Reads from environment variables first, then CLI overrides later via argparse.
All paths are relative to the project root unless ASMON_DATA_DIR is set.
"""

import os
import logging
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("ASMON_DATA_DIR", PROJECT_ROOT / "data"))
SNAPSHOT_DIR = DATA_DIR / "snapshots"
LOG_DIR = DATA_DIR / "logs"

# Ensure directories exist on import
for _d in (DATA_DIR, SNAPSHOT_DIR, LOG_DIR):
    _d.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# API Keys (env-only at this layer; CLI flag overwrites later)
# ---------------------------------------------------------------------------
SHODAN_API_KEY: str | None = os.environ.get("SHODAN_API_KEY")

# ---------------------------------------------------------------------------
# AI / LLM (optional module)
# Supports: openai (GPT-4o-mini default), anthropic (haiku-3)
# ---------------------------------------------------------------------------
AI_PROVIDER: str = os.environ.get("ASMON_AI_PROVIDER", "openai")
AI_API_KEY: str | None = os.environ.get("ASMON_AI_API_KEY")
AI_MODEL: str = os.environ.get("ASMON_AI_MODEL", "gpt-4o-mini")

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
LOG_LEVEL: str = os.environ.get("ASMON_LOG_LEVEL", "INFO").upper()


def setup_logging(level: str | None = None) -> logging.Logger:
    """Configure root logger. Call once at CLI entry point."""
    effective = (level or LOG_LEVEL).upper()
    log_file = LOG_DIR / "asmon.log"

    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    handlers: list[logging.Handler] = [
        logging.StreamHandler(),
        logging.FileHandler(log_file, encoding="utf-8"),
    ]

    logging.basicConfig(level=getattr(logging, effective, logging.INFO),
                        format=fmt, handlers=handlers, force=True)

    return logging.getLogger("asmon")
