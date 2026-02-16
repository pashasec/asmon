"""
targets.py — Multi-target configuration loader.

Reads a YAML file listing domains to monitor, with per-target option
overrides and global defaults.  Returns a flat list of TargetConfig
objects that the orchestrator iterates over.

    targets.yaml structure:
        defaults:           # optional global overrides
            shodan: false
            diff: true
        targets:
            - domain: example.com
              label: "Example Corp"
              shodan: true
              tags: [production]

No network I/O happens here — pure config parsing.
"""

import logging
from pathlib import Path
from pydantic import BaseModel, Field

logger = logging.getLogger("asmon.targets")

# pyyaml is the only new dep — stdlib has no YAML parser
try:
    import yaml  # type: ignore[import-untyped]
except ImportError:
    yaml = None  # type: ignore[assignment]


# ------------------------------------------------------------------
# Data model
# ------------------------------------------------------------------

class TargetConfig(BaseModel):
    """Resolved configuration for a single scan target."""
    domain: str
    label: str = ""
    tags: list[str] = Field(default_factory=list)

    # Scan options (mirrors CLI flags)
    shodan: bool = False
    active: bool = False
    web_risk: bool = False
    vuln_scan: bool = False
    diff: bool = True


_OPTION_KEYS = {"shodan", "active", "web_risk", "vuln_scan", "diff"}


# ------------------------------------------------------------------
# Loader
# ------------------------------------------------------------------

def load_targets(path: str | Path) -> list[TargetConfig]:
    """
    Parse a targets YAML file and return a list of TargetConfig.

    Raises:
        FileNotFoundError  – file doesn't exist
        ValueError         – parse or validation error
        ImportError         – pyyaml not installed
    """
    if yaml is None:
        raise ImportError(
            "pyyaml is required for multi-target mode. "
            "Install it with: pip install pyyaml"
        )

    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Targets file not found: {path}")

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ValueError(f"Invalid YAML in {path}: {exc}") from exc

    if not isinstance(raw, dict):
        raise ValueError(f"Expected a YAML mapping at top level in {path}")

    # --- Parse defaults ---
    defaults = raw.get("defaults", {}) or {}
    if not isinstance(defaults, dict):
        raise ValueError("'defaults' must be a mapping")

    # --- Parse targets list ---
    raw_targets = raw.get("targets", [])
    if not raw_targets:
        raise ValueError("No targets defined in config file")
    if not isinstance(raw_targets, list):
        raise ValueError("'targets' must be a list")

    configs: list[TargetConfig] = []
    for i, entry in enumerate(raw_targets):
        if isinstance(entry, str):
            # Shorthand: just a domain string
            entry = {"domain": entry}

        if not isinstance(entry, dict):
            raise ValueError(f"Target #{i+1}: expected a mapping, got {type(entry).__name__}")

        domain = entry.get("domain")
        if not domain:
            raise ValueError(f"Target #{i+1}: 'domain' is required")

        # Merge: defaults < per-target overrides
        merged: dict = {}
        merged["domain"] = domain
        merged["label"] = entry.get("label", domain)
        merged["tags"] = entry.get("tags", [])

        for key in _OPTION_KEYS:
            if key in entry:
                merged[key] = entry[key]
            elif key in defaults:
                merged[key] = defaults[key]

        configs.append(TargetConfig(**merged))

    logger.info("Loaded %d target(s) from %s", len(configs), path)
    return configs
