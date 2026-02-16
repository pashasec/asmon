"""
state.py — Alert deduplication via file-based persistence.

Tracks which alerts have already been sent so we don't spam Slack
with the same finding on every run.

Storage: single JSON file at asmon/data/alert_state.json
Cleanup: entries older than 7 days are pruned automatically.
"""

import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime, timezone, timedelta

logger = logging.getLogger("asmon.alerters.state")

# Default location alongside snapshots
_DEFAULT_STATE_FILE = Path(__file__).resolve().parent.parent / "data" / "alert_state.json"


class AlertState:
    """
    File-backed deduplication for sent alerts.

    Each alert is keyed by a deterministic hash of (target, ip, alert_type, detail).
    If an identical key exists and was sent within `suppress_hours`, the alert is
    suppressed. After `suppress_hours` the same finding can fire again (useful for
    recurring/persistent exposures that should be re-flagged periodically).
    """

    def __init__(self, state_file: Path | str | None = None, suppress_hours: int = 24):
        self._path = Path(state_file) if state_file else _DEFAULT_STATE_FILE
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._suppress = timedelta(hours=suppress_hours)
        self._entries: dict[str, dict] = self._load()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def _load(self) -> dict[str, dict]:
        if not self._path.exists():
            return {}
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except Exception as exc:
            logger.warning("Corrupt alert state file, starting fresh: %s", exc)
        return {}

    def _save(self) -> None:
        try:
            tmp = self._path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self._entries, indent=2, default=str), encoding="utf-8")
            tmp.replace(self._path)
        except Exception as exc:
            logger.error("Failed to persist alert state: %s", exc)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def _make_key(target: str, ip: str, alert_type: str, detail: str) -> str:
        """Deterministic, short key from the alert identity."""
        raw = f"{target}|{ip}|{alert_type}|{detail}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def was_sent(self, target: str, ip: str, alert_type: str, detail: str) -> bool:
        """Return True if this exact alert was already sent within the suppression window."""
        key = self._make_key(target, ip, alert_type, detail)
        entry = self._entries.get(key)
        if entry is None:
            return False

        sent_at = datetime.fromisoformat(entry["sent_at"])
        if sent_at.tzinfo is None:
            sent_at = sent_at.replace(tzinfo=timezone.utc)

        age = datetime.now(timezone.utc) - sent_at
        return age < self._suppress

    def record(self, target: str, ip: str, alert_type: str, detail: str) -> None:
        """Mark this alert as sent right now."""
        key = self._make_key(target, ip, alert_type, detail)
        self._entries[key] = {
            "target": target,
            "ip": ip,
            "alert_type": alert_type,
            "detail": detail[:120],
            "sent_at": datetime.now(timezone.utc).isoformat(),
        }
        self._save()

    def cleanup(self, max_age_days: int = 7) -> int:
        """Remove entries older than max_age_days.  Returns count removed."""
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
        stale_keys = []
        for key, entry in self._entries.items():
            try:
                sent_at = datetime.fromisoformat(entry["sent_at"])
                if sent_at.tzinfo is None:
                    sent_at = sent_at.replace(tzinfo=timezone.utc)
                if sent_at < cutoff:
                    stale_keys.append(key)
            except (KeyError, ValueError):
                stale_keys.append(key)

        for key in stale_keys:
            del self._entries[key]

        if stale_keys:
            self._save()
            logger.info("Pruned %d stale alert entries", len(stale_keys))

        return len(stale_keys)
