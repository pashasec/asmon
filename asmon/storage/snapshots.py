"""
storage/snapshots.py — Snapshot persistence layer.

Design decisions:
  - Snapshots are stored as individual JSON files, not a database.
    Rationale: this is a single-user tool. Flat files are debuggable,
    portable, and require zero infrastructure.
  - File naming: {target}_{uuid4}.json inside SNAPSHOT_DIR.
  - Writes are atomic: write to .tmp, then os.replace().
    Prevents corrupt snapshots on crash / Ctrl-C.
  - Listing and loading are by target name. The storage layer owns
    the mapping between target -> filenames.
"""

import json
import logging
import uuid
from pathlib import Path

from asmon.models import Snapshot

logger = logging.getLogger("asmon.storage")


class SnapshotStore:
    """Read/write snapshots to the local filesystem."""

    def __init__(self, base_dir: Path):
        self._dir = base_dir
        self._dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def save(self, snapshot: Snapshot) -> Path:
        """
        Persist a snapshot. Assigns a snapshot_id if not already set.
        Returns the path of the written file.
        """
        if not snapshot.snapshot_id:
            snapshot.snapshot_id = str(uuid.uuid4())

        filename = self._path_for(snapshot.target, snapshot.snapshot_id)
        tmp_path = filename.with_suffix(".tmp")

        try:
            with open(tmp_path, "w", encoding="utf-8") as fh:
                fh.write(snapshot.model_dump_json(indent=2))
            tmp_path.replace(filename)  # Atomic
            logger.info("Snapshot saved: %s", filename.name)
            return filename
        except OSError as exc:
            logger.error("Failed to write snapshot: %s", exc)
            tmp_path.unlink(missing_ok=True)
            raise

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def latest(self, target: str) -> Snapshot | None:
        """Return the most recent snapshot for a target, or None."""
        snapshots = self.list_snapshots(target)
        return snapshots[0] if snapshots else None

    def get(self, snapshot_id: str) -> Snapshot | None:
        """Load a snapshot by its ID."""
        for path in self._dir.glob("*.json"):
            if snapshot_id in path.stem:
                return self._load(path)
        return None

    def list_snapshots(self, target: str) -> list[Snapshot]:
        """All snapshots for a target, newest-first."""
        snapshots: list[Snapshot] = []
        prefix = self._safe_target_name(target)

        for path in self._dir.glob(f"{prefix}_*.json"):
            snap = self._load(path)
            if snap:
                snapshots.append(snap)

        snapshots.sort(key=lambda s: s.captured_at, reverse=True)
        return snapshots

    def list_targets(self) -> list[str]:
        """All target names with at least one snapshot on disk."""
        targets: set[str] = set()
        for path in self._dir.glob("*.json"):
            parts = path.stem.rsplit("_", 1)
            if len(parts) == 2:
                targets.add(parts[0].replace("_", "."))
        return sorted(targets)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _path_for(self, target: str, snapshot_id: str) -> Path:
        safe_target = self._safe_target_name(target)
        return self._dir / f"{safe_target}_{snapshot_id}.json"

    @staticmethod
    def _safe_target_name(target: str) -> str:
        return target.lower().replace(".", "_").replace(" ", "_")

    @staticmethod
    def _load(path: Path) -> Snapshot | None:
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
            return Snapshot.model_validate(data)
        except Exception as exc:
            logger.warning("Failed to parse %s: %s", path.name, exc)
            return None
