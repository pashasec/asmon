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
    # Retention / cleanup
    # ------------------------------------------------------------------

    def enforce_retention(
        self,
        target: str,
        keep: int = 0,
        max_age_days: int = 0,
    ) -> int:
        """
        Delete old snapshots for a target based on retention policy.

        Args:
            target:        Target domain name.
            keep:          Keep only the N most recent snapshots (0 = no limit).
            max_age_days:  Delete snapshots older than N days (0 = no limit).

        Returns:
            Number of snapshots deleted.
        """
        if keep <= 0 and max_age_days <= 0:
            return 0  # No policy set

        prefix = self._safe_target_name(target)
        # Build list of (path, captured_at) sorted newest-first
        entries: list[tuple[Path, Snapshot]] = []
        for path in self._dir.glob(f"{prefix}_*.json"):
            snap = self._load(path)
            if snap:
                entries.append((path, snap))
        entries.sort(key=lambda e: e[1].captured_at, reverse=True)

        to_delete: set[Path] = set()

        # --- Count-based retention ---
        if keep > 0 and len(entries) > keep:
            for path, _ in entries[keep:]:
                to_delete.add(path)

        # --- Age-based retention ---
        if max_age_days > 0:
            from datetime import datetime, timezone, timedelta
            cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)
            for path, snap in entries:
                if snap.captured_at < cutoff:
                    to_delete.add(path)
            # Never delete the most recent snapshot even if it's old
            if entries and entries[0][0] in to_delete:
                to_delete.discard(entries[0][0])

        # --- Delete ---
        deleted = 0
        for path in to_delete:
            try:
                path.unlink()
                logger.info("Retention: deleted %s", path.name)
                deleted += 1
            except OSError as exc:
                logger.warning("Failed to delete %s: %s", path.name, exc)

        if deleted > 0:
            logger.info(
                "Retention: deleted %d snapshot(s) for %s (keep=%d, max_age=%dd)",
                deleted, target, keep, max_age_days,
            )
        return deleted

    def enforce_retention_all(
        self,
        keep: int = 0,
        max_age_days: int = 0,
    ) -> int:
        """Run retention policy across all targets. Returns total deleted."""
        total = 0
        for target in self.list_targets():
            total += self.enforce_retention(target, keep=keep, max_age_days=max_age_days)
        return total

    def disk_usage(self) -> dict:
        """Return snapshot storage stats."""
        files = list(self._dir.glob("*.json"))
        total_bytes = sum(f.stat().st_size for f in files)
        targets = self.list_targets()
        return {
            "total_files": len(files),
            "total_bytes": total_bytes,
            "total_mb": round(total_bytes / (1024 * 1024), 2),
            "targets": len(targets),
        }

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
