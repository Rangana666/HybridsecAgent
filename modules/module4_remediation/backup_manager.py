"""
backup_manager.py — Config File Backup & Rollback Manager  (Module 4)

Creates timestamped backups of system config files before any auto-fix
is applied, and supports one-click rollback by restoring the original.

Backup naming:
  data/backups/<timestamp>_<sanitised_filename>
  e.g. data/backups/20250417_150000_etc_ssh_sshd_config

Index file:
  data/backups/backup_index.json
  {
    "backup_id": {
      "original_path": "/etc/ssh/sshd_config",
      "backup_path":   "data/backups/20250417_150000_...",
      "created_at":    "2025-04-17T15:00:00",
      "vuln_type":     "ssh_root_login_enabled",
      "restored":      false
    }, ...
  }
"""

import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# Project root resolution
_PROJECT_ROOT = Path(__file__).parent.parent.parent
_BACKUPS_DIR  = _PROJECT_ROOT / "data" / "backups"
_INDEX_FILE   = _BACKUPS_DIR  / "backup_index.json"


class BackupManager:
    """Creates, tracks, and restores config file backups."""

    def __init__(self, backups_dir: Optional[Path] = None):
        self._dir = Path(backups_dir) if backups_dir else _BACKUPS_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._dir / "backup_index.json"

    # ── Public API ─────────────────────────────────────────────

    def backup(self, original_path: str, vuln_type: str = "") -> dict:
        """
        Create a timestamped backup of a system file.

        Args:
            original_path: absolute path to the file to back up
            vuln_type:     vulnerability type triggering the backup
                           (stored in index for traceability)

        Returns:
            dict:
              success     (bool)
              backup_id   (str)  — unique ID for this backup
              backup_path (str)  — path to the backup file
              error       (str|None)
        """
        src = Path(original_path)

        if not src.exists():
            return {
                "success": False,
                "backup_id": "",
                "backup_path": "",
                "error": f"Source file not found: {original_path}",
            }

        # Build backup filename
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_name = str(original_path).lstrip("/").replace("/", "_")
        backup_filename = f"{ts}_{safe_name}"
        backup_path = self._dir / backup_filename
        backup_id = f"backup_{ts}_{safe_name}"

        try:
            shutil.copy2(str(src), str(backup_path))
            logger.info("Backed up %s → %s", original_path, backup_path)

            # Record in index
            entry = {
                "original_path": str(original_path),
                "backup_path":   str(backup_path),
                "created_at":    datetime.now().isoformat(timespec="seconds"),
                "vuln_type":     vuln_type,
                "restored":      False,
            }
            self._write_index({**self._read_index(), backup_id: entry})

            return {
                "success":     True,
                "backup_id":   backup_id,
                "backup_path": str(backup_path),
                "error":       None,
            }

        except PermissionError:
            error = f"Permission denied backing up {original_path}"
            logger.error(error)
            return {"success": False, "backup_id": "", "backup_path": "", "error": error}
        except Exception as e:
            error = str(e)
            logger.error("Backup failed: %s", e)
            return {"success": False, "backup_id": "", "backup_path": "", "error": error}

    def restore(self, backup_id: str) -> dict:
        """
        Restore a file from backup (rollback).

        Args:
            backup_id: the backup_id returned by backup()

        Returns:
            dict:
              success (bool)
              message (str)
              error   (str|None)
        """
        index = self._read_index()
        entry = index.get(backup_id)

        if not entry:
            return {
                "success": False,
                "message": "",
                "error": f"Backup ID not found: {backup_id}",
            }

        backup_path   = Path(entry["backup_path"])
        original_path = Path(entry["original_path"])

        if not backup_path.exists():
            return {
                "success": False,
                "message": "",
                "error": f"Backup file missing on disk: {backup_path}",
            }

        try:
            shutil.copy2(str(backup_path), str(original_path))
            logger.info("Restored %s ← %s", original_path, backup_path)

            # Mark as restored in index
            entry["restored"] = True
            entry["restored_at"] = datetime.now().isoformat(timespec="seconds")
            index[backup_id] = entry
            self._write_index(index)

            return {
                "success": True,
                "message": f"Restored {original_path} from backup {backup_id}",
                "error": None,
            }

        except PermissionError:
            error = f"Permission denied restoring to {original_path}"
            logger.error(error)
            return {"success": False, "message": "", "error": error}
        except Exception as e:
            error = str(e)
            logger.error("Restore failed: %s", e)
            return {"success": False, "message": "", "error": error}

    def list_backups(self, vuln_type: Optional[str] = None) -> list[dict]:
        """
        List all backups, optionally filtered by vuln_type.
        Returns newest first.
        """
        index = self._read_index()
        entries = []
        for bid, entry in index.items():
            if vuln_type and entry.get("vuln_type") != vuln_type:
                continue
            entries.append({"backup_id": bid, **entry})
        return sorted(entries, key=lambda e: e.get("created_at", ""), reverse=True)

    def delete(self, backup_id: str) -> dict:
        """
        Remove a backup entry from the index and delete its file from disk.
        """
        index = self._read_index()
        entry = index.get(backup_id)
        if not entry:
            return {"success": False, "error": f"Backup ID not found: {backup_id}"}
        try:
            bp = Path(entry["backup_path"])
            if bp.exists():
                bp.unlink()
            del index[backup_id]
            self._write_index(index)
            logger.info("Deleted backup entry: %s", backup_id)
            return {"success": True, "error": None}
        except Exception as e:
            logger.error("Delete backup failed: %s", e)
            return {"success": False, "error": str(e)}

    def get_latest_backup(self, original_path: str) -> Optional[dict]:
        """
        Return the most recent backup for a given original file path.
        """
        matching = [
            e for e in self.list_backups()
            if e["original_path"] == str(original_path)
        ]
        return matching[0] if matching else None

    def cleanup_old_backups(self, retention_days: int = 30) -> int:
        """
        Delete backups older than retention_days days.
        Returns count of deleted backups.
        """
        from datetime import timezone
        index = self._read_index()
        cutoff = datetime.now(timezone.utc).timestamp() - (retention_days * 86400)
        to_delete = []

        for bid, entry in index.items():
            try:
                ts = datetime.fromisoformat(entry["created_at"])
                if ts.timestamp() < cutoff:
                    to_delete.append(bid)
            except Exception:
                continue

        for bid in to_delete:
            entry = index[bid]
            bp = Path(entry["backup_path"])
            if bp.exists():
                bp.unlink()
                logger.info("Deleted old backup: %s", bp)
            del index[bid]

        if to_delete:
            self._write_index(index)
        return len(to_delete)

    # ── Private Helpers ────────────────────────────────────────

    def _read_index(self) -> dict:
        if not self._index_path.exists():
            return {}
        try:
            return json.loads(self._index_path.read_text())
        except Exception:
            return {}

    def _write_index(self, index: dict):
        self._index_path.write_text(json.dumps(index, indent=2))


# ── Standalone test ────────────────────────────────────────────
if __name__ == "__main__":
    import tempfile, os
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")

    with tempfile.TemporaryDirectory() as tmp:
        bm = BackupManager(backups_dir=Path(tmp) / "backups")

        # Create a fake "config" file
        fake_cfg = Path(tmp) / "sshd_config"
        fake_cfg.write_text("PermitRootLogin yes\nPasswordAuthentication yes\n")

        # Backup
        result = bm.backup(str(fake_cfg), vuln_type="ssh_root_login_enabled")
        assert result["success"], result["error"]
        print(f"[PASS] backup → id={result['backup_id'][:40]}...")

        # Modify original
        fake_cfg.write_text("PermitRootLogin no\nPasswordAuthentication no\n")

        # List backups
        backups = bm.list_backups()
        assert len(backups) == 1
        print(f"[PASS] list_backups → {len(backups)} backup(s)")

        # Restore
        restore = bm.restore(result["backup_id"])
        assert restore["success"], restore["error"]
        content = fake_cfg.read_text()
        assert "PermitRootLogin yes" in content, "Restore did not revert the file!"
        print(f"[PASS] restore → original content recovered")

        # Latest backup
        latest = bm.get_latest_backup(str(fake_cfg))
        assert latest is not None
        print(f"[PASS] get_latest_backup → found")

        print("\nAll BackupManager tests PASSED.")
