"""
Secure Backup and Ransomware Detection System
Author : Mahnoor Habib  (BITF24M003)
Subject: Information Security

How it works:
  1. Computes SHA-256 hash of every file in the monitored folder.
  2. Polls for changes every POLL_INTERVAL seconds.
  3. If more than CHANGE_THRESHOLD files change within WINDOW_SECONDS it
     raises a ransomware alert, locks further backups, and notifies the user.
  4. On every normal change it backs up the affected file automatically.
  5. The user can restore any backed-up file through the CLI menu.
"""

import os
import sys
import time
import shutil
import hashlib
import logging
import json
from datetime import datetime
from collections import deque
from pathlib import Path

# ─────────────────────────── Configuration ───────────────────────────────────
BASE_DIR        = Path(__file__).parent
MONITORED_DIR   = BASE_DIR / "monitored"
BACKUP_DIR      = BASE_DIR / "backup"
LOG_DIR         = BASE_DIR / "logs"
HASH_STORE      = BASE_DIR / "hashes.json"

POLL_INTERVAL   = 3          # seconds between each scan
CHANGE_THRESHOLD = 3         # files changed in one window → alert
WINDOW_SECONDS  = 10         # sliding window size (seconds)
# ─────────────────────────────────────────────────────────────────────────────

# ── Logging setup ─────────────────────────────────────────────────────────────
LOG_DIR.mkdir(parents=True, exist_ok=True)
MONITORED_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

log_file = LOG_DIR / f"detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    handlers=[
        logging.FileHandler(log_file),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger(__name__)


# ─────────────────────── Helper functions ────────────────────────────────────

def sha256(filepath: Path) -> str:
    """Return the SHA-256 hex digest of a file."""
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
    except (IOError, PermissionError) as e:
        logger.warning(f"Cannot read {filepath}: {e}")
        return ""
    return h.hexdigest()


def load_hashes() -> dict:
    """Load previously stored hashes from disk."""
    if HASH_STORE.exists():
        try:
            with open(HASH_STORE) as f:
                return json.load(f)
        except json.JSONDecodeError:
            pass
    return {}


def save_hashes(hashes: dict) -> None:
    """Persist current hashes to disk."""
    with open(HASH_STORE, "w") as f:
        json.dump(hashes, f, indent=2)


def scan_directory() -> dict:
    """Walk MONITORED_DIR and return {relative_path_str: sha256} for every file."""
    result = {}
    for root, _, files in os.walk(MONITORED_DIR):
        for name in files:
            full = Path(root) / name
            rel  = str(full.relative_to(MONITORED_DIR))
            result[rel] = sha256(full)
    return result


def backup_file(rel_path: str) -> Path:
    """
    Copy the current version of a monitored file into BACKUP_DIR.
    Backup name  →  <stem>__<timestamp><suffix>
    Returns the backup path.
    """
    src = MONITORED_DIR / rel_path
    if not src.exists():
        logger.warning(f"Backup skipped – file not found: {src}")
        return None

    stem      = Path(rel_path).stem
    suffix    = Path(rel_path).suffix
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    dst_name  = f"{stem}__{timestamp}{suffix}"
    dst       = BACKUP_DIR / dst_name

    shutil.copy2(src, dst)
    logger.info(f"[BACKUP]  {rel_path}  →  {dst_name}")
    return dst


def alert(message: str) -> None:
    """Print a highly visible alert to the console and log it."""
    border = "!" * 60
    print(f"\n{border}")
    print(f"  *** ALERT *** {message}")
    print(f"{border}\n")
    logger.critical(f"ALERT: {message}")


# ─────────────────────── Core monitor class ───────────────────────────────────

class RansomwareDetector:
    """
    Polls MONITORED_DIR in a loop.
    Maintains a sliding window of recent change timestamps to detect
    bursts of file modifications that are characteristic of ransomware.
    """

    def __init__(self):
        self.known_hashes: dict      = load_hashes()
        self.change_times: deque     = deque()   # timestamps of recent changes
        self.alert_raised: bool      = False
        self.total_alerts: int       = 0
        self.total_backups: int      = 0
        self.scan_count:   int       = 0

    # ── internal helpers ──────────────────────────────────────────────────────

    def _prune_window(self) -> None:
        """Remove timestamps older than WINDOW_SECONDS from the deque."""
        cutoff = time.time() - WINDOW_SECONDS
        while self.change_times and self.change_times[0] < cutoff:
            self.change_times.popleft()

    def _check_burst(self) -> bool:
        """Return True if the number of recent changes exceeds the threshold."""
        self._prune_window()
        return len(self.change_times) >= CHANGE_THRESHOLD

    def _handle_new_file(self, rel: str) -> None:
        logger.info(f"[NEW FILE]  {rel}")
        backup_file(rel)
        self.total_backups += 1
        self.change_times.append(time.time())

    def _handle_modified(self, rel: str) -> None:
        logger.info(f"[MODIFIED]  {rel}")
        backup_file(rel)
        self.total_backups += 1
        self.change_times.append(time.time())

    def _handle_deleted(self, rel: str) -> None:
        logger.info(f"[DELETED]   {rel}")
        self.change_times.append(time.time())

    # ── main scan ─────────────────────────────────────────────────────────────

    def scan(self) -> None:
        """One scan cycle: compare current state vs stored hashes."""
        current = scan_directory()
        self.scan_count += 1

        # Detect new / modified files
        for rel, digest in current.items():
            if rel not in self.known_hashes:
                self._handle_new_file(rel)
            elif self.known_hashes[rel] != digest:
                self._handle_modified(rel)

        # Detect deleted files
        for rel in list(self.known_hashes.keys()):
            if rel not in current:
                self._handle_deleted(rel)

        # Update stored state
        self.known_hashes = current
        save_hashes(self.known_hashes)

        # Burst detection
        if self._check_burst() and not self.alert_raised:
            self.alert_raised = True
            self.total_alerts += 1
            alert(
                f"Ransomware-like activity detected! "
                f"{len(self.change_times)} files changed in {WINDOW_SECONDS}s. "
                f"Immediate action required!"
            )

        # Reset alert flag once the burst window clears
        if self.alert_raised and not self._check_burst():
            self.alert_raised = False
            logger.info("[INFO] Activity returned to normal. Alert cleared.")

    # ── public run loop ───────────────────────────────────────────────────────

    def run(self) -> None:
        logger.info("=" * 60)
        logger.info("  Secure Backup & Ransomware Detection System")
        logger.info(f"  Monitoring : {MONITORED_DIR}")
        logger.info(f"  Backup dir : {BACKUP_DIR}")
        logger.info(f"  Threshold  : {CHANGE_THRESHOLD} changes / {WINDOW_SECONDS}s")
        logger.info(f"  Poll every : {POLL_INTERVAL}s")
        logger.info("=" * 60)

        # Build initial baseline on first run
        if not self.known_hashes:
            logger.info("[INIT] Building initial hash baseline …")
            self.known_hashes = scan_directory()
            save_hashes(self.known_hashes)
            logger.info(f"[INIT] Baseline recorded for {len(self.known_hashes)} file(s).")

        logger.info("[RUNNING] Press Ctrl+C to stop.\n")

        try:
            while True:
                self.scan()
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            self._print_summary()

    def _print_summary(self) -> None:
        logger.info("\n" + "=" * 60)
        logger.info("  Session Summary")
        logger.info(f"  Total scans   : {self.scan_count}")
        logger.info(f"  Total backups : {self.total_backups}")
        logger.info(f"  Total alerts  : {self.total_alerts}")
        logger.info("=" * 60)


# ─────────────────────── Restore utility ─────────────────────────────────────

def list_backups() -> list:
    """Return a sorted list of backup file Paths."""
    return sorted(BACKUP_DIR.glob("*"))


def restore_menu() -> None:
    """Interactive CLI to restore a file from backup."""
    backups = list_backups()
    if not backups:
        print("\n[INFO] No backups found.")
        return

    print("\n" + "─" * 50)
    print("  Available backups")
    print("─" * 50)
    for i, b in enumerate(backups, 1):
        size = b.stat().st_size
        print(f"  [{i:>2}]  {b.name:<45}  {size:>8} bytes")
    print("─" * 50)

    try:
        choice = int(input("\nEnter number to restore (0 to cancel): "))
    except ValueError:
        print("Invalid input.")
        return

    if choice == 0:
        return

    if not (1 <= choice <= len(backups)):
        print("Number out of range.")
        return

    backup_path = backups[choice - 1]

    # Reconstruct original filename (strip __<timestamp> from stem)
    name   = backup_path.name
    # e.g. "report__20240101_120000.txt"  →  "report.txt"
    stem   = backup_path.stem          # "report__20240101_120000"
    suffix = backup_path.suffix        # ".txt"
    parts  = stem.split("__")
    orig_stem = parts[0] if len(parts) >= 2 else stem
    orig_name = orig_stem + suffix

    dest = MONITORED_DIR / orig_name
    confirm = input(f"\nRestore '{name}' → '{dest}'? (yes/no): ").strip().lower()
    if confirm == "yes":
        shutil.copy2(backup_path, dest)
        print(f"[RESTORED]  {dest}")
        logger.info(f"[RESTORE]  {backup_path.name}  →  {dest}")
    else:
        print("Restore cancelled.")


# ─────────────────────── Entry point ─────────────────────────────────────────

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        restore_menu()
        return

    detector = RansomwareDetector()
    detector.run()


if __name__ == "__main__":
    main()