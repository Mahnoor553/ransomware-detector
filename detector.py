# ============================================================
# Secure Backup and Ransomware Detection System
# Name  : Mahnoor Habib
# Roll No : BITF24M003
# Subject : Information Security
# ============================================================

#  Import the tools
import os           
import sys         
import time         
import shutil       
import hashlib      
import json         
import logging      
from datetime import datetime      
from collections import deque      
from pathlib import Path           


#  Settings 
BASE_DIR = Path(__file__).parent       
MONITORED_DIR = BASE_DIR / "monitored" 
BACKUP_DIR    = BASE_DIR / "backup"    
LOG_DIR       = BASE_DIR / "logs"      
HASH_STORE    = BASE_DIR / "hashes.json"  

POLL_INTERVAL    = 3   
CHANGE_THRESHOLD = 3   
WINDOW_SECONDS   = 10   


#  Create folders 
MONITORED_DIR.mkdir(parents=True, exist_ok=True)
BACKUP_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)


#  Set up logging
log_filename = LOG_DIR / f"detector_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

screen_handler = logging.StreamHandler(sys.stdout)
screen_handler.stream = open(
    sys.stdout.fileno(), mode='w', encoding='utf-8', buffering=1, closefd=False
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  [%(levelname)s]  %(message)s",
    handlers=[
        logging.FileHandler(log_filename, encoding='utf-8'),
        screen_handler,
    ],
)
logger = logging.getLogger(__name__)

#  HELPER FUNCTIONS
def get_file_fingerprint(filepath):
    """
    Read a file and return its SHA-256 fingerprint (a unique 64-char string).
    If the file changes even slightly, the fingerprint will be completely different.
    We read in 64KB chunks so even large files don't fill up RAM.
    """
    hasher = hashlib.sha256()

    try:
        with open(filepath, "rb") as file:
            while True:
                chunk = file.read(65536)    
                if not chunk:
                    break
                hasher.update(chunk)
    except (IOError, PermissionError) as error:
        logger.warning(f"Cannot read file {filepath}: {error}")
        return ""

    return hasher.hexdigest()


def load_saved_fingerprints():
    """
    Load the fingerprints we saved last time from hashes.json.
    If the file doesn't exist (first run), return an empty dictionary.
    """
    if HASH_STORE.exists():
        with open(HASH_STORE) as f:
            return json.load(f)
    return {}


def save_fingerprints(fingerprints):
    """Save the current fingerprints to hashes.json so we remember them."""
    with open(HASH_STORE, "w") as f:
        json.dump(fingerprints, f, indent=2)


def scan_all_files():
    """
    Go through every file in monitored/ and get its fingerprint.
    Returns a dictionary: { "document_01.txt": "a3f4b2...", ... }
    """
    result = {}

    for folder, subfolders, files in os.walk(MONITORED_DIR):
        for filename in files:
            full_path = Path(folder) / filename
            relative_name = str(full_path.relative_to(MONITORED_DIR))
            result[relative_name] = get_file_fingerprint(full_path)

    return result


def create_backup(filename):
    """
    Copy a file into the backup/ folder with a timestamp in the name.
    Example: document_01.txt -> backup/document_01__20260418_184233.txt
    """
    source_path = MONITORED_DIR / filename

    if not source_path.exists():
        logger.warning(f"Cannot backup - file not found: {source_path}")
        return None

    name_without_ext = Path(filename).stem
    extension        = Path(filename).suffix
    timestamp        = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename  = f"{name_without_ext}__{timestamp}{extension}"
    backup_path      = BACKUP_DIR / backup_filename

    shutil.copy2(source_path, backup_path)
    logger.info(f"[BACKUP]  {filename}  ->  {backup_filename}")
    return backup_path


def show_alert(message):
    """Print a big visible alert and save it to the log."""
    border = "!" * 60
    print(f"\n{border}")
    print(f"  *** ALERT *** {message}")
    print(f"{border}\n")
    logger.critical(f"ALERT: {message}")
# THE MAIN DETECTOR CLASS
class RansomwareDetector:

    def __init__(self):
        """Set up the detector when it is first created."""
        self.saved_fingerprints  = load_saved_fingerprints()
        self.recent_change_times = deque()   # stores timestamps of recent changes
        self.alert_already_sent  = False
        self.total_alerts        = 0
        self.total_backups       = 0
        self.total_scans         = 0

    def remove_old_timestamps(self):
        """Remove timestamps older than WINDOW_SECONDS from our list."""
        ten_seconds_ago = time.time() - WINDOW_SECONDS
        while self.recent_change_times and self.recent_change_times[0] < ten_seconds_ago:
            self.recent_change_times.popleft()

    def is_burst_happening(self):
        """Return True if too many files changed in the last 10 seconds."""
        self.remove_old_timestamps()
        return len(self.recent_change_times) >= CHANGE_THRESHOLD

    def handle_new_file(self, filename):
        """A new file appeared - back it up and record the time."""
        logger.info(f"[NEW FILE]  {filename}")
        create_backup(filename)
        self.total_backups += 1
        self.recent_change_times.append(time.time())

    def handle_modified_file(self, filename):
        """A file was changed - back it up and record the time."""
        logger.info(f"[MODIFIED]  {filename}")
        create_backup(filename)
        self.total_backups += 1
        self.recent_change_times.append(time.time())

    def handle_deleted_file(self, filename):
        """A file was deleted - record the time (deletion = suspicious too)."""
        logger.info(f"[DELETED]   {filename}")
        self.recent_change_times.append(time.time())

    def do_one_scan(self):
        """
        One scan cycle - runs every 3 seconds.
        Compares current files with saved fingerprints.
        Detects new, modified, and deleted files.
        """
        current_fingerprints = scan_all_files()
        self.total_scans += 1

        # Check for NEW and MODIFIED files
        for filename, fingerprint in current_fingerprints.items():
            if filename not in self.saved_fingerprints:
                self.handle_new_file(filename)
            elif self.saved_fingerprints[filename] != fingerprint:
                self.handle_modified_file(filename)

        # Check for DELETED files
        for filename in list(self.saved_fingerprints.keys()):
            if filename not in current_fingerprints:
                self.handle_deleted_file(filename)

        # Save updated fingerprints
        self.saved_fingerprints = current_fingerprints
        save_fingerprints(self.saved_fingerprints)

        # Check if burst alert should fire
        if self.is_burst_happening() and not self.alert_already_sent:
            self.alert_already_sent = True
            self.total_alerts += 1
            show_alert(
                f"Ransomware-like activity detected! "
                f"{len(self.recent_change_times)} files changed in {WINDOW_SECONDS}s. "
                f"Immediate action required!"
            )

        # Clear alert if things are back to normal
        if self.alert_already_sent and not self.is_burst_happening():
            self.alert_already_sent = False
            logger.info("[INFO] Activity returned to normal. Alert cleared.")

    def start_monitoring(self):
        """Start watching the folder. Runs forever until Ctrl+C."""
        logger.info("=" * 60)
        logger.info("  Secure Backup & Ransomware Detection System")
        logger.info(f"  Monitoring : {MONITORED_DIR}")
        logger.info(f"  Backup dir : {BACKUP_DIR}")
        logger.info(f"  Threshold  : {CHANGE_THRESHOLD} changes / {WINDOW_SECONDS}s")
        logger.info(f"  Poll every : {POLL_INTERVAL}s")
        logger.info("=" * 60)

        if not self.saved_fingerprints:
            logger.info("[INIT] Building initial hash baseline ...")
            self.saved_fingerprints = scan_all_files()
            save_fingerprints(self.saved_fingerprints)
            logger.info(f"[INIT] Baseline recorded for {len(self.saved_fingerprints)} file(s).")

        logger.info("[RUNNING] Press Ctrl+C to stop.\n")

        try:
            while True:
                self.do_one_scan()
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            self.show_summary()

    def show_summary(self):
        """Print a summary when the user stops the program."""
        logger.info("\n" + "=" * 60)
        logger.info("  Session Summary")
        logger.info(f"  Total scans   : {self.total_scans}")
        logger.info(f"  Total backups : {self.total_backups}")
        logger.info(f"  Total alerts  : {self.total_alerts}")
        logger.info("=" * 60)

#  RESTORE FUNCTION
def restore_menu():
    """Show all backups and let the user pick one to restore."""
    all_backups = sorted(BACKUP_DIR.glob("*"))

    if not all_backups:
        print("\n[INFO] No backups found.")
        return

    print("\n" + "-" * 50)
    print("  Available backups")
    print("-" * 50)
    for number, backup_file in enumerate(all_backups, 1):
        file_size = backup_file.stat().st_size
        print(f"  [{number:>2}]  {backup_file.name:<45}  {file_size:>8} bytes")
    print("-" * 50)

    try:
        choice = int(input("\nEnter number to restore (0 to cancel): "))
    except ValueError:
        print("Please enter a number.")
        return

    if choice == 0:
        return

    if not (1 <= choice <= len(all_backups)):
        print("That number is out of range.")
        return

    chosen_backup = all_backups[choice - 1]

    # Figure out original filename from backup name
    # "document_01__20260418_184233.txt" -> "document_01.txt"
    name_parts    = chosen_backup.stem.split("__")
    original_name = name_parts[0] + chosen_backup.suffix

    restore_destination = MONITORED_DIR / original_name

    confirm = input(f"\nRestore '{chosen_backup.name}' -> '{restore_destination}'? (yes/y/no): ").strip().lower()

    if confirm in ("yes", "y"):
        shutil.copy2(chosen_backup, restore_destination)
        print(f"[RESTORED]  {restore_destination}")
        logger.info(f"[RESTORE]  {chosen_backup.name}  ->  {restore_destination}")
    else:
        print("Restore cancelled.")

#  START THE PROGRAM
def main():
    """
    python detector.py         -> starts monitoring
    python detector.py restore -> opens restore menu
    """
    if len(sys.argv) > 1 and sys.argv[1] == "restore":
        restore_menu()
        return

    detector = RansomwareDetector()
    detector.start_monitoring()


if __name__ == "__main__":
    main()