"""
Ransomware Simulator  —  FOR TESTING ONLY
==========================================
Name : Mahnoor Habib (BITF24M003)
"""

import os
import time
import random
import string
from pathlib import Path

MONITORED_DIR = Path(__file__).parent / "monitored"
MONITORED_DIR.mkdir(parents=True, exist_ok=True)

SAMPLE_CONTENT = [
    "This is a confidential document with sensitive data.\n",
    "Project report for Information Security course.\n",
    "Financial record Q1 2024: Revenue = 5,000,000 PKR\n",
    "Student database: Name, CGPA, Contact details stored here.\n",
    "Research paper draft — do not distribute.\n",
]


def random_string(length=40) -> str:
    return "".join(random.choices(string.ascii_letters + string.digits, k=length))


def create_sample_files(n=5) -> list:
    """Create n sample files in the monitored directory."""
    paths = []
    for i in range(1, n + 1):
        name = MONITORED_DIR / f"document_{i:02d}.txt"
        name.write_text(SAMPLE_CONTENT[i % len(SAMPLE_CONTENT)])
        print(f"  [+] Created  {name.name}")
        paths.append(name)
    return paths


def simulate_ransomware(files: list, delay: float = 0.5) -> None:
    """Overwrite files rapidly with garbage (simulates encryption)."""
    print("\n[SIMULATOR] Starting rapid file modification …")
    print(f"[SIMULATOR] Modifying {len(files)} files with {delay}s delay between each.\n")

    for f in files:
        fake_encrypted = (
            f"*** ENCRYPTED by RansomSim ***\n"
            f"Original file: {f.name}\n"
            f"Key ID: {random_string(16)}\n"
            f"Payload: {random_string(200)}\n"
        )
        f.write_text(fake_encrypted)
        print(f"  [!] Overwrote  {f.name}")
        time.sleep(delay)

    print("\n[SIMULATOR] Done — check the detector terminal for alerts.")


def delete_files(files: list) -> None:
    """Delete all simulated files (another ransomware behaviour)."""
    print("\n[SIMULATOR] Deleting files …")
    for f in files:
        if f.exists():
            f.unlink()
            print(f"  [-] Deleted  {f.name}")


def menu():
    print("\n" + "=" * 55)
    print("  Ransomware Simulator  (ACADEMIC / TESTING USE ONLY)")
    print("=" * 55)
    print("  1. Create sample files only")
    print("  2. Create files THEN simulate ransomware (full test)")
    print("  3. Delete all sample files in monitored/")
    print("  0. Exit")
    print("=" * 55)
    return input("  Choose option: ").strip()


if __name__ == "__main__":
    while True:
        choice = menu()

        if choice == "1":
            print()
            files = create_sample_files(n=5)
            print("\n[INFO] Files created. Run option 2 to simulate an attack.")

        elif choice == "2":
            print()
            files = create_sample_files(n=5)
            print("\n[INFO] Waiting 4 s before attack begins …")
            time.sleep(4)
            simulate_ransomware(files, delay=0.4)

        elif choice == "3":
            existing = list(MONITORED_DIR.glob("document_*.txt"))
            if existing:
                delete_files(existing)
            else:
                print("\n[INFO] No sample files found.")

        elif choice == "0":
            print("\nExiting simulator.")
            break

        else:
            print("\n[!] Invalid option.")