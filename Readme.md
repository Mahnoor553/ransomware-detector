# Secure Backup & Ransomware Detection System

**Student:** Mahnoor Habib  
**Roll No:** BITF24M003  
**Subject:** Information Security  

---

## Overview
A Python-based system that monitors a folder in real time, detects ransomware-like activity using SHA-256 file integrity checks, automatically backs up changed files, and alerts the user when a suspicious burst of changes is detected.

## Project Structure
```
ransomware_detector/
├── detector.py       ← Main monitor (run this)
├── simulator.py      ← Test simulator (mimics ransomware behaviour)
├── requirements.txt  ← No external packages needed
├── hashes.json       ← Auto-generated hash store
├── monitored/        ← Folder being watched
├── backup/           ← Auto backups saved here
└── logs/             ← Log files saved here
```

## How to Run

### 1. Start the detector
```bash
python detector.py
```

### 2. In a second terminal — run the simulator to test
```bash
python simulator.py
```

### 3. Restore a backed-up file
```bash
python detector.py restore
```

## How It Works
1. On first run, SHA-256 hashes of all files in `monitored/` are recorded.
2. Every 3 seconds the folder is re-scanned and hashes compared.
3. New, modified, or deleted files are logged and backed up automatically.
4. If **3 or more files** change within **10 seconds**, a ransomware alert fires.
5. Backups are timestamped copies stored in `backup/`.


## Academic Note
The simulator does **not** use real malware. It only overwrites text files rapidly to trigger the detection logic for testing purposes.
