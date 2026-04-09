# EDR Antigravity Simulation Lab

This repository contains a full simulation environment for an AI-powered Endpoint Detection and Response (EDR) system designed to detect, quarantine, and remediate ransomware attacks in real-time.

## Overview

The system includes tools to generate dummy data, train an AI anomaly detection model, run the active EDR defense, simulate a ransomware attack, and finally, utilities to unquarantine or restore data manually if needed.

### File Structure & Core Components

- **`data_generator.py`**: Generates a set of dummy text files in the `dummy_data/` directory to act as targets for the ransomware.
- **`train_model.py`**: Trains an `IsolationForest` machine learning model on normal vs. ransomware-like filesystem behaviors and outputs `edr_model.pkl`.
- **`edr.py`**: The core AI Antivirus/EDR system. It creates shadow backups, monitors filesystem behavior, loads the trained ML model, and actively detects and un-spawns ransomware processes.
- **`mock_malware.py` / `ransomware.py`**: Ransomware simulators that attempt to traverse `dummy_data/`, encrypt files using Fernet/AES, and rename them to `.locked`.
- **`unquarantine.py`**: An administrative tool to remove files from the `quarantined_data/` folder and restore them to their original location.
- **`restore.py`**: A manual fallback tool to recover your dummy data from the `edr_backup/` in case the automatic EDR restoration process fails or needs a retry.

---

## 🚀 How to Run the Simulation

Follow these steps in order to set up, secure, and test the Antivirus against the Ransomware.

### Step 1: Prep the Environment

1. Ensure requirements are installed. If a `requirements.txt` is available:
   ```bash
   pip install -r requirements.txt
   ```
   *Primary dependencies: `psutil`, `watchdog`, `pandas`, `scikit-learn`, `cryptography`*

2. **Generate the target data**
   Run the data generator to create dummy files that the malware will attempt to encrypt:
   ```bash
   python data_generator.py
   ```
   *(This creates a `dummy_data` folder filled with text files)*

3. **Train the AI Model**
   The EDR relies on an `IsolationForest` ML model to classify file operations (modifications per second, renames, entropy). 
   ```bash
   python train_model.py
   ```
   *(This creates `edr_model.pkl`)*

### Step 2: Start the EDR Antivirus

Open a terminal and start the EDR process. It requires the generated dummy data and the trained model to function.

```bash
python edr.py
```

*What the EDR does upon starting:*
- Creates a hidden shadow copy backup inside `edr_backup/`.
- Initializes filesystem event watchers on the target directories.
- Caches running processes periodically to maintain an intelligent timeline of process creations to correlate with filesystem anomalies.
- Stays active, continuously logging state.

**Note:** Keep this terminal open and running.

### Step 3: Run the Ransomware

To see the system in action, open a **separate terminal** and execute your malicious payload:

```bash
python mock_malware.py
```
*(You may also run `ransomware.py` or any other simulator you are testing)*

*What you will see:*
1. The ransomware will begin recursively modifying files in `dummy_data/` turning them into `.locked` encrypted chunks.
2. The `edr.py` process will detect a spike in modifications, renames, and a jump in file entropy.
3. The AI model flags the sequence as an anomaly (`Prediction: -1`).
4. The EDR correlates the event time with recently created/active processes, isolating the malware script.
5. The EDR terminates the script, moves it securely into `quarantined_data/`, and then auto-restores the affected files from the shadow backup.

---

## 🛠️ Management and Remediation

### Un-Quarantining Executables
If the EDR accidentally catches a false positive (or you simply want your ransomware script back to run another test):

```bash
python unquarantine.py
```
This interactive script lists all items in `quarantined_data/` along side their pre-lockout original paths, letting you selectively pick which file to restore to its proper location.

### Manual Data Restoration
If the ransomware was exceptionally fast and EDR auto-restore crashed or failed to complete:

```bash
python restore.py
```
This utility references `original_path.json` to move the secure copies out of `edr_backup/` back into `dummy_data/`, stripping away any leftover `.locked` files the malware managed to create.

## Configuration Defaults

- **Target Directory**: `dummy_data`
- **Quarantine Directory**: `quarantined_data` 
- **AI Model File**: `edr_model.pkl`
- **Whitelist**: Managed via `whitelist.txt` (Root applications or safe scripts to prevent the EDR from killing legitimate system/IDE processes).
