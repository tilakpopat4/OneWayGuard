<p align="center">
  <img src="logo.png" alt="OneWayGuard Logo" width="340" />
</p>

# OneWayGuard — Standalone Windows Desktop Edition
### Passive Cyber-Threat Detection & Forensic Telemetry Analysis System

[![Platform: Windows 64-bit](https://img.shields.io/badge/Platform-Windows%2010%20%2F%2011%20(x64)-0078D6?logo=windows&logoColor=white)](https://github.com/)
[![Architecture: Standalone Package](https://img.shields.io/badge/Distribution-Standalone%20Package%20(No%20Codebase)-success)](https://github.com/)
[![Python: Embedded 3.10](https://img.shields.io/badge/Python-Bundled%20Internal-blue?logo=python&logoColor=white)](https://github.com/)
[![Model: Hybrid Kalman + XGBoost](https://img.shields.io/badge/Engine-Kalman%20%2B%20XGBoost-orange)](https://github.com/)
[![Operation: 100% Passive](https://img.shields.io/badge/Operation-Zero--Transmission%20%2F%20Passive-brightgreen)](https://github.com/)
[![License: All Rights Reserved](https://img.shields.io/badge/License-Proprietary%20%2F%20Evaluative-lightgrey)](https://github.com/)

---

## 📥 Direct Downloads (v2.0.0 Standalone Package)

| Distribution Package | Description | Direct Download Link |
| :--- | :--- | :--- |
| **🚀 Windows Setup Wizard** (`.exe`) | **Recommended**. Automated 1-click self-settling installer with Desktop & Start Menu shortcuts. | [**Download OneWayGuard-Setup-Win64.exe (v2.0.0)**](https://github.com/tilakpopat4/OneWayGuard/releases/download/v2.0.0/OneWayGuard-Setup-Win64.exe) |
| **💼 Portable Package Archive** (`.zip`) | Self-contained zero-install archive. Extract anywhere and launch directly. | [**Download OneWayGuard-Desktop-Win64.zip (v2.0.0)**](https://github.com/tilakpopat4/OneWayGuard/releases/download/v2.0.0/OneWayGuard-Desktop-Win64.zip) |

---

## 📌 Overview

**OneWayGuard** is a defense-grade, passive network threat analysis system designed specifically for **one-way data diodes, network TAP feeds, mirror ports, and offline forensic PCAP investigations**. 

> **Important Notice:** This repository distributes the **pre-compiled standalone application package**. It does **NOT** require a Python installation, compilers, virtual environments, or external dependencies. All necessary runtimes, models, and dashboard assets are self-contained.

---

## 🚀 Key Capabilities

- **Zero-Footprint Passive Analysis**: Operates strictly on network metadata (IP, TCP/UDP, DNS, TLS/QUIC flow metrics). It never transmits packets, sends active probes, completes TCP handshakes, or modifies traffic.
- **Hybrid Streaming Detection Engine**:
  - **Kalman Anomaly Filter Bank**: Provides sub-millisecond anomaly detection on packet rates, inter-arrival times, and SYN flag divergence.
  - **Hardened XGBoost Classifier**: Evaluates multi-class malicious flow signatures with offline validation metrics of ~98.3% accuracy and 0.999 ROC-AUC.
- **Multi-Vector Threat Identification**:
  - **Botnet C2 Beaconing**: Jitter, inter-arrival periodicity, and heartbeat tracking.
  - **DGA / DNS Tunnelling**: Domain label length, Shannon entropy, and digit-ratio analysis.
  - **Volumetric & Protocol DDoS**: SYN/UDP flood aggregation and destination-level stress signals.
  - **Reconnaissance & Port Scans**: Source-to-host/port fan-out pattern discovery.
  - **Data Exfiltration**: Directional outbound volumetric and byte-ratio heuristics.
- **Forensic Incident Reporting**:
  - Automatically exports defense-grade 5-page formatted reports in **DOCX** and **PDF** formats.
  - Includes cryptographically calculated SHA-256 capture hashes, chain-of-custody logging, and MITRE ATT&CK mitigation matrices.
- **Embedded Desktop Experience**:
  - Launches into an isolated, modern windowed desktop application (via Chrome/Edge App Mode) without terminal windows.

---

## 📦 Package Contents

When you download or clone this package repository, the directory structure contains:

```text
OneWayGuard/
│
├── OneWayGuard.exe                   # Main desktop application launcher
├── README_HOW_TO_RUN.txt             # Quick execution cheatsheet
├── README.md                         # Complete installation & user guide (this file)
│
├── dashboard/                        # Embedded UI web interface (HTML5/CSS3/ES6)
│   ├── index.html                    # Main dashboard interface
│   ├── app.js                        # Client state engine & WebSocket handler
│   └── styles.css                    # Dark glassmorphism UI styling
│
├── models/                           # Pre-trained ML weights & scaler models
│   ├── hardened_binary_xgb.json      # Hardened flow classifier model
│   ├── dga_domain_model.joblib       # DGA / domain classifier
│   └── scaler_metadata.json          # Pre-computed feature normalization scales
│
├── sample_pcaps/                     # Pre-packaged network captures for immediate testing
│   └── sample_threat_traffic.pcap    # Multi-threat evaluation capture
│
├── reports/                          # Default output directory for generated DOCX/PDF reports
│
└── _internal/                        # Bundled standalone C++ runtimes, Python engine & DLLs
    ├── xgboost/                      # Bundled XGBoost C-API and dynamic libraries
    └── ...                           # Core shared dependencies
```

---

## 💻 System Requirements

| Specification | Minimum Requirement | Recommended |
|---|---|---|
| **Operating System** | Windows 10 (64-bit) or Windows 11 (64-bit) | Windows 11 (64-bit) |
| **Processor** | Intel Core i3 / AMD Ryzen 3 or equivalent | Intel Core i5 / AMD Ryzen 5 or better |
| **Memory (RAM)** | 4 GB RAM | 8 GB RAM or higher (recommended for large PCAPs) |
| **Disk Space** | 600 MB free storage | 1 GB free storage |
| **Display** | 1280 x 720 resolution | 1920 x 1080 resolution |
| **Web Browser** | Microsoft Edge or Google Chrome installed | Latest Microsoft Edge / Chrome |
| **Optional Driver** | *None for PCAP replay* | **Npcap** (only needed if using Live Capture) |

> ℹ️ **Offline PCAP Analysis requires zero drivers!** You only need Npcap if you intend to capture live packets directly from a physical network interface.

---

## 🛠️ Installation & Setup

### Step 1: Choose Your Preferred Distribution

- **Option 1: Windows Setup Wizard (Recommended)**:
  - Download or copy the setup files (`OneWayGuard-Setup-Win64.exe`, `OneWayGuard_Security_Certificate.cer`, and `START_INSTALLATION.bat`).
  - **On any external Windows PC**, simply right-click **`START_INSTALLATION.bat`** → **Run as Administrator**.
  - It automatically authorizes the genuine OneWayGuard security certificate, unblocks external download tags, and launches the Setup Wizard with **zero Windows Defender SmartScreen blocks**.
  - The wizard automatically checks for the **Npcap driver**, configures Desktop & Start Menu shortcuts, sets file permissions, and installs to `C:\Program Files\OneWayGuard`.
- **Option 2: Standalone Portable ZIP**:
  - Download `OneWayGuard-Desktop-Win64.zip`.
  - Right-click and extract all files to a local directory (e.g., `C:\OneWayGuard\`).
  - Double-click **`START_ONEWAYGUARD.bat`** (or `OneWayGuard.exe`) to launch immediately.

> ⚠️ **Important (Portable ZIP only):** If using the portable ZIP, do not move `OneWayGuard.exe` outside its extracted folder; it uses relative paths to `_internal/`, `models/`, and `dashboard/`. If you want a desktop shortcut, right-click `OneWayGuard.exe` → **Send to** → **Desktop (create shortcut)**.


---

## ⚡ How to Run OneWayGuard

### 1. Launch the Desktop Application
Double-click `OneWayGuard.exe` in the application folder.

```text
[OneWayGuard.exe]
       │
       ├──► Starts local FastAPI backend service (127.0.0.1:8000)
       ├──► Automatically checks for port conflicts & selects open port
       └──► Launches dedicated UI in standalone desktop application window
```

### 2. Alternative: Command-Line Launch
You can also launch OneWayGuard via PowerShell or Command Prompt to observe startup telemetry:

```powershell
cd C:\OneWayGuard
.\OneWayGuard.exe
```

### 3. Accessing via Browser
If your system blocks the desktop app window or you prefer interacting via your browser:
1. Ensure `OneWayGuard.exe` is running.
2. Open your preferred browser and navigate to:
   ```text
   http://127.0.0.1:8000
   ```
3. Interactive API documentation is available at:
   ```text
   http://127.0.0.1:8000/docs
   ```

---

## 🧪 Quick Start Guide (Testing with Included Sample)

Follow these steps to run your first forensic analysis within 2 minutes:

1. **Start the Application**: Double-click `OneWayGuard.exe`.
2. **Select PCAP File**: In the dashboard, click **Browse / Upload PCAP**.
3. **Choose Test Capture**: Navigate to the bundled `sample_pcaps` folder inside the OneWayGuard directory and select:
   ```text
   sample_pcaps/sample_threat_traffic.pcap
   ```
4. **Configure Parameters**:
   - **Model**: Default hardened XGBoost classifier (`hardened_binary_xgb`).
   - **Threshold**: Set confidence sensitivity (default `0.50`).
   - **Packet Limit**: Leave empty for full capture analysis, or enter `1000` for a fast preview.
5. **Analyze Capture**: Click **Analyze Capture**.
   - Watch real-time flow reconstruction, packet metrics, and Kalman anomaly scoring.
   - Threat alerts will populate with severity classifications, confidence ratings, and behavioral evidence.
6. **Export Defense-Grade Report**:
   - Click **Generate DOCX Report** or **Generate PDF Report**.
   - Reports are automatically compiled with executive summaries, SHA-256 integrity hashes, flow logs, and mitigation recommendations.
   - Access the exported files directly in the `reports/` folder.

---

## 📡 Live Capture Mode (Optional Setup)

If you plan to use OneWayGuard for live wire monitoring:

1. **Install Npcap**:
   - Download the installer from [https://npcap.com/](https://npcap.com/).
   - During installation, check the box: **"Install Npcap in WinPcap API-compatible Mode"**.
2. **Launch as Administrator**:
   - Right-click `OneWayGuard.exe` and select **Run as Administrator** (required by Windows to access raw network interface drivers).
3. **Select Interface**:
   - In the dashboard, switch to the **Live Capture** tab.
   - Choose your monitored network interface from the dropdown and click **Start Monitoring**.

---

## ❓ Troubleshooting & FAQs

### Q1: Windows SmartScreen shows "Windows protected your PC"
- **Cause**: Windows Defender SmartScreen automatically flags newly downloaded binaries or files transferred from external USB drives that lack cloud download reputation ("Mark of the Web").
- **Permanent Solution (1-Click Trust)**:
  - Right-click `INSTALL_SECURITY_CERTIFICATE.bat` and select **Run as Administrator**.
  - This registers the genuine **OneWayGuard Defense Forensics** certificate into your Windows Trusted Root & Publisher stores, permanently removing the Defender prompt on that machine.
- **Quick Solution**:
  - Right-click `OneWayGuard-Setup-Win64.exe` (or `OneWayGuard.exe`) → **Properties** → Check **"Unblock"** at the bottom → Click **OK**.
  - Alternatively, in the SmartScreen prompt, click **More info** → **Run anyway**.

### Q2: My Antivirus flagged `OneWayGuard.exe`
- **Cause**: PyInstaller-packaged executables are occasionally flagged by aggressive heuristic scanners (generic false-positive).
- **Solution**: Whitelist `OneWayGuard.exe` or add the `OneWayGuard` installation folder to your antivirus exclusions.

### Q3: What if port 8000 is already used by another service?
- OneWayGuard automatically detects if port 8000 is occupied and cleanly binds to the next available free ephemeral port. Check the desktop window title or `onewayguard_desktop.log` to see the assigned port.

### Q4: Where are log files stored?
- If any issue occurs, an execution log is written to:
  ```text
  onewayguard_desktop.log
  ```
  in the same folder as `OneWayGuard.exe`. Review this file for detailed diagnostic messages.

### Q5: How do I exit the application?
- Simply close the OneWayGuard desktop window. The background web service and detection workers will automatically terminate cleanly.

---

## 🛡️ Architecture & Security Principles

```text
       UNIDIRECTIONAL / TAP FEED
                   │
                   ▼
┌──────────────────────────────────────┐
│       [1] Ingestion & Parser         │  ◄── IPv4 Flow Reconstruction (Zero-Transmit)
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│    [2] Metadata Feature Extractor    │  ◄── No Payload Decryption / Privacy Safe
└──────────┬────────────────┬──────────┘
           │                │
           ▼                ▼
┌────────────────────┐ ┌────────────────────────┐
│ [3] Kalman Filter  │ │ [4] ML Threat Models   │
│  Streaming Anomaly │ │  XGBoost Flow Analysis │
└──────────┬─────────┘ └───────────┬────────────┘
           │                       │
           └───────────┬───────────┘
                       ▼
┌──────────────────────────────────────┐
│      [5] Scoring & Alert Fusion      │  ◄── Multi-Signal Confidence Fusion
└──────────────────┬───────────────────┘
                   ▼
┌──────────────────────────────────────┐
│    [6] Standalone UI & Reporting     │  ◄── PDF / DOCX 5-Page Forensic Export
└──────────────────────────────────────┘
```

- **Strictly Passive**: OneWayGuard is designed for passive monitoring only. It has zero transmission capability over monitored interfaces, making it immune to active discovery and fully compliant with air-gapped network policies.
- **Privacy Preserving**: Operates solely on metadata (packet timing, packet size distribution, port entropy, protocol headers). Payload contents are never decrypted or retained.

---

## 📄 License & Attribution

Developed for passive network security monitoring and forensic investigation.  
All models, heuristics, and user interface components are bundled within this standalone release.
