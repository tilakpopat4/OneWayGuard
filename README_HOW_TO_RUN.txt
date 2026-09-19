========================================================================
             ONEWAYGUARD - PASSIVE NETWORK THREAT ANALYSIS
                      Windows Desktop Application
========================================================================

HOW TO RUN:
1. Double-click "OneWayGuard.exe" to start the application.
2. The application will launch in its own standalone desktop window.
3. No command prompt, Python installation, or external tools required!

FEATURES:
- Passive PCAP Forensics: Upload PCAP files to detect C2 beaconing,
  DGA queries, port scans, and multi-class malware signatures.
- Real-Time Kalman Signal Smoothing: Kalman anomaly bank with dynamic
  chi-square divergence thresholds.
- Defense-Grade Incident Reporting: Generates forensically formatted
  5-page threat reports in DOCX and PDF formats with chain of custody.
- Live Capture Mode: Support for passive live interface monitoring.

INCLUDED TEST DATA:
- Check the "sample_pcaps" folder inside this directory for a ready-to-test
  threat capture: "sample_threat_traffic.pcap".
- In the dashboard, simply click "Upload PCAP" and select this file to see
  immediate detections, flow metrics, and incident reporting.

EXITING THE APP:
- Simply close the OneWayGuard desktop window. The background engine will
  shut down cleanly.

REPORTS:
- Exported reports are saved in the "reports" folder inside this directory.

========================================================================
