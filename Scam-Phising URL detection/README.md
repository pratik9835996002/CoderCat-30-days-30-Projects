# URL Safety Checker

A Flask-based web application that checks whether a URL is safe or potentially malicious using the VirusTotal API v3.

Users can paste any URL into the web interface, and the backend scans it through VirusTotal to analyze security threats such as phishing, malware, or suspicious behavior.

---

# Features

- Scan URLs using VirusTotal API v3
- Clean dark-themed dashboard
- Large security verdict display:
  - SAFE
  - SUSPICIOUS
  - DANGEROUS
- Shows:
  - Number of security engines that flagged the URL
  - Malicious vs clean progress bar
  - Checked URL
  - Detected threat categories
- Handles API and URL errors gracefully

---

# Tech Stack

- Python
- Flask
- Requests
- HTML/CSS
- VirusTotal API v3(public)

---

