# Simple CLI Vulnerability Scanner

A Python command-line tool that scans a target for open ports,
grabs service banners, checks HTTP security headers, and generates
a vulnerability report in JSON or CSV format.

## Features
- Multithreaded TCP port scanner
- Banner grabbing and service detection
- Risky service detection (Telnet, FTP, SMB, RDP, etc.)
- Outdated software version detection
- HTTP security header checks
- Severity rating, description and mitigation for every finding
- JSON / CSV report export

## Installation
```
git clone https://github.com/YOUR-USERNAME/vuln-scanner.git
cd vuln-scanner
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

## Usage
```
python scanner.py -t <target> [-p <ports>] [-o <output file>]
```

Examples:
```
python scanner.py -t scanme.nmap.org
python scanner.py -t scanme.nmap.org -p 1-1024 -o reports/report.json
python scanner.py -t 127.0.0.1 -p 22,80,443 -o reports/report.csv
```

## Project Structure
```
scanner.py   - CLI, port scanning, banner grabbing
vulns.py     - vulnerability checks (ports, banners, HTTP headers)
report.py    - JSON / CSV report generation
reports/     - sample scan output and screenshots
```

## Disclaimer
Use this tool only on systems you own or have explicit permission
to test. Unauthorized scanning may be illegal.