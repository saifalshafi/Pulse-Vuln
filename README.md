# PULSE - Internal Vulnerability Scanner

## Overview

PULSE is a Python-based internal vulnerability scanner developed for
controlled lab environments.\
It performs host discovery, port scanning, service identification,
misconfiguration detection, CVE correlation, and risk scoring.

------------------------------------------------------------------------

## Features

-   Single Host Scan
-   Subnet Scan (CIDR Support)
-   Multi-threaded TCP Port Scanning
-   Full Port Scan (1--65535)
-   Service & Version Detection (Banner Grabbing)
-   Misconfiguration Checks (FTP, SMB, HTTP, Telnet, Headers)
-   CVE Mapping via NVD API
-   Risk Score Calculation
-   JSON Report Export
-   Graphical Interface (PyQt5)

------------------------------------------------------------------------

## Architecture

Target Input\
→ Host Discovery\
→ Port Scanning\
→ Service Detection\
→ Misconfiguration Engine\
→ CVE Correlation\
→ Risk Engine\
→ Reporting (CLI / JSON / GUI)

------------------------------------------------------------------------

## Installation

``` bash
git clone https://github.com/khairabusir69/pulse-internal-vuln-scanner.git
cd pulse-internal-vuln-scanner

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

------------------------------------------------------------------------

## Usage

### CLI Scan

``` bash
pulse 127.0.0.1
pulse 192.168.56.0/24
pulse 127.0.0.1 --full
pulse 127.0.0.1 --json
```

### GUI

``` bash
python -m scanner_app.gui_enterprise
```

------------------------------------------------------------------------

## Sample Output

Example detection: - Open Port: 8080 - Service: Apache/2.4.49 -
CVE-2021-41773 (Critical -- 9.8) - CVE-2021-42013 (Critical -- 9.8)

------------------------------------------------------------------------

## Limitations

-   No UDP scanning
-   No authenticated scans
-   Internet required for CVE mapping
-   Banner-based service detection

------------------------------------------------------------------------

## Future Improvements

-   UDP scanning
-   OS fingerprinting
-   Local CVE database
-   Advanced fingerprinting
-   Enterprise reporting dashboard

------------------------------------------------------------------------

## Disclaimer

This tool is intended strictly for authorized internal lab environments.
Unauthorized scanning is prohibited.
