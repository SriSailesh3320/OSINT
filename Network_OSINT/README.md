# Network-Based OSINT Investigation Tool

## Overview
This tool performs comprehensive OSINT (Open Source Intelligence) on network targets. It gathers DNS, WHOIS, geolocation, threat intelligence, and port scanning data using multiple Python libraries.

## Libraries Used and Their Purpose

### 1. socket
**Purpose:** Native Python module for network communication and IP/domain resolution.
- Functions: `socket.socket()`, `socket.inet_aton()`, `socket.gethostbyname()`, `socket.gethostbyaddr()`, `socket.connect_ex()`, `socket.getservbyport()`
- **Snippet:**
```python
import socket
ip = socket.gethostbyname('example.com')
hostname = socket.gethostbyaddr(ip)[0]
```
*Explained:* Resolves a domain to IP and finds its reverse DNS name.

---
### 2. json
**Purpose:** Standard module for serializing data to/from JSON format.
- Functions: `json.dump()`, `json.load()`, `json.loads()`, `json.dumps()`
- **Snippet:**
```python
import json
data = {"key": "value"}
with open('output.json', 'w') as f:
    json.dump(data, f, indent=4)
```
*Explained:* Saves a dictionary to a JSON file for integration/export.

---
### 3. csv
**Purpose:** Standard Python module for reading/writing CSV files.
- Functions: `csv.writer()`, `writer.writerow()`
- **Snippet:**
```python
import csv
with open('data.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['field1', 'field2'])
    writer.writerow([1, 2])
```
*Explained:* Saves key-value pairs in tabular CSV format, easy for data analysis.

---
### 4. requests
**Purpose:** Powerful HTTP library for making API calls, e.g., VirusTotal, ip-api.com.
- Functions: `requests.get()`, response object methods
- **Snippet:**
```python
import requests
resp = requests.get('https://ip-api.com/json/8.8.8.8')
if resp.status_code == 200:
    data = resp.json()
```
*Explained:* Fetches geolocation data for the target IP via HTTP API.

---
### 5. datetime
**Purpose:** Built-in module for handling timestamps.
- Functions: `datetime.now()`, `datetime.isoformat()`
- **Snippet:**
```python
from datetime import datetime
ts = datetime.now().isoformat()
```
*Explained:* Used to timestamp the investigation's results.

---
### 6. time
**Purpose:** Provides time-related functions (rate limiting during port scanning).
- Functions: `time.sleep()`
- **Snippet:**
```python
import time
time.sleep(0.1)
```
*Explained:* Adds delay between port scans for stealth and reliability.

---
### 7. ipwhois
**Purpose:** Retrieves WHOIS/ASN info for IP addresses (network owner, country, org).
- Functions: `IPWhois(ip)`, `.lookup_rdap()`
- **Snippet:**
```python
from ipwhois import IPWhois
obj = IPWhois('8.8.8.8')
info = obj.lookup_rdap()
print(info['asn'], info['asn_description'])
```
*Explained:* Extracts detailed network owner/registry data.

---
### 8. python-dotenv
**Purpose:** Loads secrets/config from a `.env` file, e.g., API keys.
- Functions: `load_dotenv()`, `os.getenv()`
- **Snippet:**
```python
from dotenv import load_dotenv
import os
load_dotenv()
api_key = os.getenv("VIRUSTOTAL_API_KEY")
```
*Explained:* Keeps your API keys outside of code for security and versatility.

---
### 9. os
**Purpose:** Accesses system environment variables and file system for basic ops.
- Functions: `os.getenv()`
- **Used with python-dotenv, see above**

---
### 10. folium
**Purpose:** Generates interactive geographic maps using Leaflet.js.
- Functions: `folium.Map()`, `folium.Marker()`, `folium.Circle()`, `.add_to()`, `.save()`
- **Snippet:**
```python
import folium
m = folium.Map(location=[37.7749, -122.4194], zoom_start=13)
folium.Marker(location=[37.7749, -122.4194], popup='San Francisco').add_to(m)
m.save('map.html')
```
*Explained:* Visualizes the target's location on a map with popups and overlays.

---

## Quickstart Installation
1. Install Python (>=3.8 recommended).
2. Install dependencies:
    ```bash
    pip install requests ipwhois python-dotenv folium
    ```
3. Create a `.env` file with your VirusTotal API key:
    ```
    VIRUSTOTAL_API_KEY=your_key_here
    ```
4. Run the tool:
    ```bash
    python network_osint.py
    ```

---

## Output
- `osint_results.json`: Full investigation results in JSON format.
- `osint_results.csv`: Tabular data for Excel/analysis.
- `osint_map.html`: Interactive report for geolocation and investigation results.

---

## Troubleshooting
- Install missing modules with pip as above if ImportError occurs.
- Network services may block requests, use public/known test domains/IPs.
- Ensure your .env file is secure; never commit it to public repositories.

---

## Legal and Ethics Notice
- Use only on permitted and owned resources!
- Port scanning/reporting geolocation sometimes triggers alerts or is regulated.

---

## Reference Links
- Python socket: https://docs.python.org/3/library/socket.html
- Requests: https://requests.readthedocs.io
- IPWhois Docs: https://ipwhois.readthedocs.io
- Folium Docs: https://python-visualization.github.io/folium
- python-dotenv: https://pypi.org/project/python-dotenv/
- VirusTotal API: https://developers.virustotal.com/reference

