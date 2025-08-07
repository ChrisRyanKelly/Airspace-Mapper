**Map and analyse wireless airspace for Red Team operations with geolocation, signal strength, and vendor enrichment. Inspired by CyberArk’s WPA-scale reconnaissance strategy.**

## Overview

This project builds on [CyberArk’s “Cracking WiFi at Scale with One Simple Trick”](https://www.cyberark.com/resources/threat-research-blog/cracking-wifi-at-scale-with-one-simple-trick), which showed how WPA handshake metadata (like SSID patterns and MAC prefixes) can prioritise cracking at scale.

While their research focused on large-scale password recovery, this tool addresses a complementary challenge:

> **How do we enrich raw WPA handshake captures with GPS data, vendor metadata, and signal strength to make them actionable for Red Team operations?**

---

## Use Case

This toolkit is designed for:

- Red Teamers performing passive WiFi reconnaissance  
- Security researchers mapping wireless attack surfaces  
- Operators preparing cracking queues and prioritising weak/default configurations  
- Analysts geolocating and tracking wireless infrastructure for physical access planning  

---

## Features

- Parse `.22000` WPA handshake files  
- Perform MAC OUI → vendor enrichment via CSV  
- Correlate APs with signal strength from `.tsv` logs  
- Optionally map GPS coordinates using `.gpx` waypoints or tracks  
- Output structured JSON and GPX for geospatial analysis  
- De-duplicate targets and normalize metadata  

---

## Quick Start

### Requirements

- Python 3.8+  
- `oui.csv` – CSV-formatted MAC-to-vendor lookup (e.g., from IEEE or public datasets)  
- WPA handshake file in `.22000` format  
- Signal log `.tsv` file (timestamp, signal strength, MAC)  
- Optional: GPS track log in `.gpx` format (e.g., from Kismet or mobile app)

### Run the Tool

```bash
python3 airspace_map.py handshakes.22000 signal_log.tsv gps_track.gpx --export-gpx
```

### Output

- `airspace_analysis_YYYYMMDD_HHMMSS.json`
    
- `waypoints_YYYYMMDD_HHMMSS.gpx` (optional)

---
## What This Enables

### Parsing Logic

- Parses `WPA*02*...` formatted hash lines from `.22000` files
    
- Extracts AP MAC and SSID (decoded from hex)

### Signal Mapping

- Matches MACs from `.tsv` logs and pulls the strongest signal seen
    
- Uses this to infer proximity or target priority

### GPS Matching

- Matches GPX timestamps to `.tsv` timestamps
    
- Correlates MAC → GPS location (within ±5 mins)
    
- Outputs waypoints for compatible mapping tools

### Vendor Lookup

- Reads `oui.csv` with MAC prefix → vendor mapping
    
- Cleans vendor names and falls back to `"Unknown"` if not found

---

### Sample Output

```json
{
  "ssid": "BT-9TCJM9",
  "ap_mac": "709741657c77",
  "vendor": "Arcadyan Corporation",
  "signal": -59,
  "hash_line": "WPA*02*...",
  "latitude": 53.273347,
  "longitude": -3.263293
}
```
 
---
### Capabilities Summary

|Capability|Description|
|---|---|
|🔐 **WPA cracking triage**|Prioritise by signal strength and SSID naming conventions|
|🏭 **Vendor fingerprinting**|Identify vulnerable routers using OUI tags (e.g., Arcadyan, TP-Link)|
|📍 **Geolocation**|Map APs in physical space for Red Team ops or surveillance|
|🧰 **Toolchain integration**|Bridge to tools like `RouterSploit` or `cvemap` using vendor/device data|
|🗂️ **Recon intelligence**|Build structured profiles of devices for tracking or future targeting|

## Strategic Impact

This tool supports the **first phase** of Red Team operations: Reconnaissance.

Once you've built a dataset of geolocated, vendor-enriched wireless targets, you can:

- Use tools like `RouterSploit` to scan for known vulnerabilities
    
- Feed vendors into [cvemap](https://github.com/projectdiscovery/cvemap) to identify matching CVEs
    
- Attempt WPA password cracking only on high-priority candidates (e.g., known-vulnerable vendors, strong signal, default SSID patterns)

> **Example:** A `BT-Hub` router using a default SSID and manufactured by Arcadyan might be running vulnerable firmware exploitable via UPnP or telnet injection.

---

## Next Steps

### Planned Enhancements

- WPA hash cracking via local `hashcat` or cloud API integration
    
- CVE matching via `cvemap` or NIST CVE feeds
    
- Visual heatmaps or clustering by signal/vendor
    
- Vendor → router model mapping (e.g., TP-Link + MAC = Archer C5)

---

## References

- [CyberArk – “Cracking WiFi at Scale with One Simple Trick”](https://www.cyberark.com/resources/threat-research-blog/cracking-wifi-at-scale-with-one-simple-trick)
    
- [cvemap by ProjectDiscovery](https://github.com/projectdiscovery/cvemap)
    
- [RouterSploit](https://github.com/threat9/routersploit)
    
- IEEE OUI Lookup Tool

---

### License

MIT — open too modification, adaptation and deployment by other researchers or tool devs who think they may be able to enhance or improve this project.

### Questions?

Open an issue, fork the repo, or reach out via GitHub Discussions.
