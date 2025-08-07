#!/usr/bin/env python3
"""
WiFi Analysis Tool with GPS Correlation

Analyzes WiFi hash files (.22000 format) and correlates them with signal strength
data and GPS tracks to create comprehensive network maps and reports.

Features:
- Parse WiFi hashes and extract network information
- Correlate with signal strength and GPS location data
- Generate JSON reports and GPX waypoints
- OUI database lookup for device vendor identification
"""

import sys
import os
import json
import csv
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, Tuple

@dataclass
class ThreatTarget:
    """WiFi access point with signal strength, vendor, and optional GPS data."""
    ssid: str
    ap_mac: str
    vendor: str
    hash_line: str
    signal: int = -100  # Signal strength in dBm
    location: Optional[Tuple[float, float]] = None  # GPS coordinates if available


class SimplifiedAnalyzer:
    """
    Analyzes WiFi hash files and correlates them with signal strength and GPS data.
    
    Parses .22000 hash files, matches them with signal data from TSV files,
    and optionally correlates with GPS tracks for geolocation mapping.
    """
    
    def __init__(self, hash_file, tsv_file, gps_file=None, oui_file="oui.csv"):
        """
        Initialize the analyzer with input file paths and load OUI database.
        
        Args:
            hash_file (str): Path to WiFi hash file containing network hashes
            tsv_file (str): Path to TSV file with timestamp, signal, MAC data
            gps_file (str, optional): Path to GPX file with GPS tracking data
            oui_file (str): Path to CSV file containing OUI-to-vendor mappings
        """
        # Store file paths for later processing
        self.hash_file = hash_file
        self.tsv_file = tsv_file
        self.gps_file = gps_file
        self.oui_file = oui_file
        
        # Load OUI database for vendor identification
        # This is done at initialization for efficiency during analysis
        self.oui_database = self._load_oui_database()
        print(f"[+] Loaded {len(self.oui_database)} OUI entries")

    def analyze_targets(self):
        """
        Parse hash file and correlate with signal strength and GPS data.
        
        Returns list of ThreatTarget objects with complete metadata.
        """
        print("[*] Analyzing targets...")
        
        # Dictionary to store unique targets (prevents duplicates)
        targets = {}
        
        # Pre-load auxiliary data to avoid repeated file I/O during main loop
        signal_data = self._load_signal_data()  # MAC -> signal strength mapping
        gps_data = self._load_gps_data()      # MAC -> GPS coordinates mapping
        
        # Process hash file line by line
        with open(self.hash_file, 'r') as f:
            for line in f:
                line = line.strip()
                
                # Skip empty lines and non-hash lines
                if not line or '*' not in line:
                    continue
                
                # Parse hash format: $HCC$*type*salt*ap_mac*client_mac*ssid_hex*hash*
                parts = line.split('*')
                if len(parts) < 6:
                    continue  # Malformed hash line
                
                # Extract essential components from hash line
                hash_type, ap_mac, ssid_hex, hash_line = parts[1], parts[3].lower(), parts[5], line
                
                # Decode SSID from hexadecimal representation
                try:
                    ssid = bytes.fromhex(ssid_hex).decode('utf-8', errors='ignore')
                except:
                    continue  # Skip if SSID can't be decoded
                
                # Create unique identifier to prevent duplicate processing
                target_id = f"{ssid}_{ap_mac}"
                if target_id in targets:
                    continue  # Skip duplicates
                
                # Perform vendor lookup using first 6 characters of MAC (OUI)
                mac_prefix = ap_mac.replace(":", "")[:6].upper()
                vendor = self.oui_database.get(mac_prefix, "Unknown")
                
                # Correlate with signal strength data
                mac_clean = ap_mac.replace(":", "")  # Remove colons for lookup
                signal = signal_data.get(mac_clean, -100)  # Default to weak signal
                
                # Correlate with GPS location data if available
                location = gps_data.get(mac_clean, None)

                # Create comprehensive target profile
                targets[target_id] = ThreatTarget(
                    ssid=ssid,
                    ap_mac=ap_mac,
                    vendor=vendor,
                    hash_line=hash_line,
                    signal=signal,
                    location=location
                )
        
        return list(targets.values())
    
    def _load_oui_database(self):
        """Load OUI database for MAC address to vendor mapping."""
        oui_db = {}
        
        # Check if OUI file exists before attempting to load
        if not os.path.exists(self.oui_file):
            print(f"[!] OUI file {self.oui_file} not found, using limited database")
            return oui_db
        
        try:
            with open(self.oui_file, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    # Normalize prefix to uppercase for consistent lookup
                    prefix = row['prefix'].upper()
                    # Clean vendor name (remove quotes, take last part after tabs)
                    vendor = row['vendor'].strip('"').split('\t')[-1]
                    oui_db[prefix] = vendor
        except Exception as e:
            print(f"[!] Error loading OUI database: {e}")
        
        return oui_db

    def _load_signal_data(self):
        """
        Pre-load signal strength data from TSV file for efficient lookups.
        
        Expected TSV format: timestamp\tsignal_strength\tmac_address
        Creates a mapping from MAC addresses to signal strength values.
        
        Returns:
            dict: Mapping of MAC addresses (no colons) to signal strength (dBm)
        """
        signal_map = {}
        try:
            with open(self.tsv_file, 'r') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    # Ensure we have at least timestamp, signal, MAC columns
                    if len(parts) >= 3:
                        # Store MAC without colons as key, signal strength as value
                        mac_clean = parts[2].lower().replace(":", "")
                        signal_map[mac_clean] = int(parts[1])
        except Exception:
            # Silently fail and return empty map if TSV can't be loaded
            pass
        return signal_map
    
    def _load_gps_data(self):
        """
        Load and correlate GPS data from GPX file with WiFi detection timestamps.
        
        This complex method performs temporal correlation between GPS track points
        and WiFi detection times to assign geographic coordinates to detected
        access points. It handles both GPX tracks and waypoints.
        
        Returns:
            dict: Mapping of MAC addresses to GPS coordinate dictionaries
        """
        gps_map = {}
        
        # Return empty map if no GPS file provided or file doesn't exist
        if not self.gps_file or not os.path.exists(self.gps_file):
            return gps_map
        
        try:
            # Parse GPX file
            tree = ET.parse(self.gps_file)
            root = tree.getroot()
            
            # GPX namespace
            ns = {'gpx': 'http://www.topografix.com/GPX/1/1'}
            
            # Find all track points or waypoints
            track_points = []
            
            # Look for track points in tracks
            for trk in root.findall('.//gpx:trk', ns):
                for trkseg in trk.findall('.//gpx:trkseg', ns):
                    for trkpt in trkseg.findall('.//gpx:trkpt', ns):
                        lat = float(trkpt.get('lat'))
                        lon = float(trkpt.get('lon'))
                        time_elem = trkpt.find('gpx:time', ns)
                        timestamp = time_elem.text if time_elem is not None else None
                        
                        if timestamp:
                            # Convert ISO timestamp to Unix timestamp for correlation
                            try:
                                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                                unix_timestamp = dt.timestamp()
                                track_points.append({
                                    'latitude': lat,
                                    'longitude': lon,
                                    'timestamp': timestamp,
                                    'unix_timestamp': unix_timestamp
                                })
                            except:
                                continue
            
            # Look for waypoints if no track points found
            if not track_points:
                for wpt in root.findall('.//gpx:wpt', ns):
                    lat = float(wpt.get('lat'))
                    lon = float(wpt.get('lon'))
                    time_elem = wpt.find('gpx:time', ns)
                    timestamp = time_elem.text if time_elem is not None else None
                    
                    if timestamp:
                        try:
                            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                            unix_timestamp = dt.timestamp()
                            track_points.append({
                                'latitude': lat,
                                'longitude': lon,
                                'timestamp': timestamp,
                                'unix_timestamp': unix_timestamp
                            })
                        except:
                            continue
            
            print(f"[+] Loaded {len(track_points)} GPS points from GPX file")
            
            # Create timestamp-based mapping with TSV data
            if track_points:
                self.track_points = sorted(track_points, key=lambda x: x['unix_timestamp'])
                # Load TSV timestamp data for correlation
                tsv_timestamps = self._load_tsv_timestamps()
                
                # Create GPS mapping based on temporal proximity
                for mac, tsv_timestamp in tsv_timestamps.items():
                    closest_gps = self._find_closest_gps_point(tsv_timestamp, self.track_points)
                    if closest_gps:
                        gps_map[mac] = closest_gps
            
        except Exception as e:
            print(f"[!] Error loading GPX data: {e}")
            self.gps_fallback_data = None
        
        return gps_map
    
    def _load_tsv_timestamps(self):
        """
        Extract timestamps from TSV file for temporal correlation with GPS data.
        
        Parses the TSV file to extract the earliest timestamp for each MAC address,
        which will be used to correlate WiFi detections with GPS track points.
        
        Returns:
            dict: Mapping of MAC addresses to earliest detection timestamps
        """
        timestamps = {}
        try:
            with open(self.tsv_file, 'r') as f:
                for line in f:
                    parts = line.strip().split('\t')
                    if len(parts) >= 3:
                        timestamp = float(parts[0])  # Unix timestamp
                        mac = parts[2].lower().replace(":", "")  # Normalize MAC format
                        
                        # Keep the earliest timestamp for each MAC address
                        # This represents the first time we detected this AP
                        if mac not in timestamps or timestamp < timestamps[mac]:
                            timestamps[mac] = timestamp
        except Exception as e:
            print(f"[!] Error loading TSV timestamps: {e}")
        return timestamps
    
    def _find_closest_gps_point(self, target_timestamp, track_points):
        """
        Find GPS point with timestamp closest to the target detection time.
        
        Uses linear search to find the GPS track point with the smallest
        temporal difference from the WiFi detection timestamp. Only returns
        a match if within a reasonable time window (5 minutes).
        
        Args:
            target_timestamp (float): Unix timestamp of WiFi detection
            track_points (list): List of GPS points with timestamps
        
        Returns:
            dict: GPS point data if found within time window, None otherwise
        """
        if not track_points:
            return None
        
        closest_point = None
        min_time_diff = float('inf')
        
        # Linear search for closest temporal match
        for point in track_points:
            time_diff = abs(point['unix_timestamp'] - target_timestamp)
            if time_diff < min_time_diff:
                min_time_diff = time_diff
                closest_point = point
        
        # Only return GPS data if it's within a reasonable time window
        # 300 seconds (5 minutes) allows for minor timing discrepancies
        if min_time_diff <= 300:
            return closest_point
        return None
    
    
    
    
    
    
    
    def generate_report(self, targets):
        """
        Generate comprehensive JSON report of analyzed WiFi targets.
        
        Creates a structured JSON report containing all discovered WiFi networks
        with their associated metadata including vendor information, signal strength,
        GPS coordinates, and original hash data. The report is automatically
        saved with a timestamp-based filename.
        
        Args:
            targets (list[ThreatTarget]): List of analyzed WiFi targets
            
        Returns:
            dict: Complete analysis report data structure
        """
        print("[*] Generating report...")
        
        # Build comprehensive report structure
        report = {
            "timestamp": datetime.now().isoformat(),  # Analysis timestamp
            "total_analyzed": len(targets),           # Summary count
            "targets": [  # Individual target details
                {
                    "ssid": t.ssid,
                    "ap_mac": t.ap_mac,
                    "vendor": t.vendor,
                    "signal": t.signal,
                    "hash_line": t.hash_line,  # Original hash for reference
                    # Extract GPS coordinates if available, otherwise null
                    "latitude": t.location["latitude"] if t.location else None,
                    "longitude": t.location["longitude"] if t.location else None
                } for t in targets
            ]
        }
        
        # Auto-save with timestamped filename to prevent overwrites
        filename = f"airspace_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(report, f, indent=2)  # Pretty-formatted JSON
        
        print(f"[+] Analysis complete: {filename}")
        return report
    
    def export_gpx(self, targets, filename=None):
        """
        Export WiFi targets with GPS coordinates as GPX waypoints.
        
        Creates a GPX (GPS Exchange Format) file containing waypoints for each
        WiFi target that has associated GPS coordinates. This format is compatible
        with most mapping applications including Google Earth, QGIS, and GPS devices.
        
        Args:
            targets (list[ThreatTarget]): List of analyzed WiFi targets
            filename (str, optional): Custom filename for GPX export
            
        Returns:
            str: Filename of the generated GPX file
        """
        # Generate default filename if none provided
        if not filename:
            filename = f"waypoints_{datetime.now().strftime('%Y%m%d')}.gpx"
        
        print(f"[*] Exporting waypoints to {filename}...")
        
        # Create GPX XML structure with proper namespace declarations
        gpx = ET.Element("gpx", version="1.1", creator="WiFi-Analysis-Tool")
        gpx.set("xmlns", "http://www.topografix.com/GPX/1/1")
        gpx.set("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
        gpx.set("xsi:schemaLocation", "http://www.topografix.com/GPX/1/1 http://www.topografix.com/GPX/1/1/gpx.xsd")
        
        # Add GPX metadata section
        metadata = ET.SubElement(gpx, "metadata")
        name = ET.SubElement(metadata, "name")
        name.text = "WiFi Analysis Waypoints"
        desc = ET.SubElement(metadata, "desc")
        desc.text = f"WiFi networks analyzed on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        time_elem = ET.SubElement(metadata, "time")
        time_elem.text = datetime.now().isoformat() + "Z"
        
        # Process each target and create waypoints for those with GPS data
        waypoint_count = 0
        for target in targets:
            if target.location:  # Only export targets with GPS coordinates
                # Create waypoint element with lat/lon attributes
                wpt = ET.SubElement(gpx, "wpt", 
                                   lat=str(target.location["latitude"]), 
                                   lon=str(target.location["longitude"]))
                
                # Add waypoint name (SSID)
                name = ET.SubElement(wpt, "name")
                name.text = target.ssid
                
                # Add detailed description with network information
                desc = ET.SubElement(wpt, "desc")
                desc.text = (f"SSID: {target.ssid}\n"
                           f"MAC: {target.ap_mac}\n"
                           f"Vendor: {target.vendor}\n"
                           f"Signal: {target.signal} dBm")
                
                # Add waypoint symbol for mapping applications
                sym = ET.SubElement(wpt, "sym")
                sym.text = "Waypoint"
                
                # Add original GPS timestamp if available
                if target.location.get("timestamp"):
                    time_elem = ET.SubElement(wpt, "time")
                    time_elem.text = target.location["timestamp"]
                
                waypoint_count += 1
        
        # Write GPX file with proper formatting
        tree = ET.ElementTree(gpx)
        ET.indent(tree, space="  ", level=0)  # Pretty formatting for readability
        tree.write(filename, encoding="utf-8", xml_declaration=True)
        
        print(f"[+] Exported {waypoint_count} waypoints to {filename}")
        print(f"    Compatible with Google Earth, QGIS, and other mapping tools")
        return filename


def main():
    """Main entry point - handles CLI args and orchestrates analysis workflow."""
    
    # Validate minimum required arguments
    if len(sys.argv) < 3:
        # Display usage information and exit
        print("WiFi Analysis Tool")
        print("Features: Device Fingerprinting | GPS Correlation")
        print()
        print("Usage: python3 airspace_map.py <hash_file.22000> <tsv_file> [GPS_data.gpx] [--export-gpx]")
        print("\nRequired files:")
        print("  • oui.csv - OUI database for vendor identification")
        print("\nOptional:")
        print("  • GPS_data.gpx - GPX format GPS track file for geolocation")
        print("  • --export-gpx - Export waypoints to GPX format")
        sys.exit(1)
    
    # Parse command-line arguments with flexible ordering
    hash_file, tsv_file = sys.argv[1], sys.argv[2]  # Required arguments
    gps_file = None      # Optional GPS file path
    export_gpx = False   # Optional GPX export flag
    
    # Process remaining optional arguments
    for i, arg in enumerate(sys.argv[3:], 3):
        if arg == "--export-gpx":
            export_gpx = True
        elif not arg.startswith("--") and gps_file is None:
            # First non-flag argument is assumed to be GPS file
            gps_file = arg
    
    # Validate that required input files exist before proceeding
    if not os.path.exists(hash_file) or not os.path.exists(tsv_file):
        print("[!] Required files not found")
        sys.exit(1)
    
    # Display tool header and configuration
    print("WiFi Analysis Tool")
    print("Simple WiFi Network Analysis with GPS")
    print()
    
    try:
        # Initialize analyzer with validated input files
        analyzer = SimplifiedAnalyzer(hash_file, tsv_file, gps_file)
        
        # Perform comprehensive WiFi network analysis
        targets = analyzer.analyze_targets()
        
        # Generate primary JSON analysis report
        report = analyzer.generate_report(targets)
        
        # Export GPX waypoints if requested by user
        if export_gpx:
            print()  # Add spacing for readability
            gpx_file = analyzer.export_gpx(targets)
        
        # Display comprehensive analysis summary
        print("\nAnalysis Complete")
        print(f"   Targets Analyzed: {len(targets)}")
        print(f"   JSON Report: airspace_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        if export_gpx:
            print(f"   GPX Export: {gpx_file}")
        print(f"   OUI Database: {len(analyzer.oui_database)} entries")
        
    except KeyboardInterrupt:
        # Handle graceful shutdown on user interrupt (Ctrl+C)
        print("\n[!] Analysis interrupted by user")
        sys.exit(1)
    except Exception as e:
        # Handle any unexpected errors with informative message
        print(f"[!] Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
