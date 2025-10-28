import socket
import json
import csv
import requests
from datetime import datetime
import time
from ipwhois import IPWhois
from dotenv import load_dotenv
import os
import folium

load_dotenv()  # Load environment variables from .env file
api_key = os.getenv("VIRUSTOTAL_API_KEY")  # Your VirusTotal API key

class NetworkOSINT:
    def __init__(self, target):
        self.target = target
        self.results = {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "basic_info": {},
            "geolocation": {},
            "threat_intel": {},
            "whois_info": {},
            "ports": []
        }

    def resolve_target(self):
        """Resolve domain to IP or validate IP address"""
        try:
            socket.inet_aton(self.target)
            ip = self.target
            print(f"[+] Valid IP address: {ip}")
        except socket.error:
            try:
                ip = socket.gethostbyname(self.target)
                print(f"[+] Resolved {self.target} to {ip}")
            except socket.gaierror as e:
                print(f"[-] DNS resolution failed: {e}")
                return None
                
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            print(f"[+] Reverse DNS: {hostname}")
            self.results["basic_info"]["hostname"] = hostname
        except socket.herror:
            print("[-] Reverse DNS lookup failed")
            self.results["basic_info"]["hostname"] = "N/A"
            
        self.results["basic_info"]["ip"] = ip
        return ip

    def get_whois_info(self, ip):
        """Retrieve WHOIS info including ASN and organization"""
        try:
            print("[*] Querying WHOIS information...")
            obj = IPWhois(ip)
            results = obj.lookup_rdap(depth=1)
            
            self.results["whois_info"] = {
                "asn": results.get("asn", "N/A"),
                "asn_description": results.get("asn_description", "N/A"),
                "asn_country": results.get("asn_country_code", "N/A"),
                "network": results.get("network", {}).get("cidr", "N/A"),
                "organization": results.get("network", {}).get("name", "N/A")
            }
            print(f"[+] ASN: {self.results['whois_info']['asn']}")
            print(f"[+] Organization: {self.results['whois_info']['organization']}")
        except Exception as e:
            print(f"[-] WHOIS lookup failed: {e}")
            self.results["whois_info"] = {"error": str(e)}

    def get_geolocation(self, ip):
        """Fallback geolocation using ip-api.com"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    self.results["geolocation"] = {
                        "country": data.get("country", "N/A"),
                        "country_code": data.get("countryCode", "N/A"),
                        "city": data.get("city", "N/A"),
                        "latitude": data.get("lat", 0),
                        "longitude": data.get("lon", 0),
                        "timezone": data.get("timezone", "N/A"),
                        "isp": data.get("isp", "N/A"),
                        "org": data.get("org", "N/A")
                    }
                    print(f"[+] Location (API): {data.get('city')}, {data.get('country')}")
        except Exception as e:
            print(f"[-] API geolocation failed: {e}")
            self.results["geolocation"] = {"error": str(e)}

    def get_threat_intelligence(self, ip, api_key=None):
        """Query threat intelligence using VirusTotal API"""
        if not api_key:
            print("[-] VirusTotal API key not provided. Skipping threat intel check.")
            self.results["threat_intel"] = {"error": "No API key provided"}
            return
        try:
            print("[*] Querying VirusTotal threat intelligence...")
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
            response = requests.get(url, headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                self.results["threat_intel"] = {
                    "reputation": attributes.get("reputation", 0),
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "as_owner": attributes.get("as_owner", "N/A"),
                    "country": attributes.get("country", "N/A")
                }
                print(f"[+] Reputation: {self.results['threat_intel']['reputation']}")
                print(f"[+] Malicious detections: {stats.get('malicious', 0)}")
            elif response.status_code == 404:
                print("[-] IP not found in VirusTotal database")
                self.results["threat_intel"] = {"error": "IP not found"}
            else:
                print(f"[-] VirusTotal API error: {response.status_code}")
                self.results["threat_intel"] = {"error": f"HTTP {response.status_code}"}
        except Exception as e:
            print(f"[-] VirusTotal request failed: {e}")
            self.results["threat_intel"] = {"error": str(e)}

    def scan_common_ports(self, ip, ports=[80, 443, 22, 21, 25, 53, 110, 3306, 8080]):
        """Scan common ports on the target"""
        print(f"[*] Scanning {len(ports)} common ports...")
        open_ports = []
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((ip, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "unknown"
                open_ports.append({"port": port, "service": service, "state": "open"})
                print(f"[+] Port {port} ({service}) is OPEN")
            sock.close()
            time.sleep(0.1)  # Rate limiting
        self.results["ports"] = open_ports
        print(f"[+] Found {len(open_ports)} open ports")

    def generate_map(self, output_file="osint_map.html"):
        """Generate interactive map using Folium"""
        try:
            geo = self.results.get("geolocation", {})
            if not geo or "error" in geo:
                print("[-] Cannot generate map without geolocation data")
                return
            lat = geo.get("latitude", 0)
            lon = geo.get("longitude", 0)
            if lat == 0 and lon == 0:
                print("[-] Invalid coordinates for map generation")
                return
            print(f"[*] Generating interactive map at ({lat}, {lon})...")
            m = folium.Map(location=[lat, lon], zoom_start=10)
            popup_html = f"""
            <b>Target:</b> {self.target}<br>
            <b>IP:</b> {self.results['basic_info'].get('ip', 'N/A')}<br>
            <b>Location:</b> {geo.get('city', 'N/A')}, {geo.get('country', 'N/A')}<br>
            <b>ASN:</b> {self.results['whois_info'].get('asn', 'N/A')}<br>
            <b>Organization:</b> {self.results['whois_info'].get('organization', 'N/A')}<br>
            <b>Open Ports:</b> {len(self.results.get('ports', []))}
            """
            folium.Marker(
                location=[lat, lon],
                popup=folium.Popup(popup_html, max_width=300),
                tooltip=f"{self.target}",
                icon=folium.Icon(color="red", icon="info-sign")
            ).add_to(m)
            if geo.get("accuracy_radius"):
                folium.Circle(
                    location=[lat, lon],
                    radius=geo.get("accuracy_radius") * 1000,
                    color="blue",
                    fill=True,
                    fill_opacity=0.1
                ).add_to(m)
            m.save(output_file)
            print(f"[+] Map saved to {output_file}")
        except ImportError:
            print("[-] folium library not installed. Install with: pip install folium")
        except Exception as e:
            print(f"[-] Map generation failed: {e}")

    def export_json(self, output_file="osint_results.json"):
        """Export results to JSON file"""
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            print(f"[+] JSON results saved to {output_file}")
        except Exception as e:
            print(f"[-] Failed to save JSON: {e}")

    def export_csv(self, output_file="osint_results.csv"):
        """Export results to CSV file"""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(["Category", "Field", "Value"])
                for key, value in self.results["basic_info"].items():
                    writer.writerow(["Basic Info", key, value])
                for key, value in self.results["whois_info"].items():
                    writer.writerow(["WHOIS", key, value])
                for key, value in self.results["geolocation"].items():
                    writer.writerow(["Geolocation", key, value])
                for key, value in self.results["threat_intel"].items():
                    writer.writerow(["Threat Intelligence", key, value])
                for port_info in self.results["ports"]:
                    writer.writerow(["Open Ports", port_info["port"], 
                                   f"{port_info['service']} ({port_info['state']})"])
            print(f"[+] CSV results saved to {output_file}")
        except Exception as e:
            print(f"[-] Failed to save CSV: {e}")

    def run_investigation(self, vt_api_key=None, scan_ports=True):
        print("="*60)
        print("Network-based OSINT Investigation Tool")
        print("="*60)
        print(f"Target: {self.target}\n")

        ip = self.resolve_target()
        if not ip:
            return False

        self.get_whois_info(ip)
        self.get_geolocation(ip)
        self.get_threat_intelligence(ip, vt_api_key)

        if scan_ports:
            self.scan_common_ports(ip)

        print("\n" + "="*60)
        print("Investigation Complete!")
        print("="*60)
        return True

def main():
    print("\n" + "="*60)
    print("Network-based OSINT Investigation Tool")
    print("="*60 + "\n")
    target = input("Enter IP address or domain to investigate: ").strip()
    if not target:
        print("[-] No target provided")
        return
    vt_key = api_key  # Loaded from environment variable
    if not vt_key:
        vt_key = input("Enter VirusTotal API key (press Enter to skip): ").strip() or None
    osint = NetworkOSINT(target)
    if osint.run_investigation(vt_api_key=vt_key, scan_ports=True):
        print("\n[*] Exporting results...")
        osint.export_json()
        osint.export_csv()
        osint.generate_map()
        print("\n[+] All outputs generated successfully!")
        print("    - osint_results.json")
        print("    - osint_results.csv")
        print("    - osint_map.html")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n[-] Investigation interrupted by user")
    except Exception as e:
        print(f"\n[-] Error: {e}")
