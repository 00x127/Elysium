import socket
import ipaddress
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from modules.network import NetworkScanner
from modules.service import ServiceDetector
from modules.os_detect import OSFingerprint
from modules.dns import DNSResolver

class ScannerEngine:
    def __init__(self):
        self.banner = """
        ╔══════════════════════════════════════════════╗
        ║                   ELYSIUM                    ║
        ║           Advanced Network Recon             ║
        ║                  by 0x127                    ║
        ╚══════════════════════════════════════════════╝
        """
        print(self.banner)
        self.results = {
            'scan_start': datetime.now().isoformat(),
            'target': None,
            'hosts': {}
        }
        self.net_scanner = NetworkScanner()
        self.svc_detector = ServiceDetector()
        self.os_fingerprint = OSFingerprint()
        self.dns_resolver = DNSResolver()

    def validate_host(self, target):
        try:
            ipaddress.ip_address(target)
            return target
        except:
            try:
                return socket.gethostbyname(target)
            except socket.gaierror:
                raise ValueError(f"Invalid target: {target}")

    def scan_network(self, network):
        return self.net_scanner.ping_sweep(network)

    def scan_ports(self, target, ports, grab_banner=False, check_vulns=False):
        return self.svc_detector.scan_services(target, ports, grab_banner, check_vulns)

    def detect_os(self, target, use_traceroute=False):
        return self.os_fingerprint.detect(target, use_traceroute)

    def lookup_dns(self, target):
        return self.dns_resolver.lookup(target)

    def export_results(self, filename, format='json'):
        self.results['scan_end'] = datetime.now().isoformat()

        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"[+] Results saved to {filename}")
        elif format == 'txt':
            with open(filename, 'w') as f:
                f.write("="*60 + "\n")
                f.write("ELYSIUM SCAN REPORT\n")
                f.write("="*60 + "\n\n")
                f.write(f"Scan Start: {self.results['scan_start']}\n")
                f.write(f"Scan End: {self.results['scan_end']}\n")
                f.write(f"Target: {self.results['target']}\n\n")

                for host, data in self.results['hosts'].items():
                    f.write(f"\n{'='*60}\n")
                    f.write(f"Host: {host}\n")
                    f.write(f"{'='*60}\n")

                    if 'os_info' in data:
                        f.write(f"\nOS Information:\n")
                        for key, val in data['os_info'].items():
                            f.write(f"  {key}: {val}\n")

                    if 'open_ports' in data:
                        f.write(f"\nOpen Ports ({len(data['open_ports'])}):\n")
                        for port_info in data['open_ports']:
                            f.write(f"  Port {port_info['port']}/tcp - {port_info['service']}\n")
                            if 'banner' in port_info:
                                f.write(f"    Banner: {port_info['banner'][:100]}\n")
                            if 'potential_vulns' in port_info:
                                f.write(f"    Vulnerabilities: {', '.join(port_info['potential_vulns'])}\n")

            print(f"[+] Results saved to {filename}")
