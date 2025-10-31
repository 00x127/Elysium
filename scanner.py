#!/usr/bin/env python3

import socket
import threading
import subprocess
import platform
import argparse
import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

class ElysiumScanner:
    def __init__(self):
        self.banner = """
        ╔══════════════════════════════════════════════╗
        ║                   ELYSIUM                    ║
        ║           Advanced Network Recon             ║
        ║                  by 0x127                    ║
        ╚══════════════════════════════════════════════╝
        """
        print(self.banner)

    def validate_target(self, target):
        try:
            ipaddress.ip_address(target)
            return target
        except:
            try:
                return socket.gethostbyname(target)
            except socket.gaierror:
                raise ValueError(f"Invalid target: {target}")

    def port_scan(self, target, port, timeout=2):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                try:
                    service = socket.getservbyport(port, 'tcp')
                except:
                    service = 'unknown'
                return port, service, 'open'
        except:
            pass
        return port, None, 'closed'

    def ping_sweep(self, network):
        active_hosts = []
        network = ipaddress.ip_network(network, strict=False)

        print(f"[*] Scanning network {network}...")

        def ping_host(ip):
            param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            command = ["ping", param, str(ip)]
            try:
                output = subprocess.run(command, capture_output=True, timeout=2)
                if output.returncode == 0:
                    return str(ip)
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(ping_host, ip) for ip in network.hosts()]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    active_hosts.append(result)
                    print(f"[+] Host alive: {result}")

        return active_hosts

    def service_scan(self, target, ports):
        open_ports = []
        print(f"[*] Scanning {target} for open ports...")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=200) as executor:
            future_to_port = {executor.submit(self.port_scan, target, port): port for port in ports}

            for future in as_completed(future_to_port):
                port, service, status = future.result()
                if status == 'open':
                    open_ports.append((port, service))
                    print(f"[+] {target}:{port} - {service.upper()}")

        scan_time = time.time() - start_time
        print(f"\n[*] Scan completed in {scan_time:.2f} seconds")
        print(f"[+] Found {len(open_ports)} open ports")

        return open_ports

    def os_detection(self, target):
        print(f"[*] Performing OS detection on {target}...")
        try:
            ttl_values = {
                'Linux': 64,
                'Windows': 128,
                'Cisco': 255
            }

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, 80))
            sock.close()

            ping_param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            command = ["ping", ping_param, target]
            output = subprocess.run(command, capture_output=True, text=True, timeout=5)

            if 'ttl=' in output.stdout.lower():
                ttl_line = [line for line in output.stdout.split('\n') if 'ttl=' in line.lower()]
                if ttl_line:
                    ttl_value = int(ttl_line[0].split('ttl=')[1].split(' ')[0])

                    closest_os = 'Unknown'
                    closest_diff = float('inf')

                    for os_name, os_ttl in ttl_values.items():
                        diff = abs(ttl_value - os_ttl)
                        if diff < closest_diff:
                            closest_diff = diff
                            closest_os = os_name

                    print(f"[+] Estimated OS: {closest_os} (TTL: {ttl_value})")
                    return closest_os
        except:
            print("[-] OS detection failed")

        return 'Unknown'

    def dns_lookup(self, target):
        print(f"[*] Performing DNS lookup for {target}...")
        try:
            ip = socket.gethostbyname(target)
            print(f"[+] {target} resolves to {ip}")

            try:
                hostname = socket.gethostbyaddr(ip)
                print(f"[+] Reverse DNS: {hostname[0]}")
            except:
                print("[-] No reverse DNS record found")

            return ip
        except socket.gaierror:
            print(f"[-] Could not resolve {target}")
            return None

def parse_ports(port_spec):
    ports = set()

    if port_spec == 'all':
        return list(range(1, 65536))
    elif port_spec == 'common':
        common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080]
        return common_ports

    parts = port_spec.split(',')
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(description='Elysium - Advanced Network Scanner')
    parser.add_argument('target', help='Target IP, hostname, or network (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='common', help='Ports to scan (common, all, or 80,443,1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Thread count (default: 200)')
    parser.add_argument('-T', '--timeout', type=float, default=2.0, help='Timeout in seconds (default: 2)')
    parser.add_argument('--ping', action='store_true', help='Perform ping sweep on network')
    parser.add_argument('--os', action='store_true', help='Perform OS detection')
    parser.add_argument('--dns', action='store_true', help='Perform DNS lookup')

    args = parser.parse_args()

    scanner = ElysiumScanner()

    try:
        if args.ping and '/' in args.target:
            scanner.ping_sweep(args.target)
            return

        target_ip = scanner.validate_target(args.target)

        if args.dns:
            scanner.dns_lookup(args.target)

        ports = parse_ports(args.ports)

        if args.os:
            scanner.os_detection(target_ip)

        print(f"[*] Target: {args.target} ({target_ip})")
        print(f"[*] Ports: {len(ports)} | Threads: {args.threads} | Timeout: {args.timeout}s")
        print("")

        open_ports = scanner.service_scan(target_ip, ports)

        if open_ports:
            print("\n" + "="*50)
            print("SUMMARY:")
            print("="*50)
            for port, service in sorted(open_ports):
                print(f"  {port}/tcp - {service}")

    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()