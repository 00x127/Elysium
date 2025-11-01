#!/usr/bin/env python3

import socket
import threading
import subprocess
import platform
import argparse
import ipaddress
import time
import struct
import select
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

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
        self.scan_results = {
            'scan_start': datetime.now().isoformat(),
            'target': None,
            'hosts': {}
        }

    def validate_target(self, target):
        try:
            ipaddress.ip_address(target)
            return target
        except:
            try:
                return socket.gethostbyname(target)
            except socket.gaierror:
                raise ValueError(f"Invalid target: {target}")

    def banner_grab(self, target, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            except:
                pass
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                return banner[:200]
        except:
            pass
        return None

    def check_vulnerabilities(self, target, port, service):
        vulns = []
        
        common_vulns = {
            21: ['Anonymous FTP', 'vsftpd 2.3.4 backdoor'],
            22: ['Weak SSH algorithms', 'Default credentials'],
            23: ['Telnet plaintext', 'No encryption'],
            3306: ['MySQL default root', 'No password'],
            3389: ['RDP BlueKeep (CVE-2019-0708)', 'Weak credentials'],
            5900: ['VNC no authentication', 'Weak password'],
            6379: ['Redis no auth', 'Unprotected instance']
        }
        
        if port in common_vulns:
            vulns.extend(common_vulns[port])
        
        return vulns

    def traceroute(self, target, max_hops=30, timeout=2):
        print(f"[*] Tracing route to {target}...")
        
        try:
            dest_addr = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[-] Cannot resolve {target}")
            return None
        
        port = 33434
        icmp = socket.getprotobyname('icmp')
        udp = socket.getprotobyname('udp')
        
        hops = 0
        
        for ttl in range(1, max_hops + 1):
            try:
                recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
                
                send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                recv_socket.settimeout(timeout)
                
                recv_socket.bind(("", port))
                send_socket.sendto(b"", (dest_addr, port))
                
                try:
                    data, curr_addr = recv_socket.recvfrom(512)
                    curr_addr = curr_addr[0]
                except socket.timeout:
                    recv_socket.close()
                    send_socket.close()
                    continue
                finally:
                    recv_socket.close()
                    send_socket.close()
                
                hops = ttl
                
                if curr_addr == dest_addr:
                    print(f"[+] Reached target at hop {hops}")
                    return hops
                    
            except PermissionError:
                print("[*] Insufficient privileges for raw sockets, using system traceroute...")
                return self.traceroute_fallback(target, max_hops)
            except Exception as e:
                continue
        
        print(f"[+] Estimated hops: {hops} (target not reached within {max_hops} hops)")
        return hops if hops > 0 else None

    def traceroute_fallback(self, target, max_hops=30):
        try:
            if platform.system().lower() == "windows":
                cmd = ["tracert", "-h", str(max_hops), "-w", "1000", target]
            else:
                cmd = ["traceroute", "-m", str(max_hops), "-w", "1", target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            lines = result.stdout.split('\n')
            hop_count = 0
            
            for line in lines:
                line = line.strip()
                if not line or line.startswith('traceroute') or line.startswith('Tracing'):
                    continue
                
                parts = line.split()
                if parts and parts[0].replace('.', '').isdigit():
                    try:
                        hop_num = int(parts[0])
                        if hop_num > hop_count:
                            hop_count = hop_num
                    except:
                        continue
            
            if hop_count > 0:
                print(f"[+] Detected {hop_count} hops to target")
                return hop_count
            
        except subprocess.TimeoutExpired:
            print("[-] Traceroute timed out")
        except FileNotFoundError:
            print("[-] Traceroute command not found")
        except Exception as e:
            print(f"[-] Traceroute failed: {e}")
        
        return None

    def port_scan(self, target, port, timeout=2, grab_banner=False):
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
                
                banner = None
                if grab_banner:
                    banner = self.banner_grab(target, port)
                
                return port, service, 'open', banner
        except:
            pass
        return port, None, 'closed', None

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

    def service_scan(self, target, ports, grab_banner=False, check_vulns=False):
        open_ports = []
        print(f"[*] Scanning {target} for open ports...")
        start_time = time.time()

        with ThreadPoolExecutor(max_workers=200) as executor:
            future_to_port = {executor.submit(self.port_scan, target, port, 2, grab_banner): port for port in ports}

            for future in as_completed(future_to_port):
                port, service, status, banner = future.result()
                if status == 'open':
                    port_info = {'port': port, 'service': service}
                    
                    if banner:
                        port_info['banner'] = banner
                        print(f"[+] {target}:{port} - {service.upper()} - {banner[:50]}")
                    else:
                        print(f"[+] {target}:{port} - {service.upper()}")
                    
                    if check_vulns:
                        vulns = self.check_vulnerabilities(target, port, service)
                        if vulns:
                            port_info['potential_vulns'] = vulns
                            print(f"    [!] Potential vulnerabilities: {', '.join(vulns)}")
                    
                    open_ports.append(port_info)

        scan_time = time.time() - start_time
        print(f"\n[*] Scan completed in {scan_time:.2f} seconds")
        print(f"[+] Found {len(open_ports)} open ports")

        return open_ports

    def os_detection(self, target, use_traceroute=False):
        print(f"[*] Performing OS detection on {target}...")
        try:
            ttl_values = {
                'Linux/Unix': 64,
                'Windows': 128,
                'Cisco/Network': 255
            }

            hops = None
            if use_traceroute:
                hops = self.traceroute(target)
            
            ping_param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            command = ["ping", ping_param, target]
            output = subprocess.run(command, capture_output=True, text=True, timeout=5)

            if 'ttl=' in output.stdout.lower():
                ttl_line = [line for line in output.stdout.split('\n') if 'ttl=' in line.lower()]
                if ttl_line:
                    received_ttl = int(ttl_line[0].split('ttl=')[1].split(' ')[0])
                    
                    print(f"[+] Received TTL: {received_ttl}")
                    
                    if hops:
                        calculated_original_ttl = received_ttl + hops
                        print(f"[+] Calculated original TTL: {calculated_original_ttl} (hops: {hops})")
                        
                        closest_os = 'Unknown'
                        closest_diff = float('inf')
                        
                        for os_name, os_ttl in ttl_values.items():
                            diff = abs(calculated_original_ttl - os_ttl)
                            if diff < closest_diff:
                                closest_diff = diff
                                closest_os = os_name
                        
                        confidence = max(0, 100 - (closest_diff * 10))
                        print(f"[+] Estimated OS: {closest_os}")
                        print(f"[+] Confidence: {confidence:.1f}% (diff: {closest_diff})")
                        
                        if closest_diff <= 5:
                            reliability = "HIGH"
                        elif closest_diff <= 15:
                            reliability = "MEDIUM"
                        else:
                            reliability = "LOW"
                        
                        print(f"[+] Detection reliability: {reliability}")
                        
                        return {
                            'os': closest_os,
                            'ttl': received_ttl,
                            'calculated_ttl': calculated_original_ttl,
                            'hops': hops,
                            'confidence': confidence,
                            'reliability': reliability
                        }
                    else:
                        print("[*] Using basic TTL matching (no hop count available)")
                        closest_os = 'Unknown'
                        closest_diff = float('inf')

                        for os_name, os_ttl in ttl_values.items():
                            diff = abs(received_ttl - os_ttl)
                            if diff < closest_diff:
                                closest_diff = diff
                                closest_os = os_name

                        print(f"[+] Estimated OS: {closest_os} (TTL: {received_ttl})")
                        print(f"[!] Note: Accuracy limited without traceroute data")
                        
                        return {
                            'os': closest_os,
                            'ttl': received_ttl,
                            'method': 'basic'
                        }
                        
        except Exception as e:
            print(f"[-] OS detection failed: {e}")

        return {'os': 'Unknown'}

    def dns_lookup(self, target):
        print(f"[*] Performing DNS lookup for {target}...")
        dns_info = {}
        try:
            ip = socket.gethostbyname(target)
            print(f"[+] {target} resolves to {ip}")
            dns_info['ip'] = ip

            try:
                hostname = socket.gethostbyaddr(ip)
                print(f"[+] Reverse DNS: {hostname[0]}")
                dns_info['reverse_dns'] = hostname[0]
            except:
                print("[-] No reverse DNS record found")

            return dns_info
        except socket.gaierror:
            print(f"[-] Could not resolve {target}")
            return None

    def save_results(self, filename, format='json'):
        self.scan_results['scan_end'] = datetime.now().isoformat()
        
        if format == 'json':
            with open(filename, 'w') as f:
                json.dump(self.scan_results, f, indent=2)
            print(f"[+] Results saved to {filename}")
        elif format == 'txt':
            with open(filename, 'w') as f:
                f.write("="*60 + "\n")
                f.write("ELYSIUM SCAN REPORT\n")
                f.write("="*60 + "\n\n")
                f.write(f"Scan Start: {self.scan_results['scan_start']}\n")
                f.write(f"Scan End: {self.scan_results['scan_end']}\n")
                f.write(f"Target: {self.scan_results['target']}\n\n")
                
                for host, data in self.scan_results['hosts'].items():
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

def parse_ports(port_spec):
    ports = set()

    if port_spec == 'all':
        return list(range(1, 65536))
    elif port_spec == 'common':
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443]
        return common_ports
    elif port_spec == 'top100':
        return [7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157]

    parts = port_spec.split(',')
    for part in parts:
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))

    return sorted(ports)

def main():
    parser = argparse.ArgumentParser(
        description='Elysium - Advanced Network Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python3 scanner.py 192.168.1.1 -p common
  python3 scanner.py example.com --os --traceroute --banner
  python3 scanner.py 10.0.0.1 -p 1-1000 --vulns -o report.json
  python3 scanner.py 192.168.1.0/24 --ping
        '''
    )
    
    parser.add_argument('target', help='Target IP, hostname, or network (e.g., 192.168.1.0/24)')
    parser.add_argument('-p', '--ports', default='common', help='Ports to scan (common, top100, all, or 80,443,1-1000)')
    parser.add_argument('-t', '--threads', type=int, default=200, help='Thread count (default: 200)')
    parser.add_argument('-T', '--timeout', type=float, default=2.0, help='Timeout in seconds (default: 2)')
    parser.add_argument('--ping', action='store_true', help='Perform ping sweep on network')
    parser.add_argument('--os', action='store_true', help='Perform OS detection')
    parser.add_argument('--traceroute', action='store_true', help='Use traceroute for accurate OS detection')
    parser.add_argument('--dns', action='store_true', help='Perform DNS lookup')
    parser.add_argument('--banner', action='store_true', help='Grab service banners')
    parser.add_argument('--vulns', action='store_true', help='Check for common vulnerabilities')
    parser.add_argument('-o', '--output', help='Save results to file (json or txt)')
    parser.add_argument('--format', choices=['json', 'txt'], default='json', help='Output format (default: json)')

    args = parser.parse_args()

    scanner = ElysiumScanner()

    try:
        if args.ping and '/' in args.target:
            hosts = scanner.ping_sweep(args.target)
            if args.output:
                scanner.scan_results['target'] = args.target
                scanner.scan_results['active_hosts'] = hosts
                scanner.save_results(args.output, args.format)
            return

        target_ip = scanner.validate_target(args.target)
        scanner.scan_results['target'] = args.target

        host_data = {}

        if args.dns:
            dns_info = scanner.dns_lookup(args.target)
            if dns_info:
                host_data['dns_info'] = dns_info

        ports = parse_ports(args.ports)

        if args.os:
            os_info = scanner.os_detection(target_ip, use_traceroute=args.traceroute)
            host_data['os_info'] = os_info

        print(f"[*] Target: {args.target} ({target_ip})")
        print(f"[*] Ports: {len(ports)} | Threads: {args.threads} | Timeout: {args.timeout}s")
        print("")

        open_ports = scanner.service_scan(target_ip, ports, grab_banner=args.banner, check_vulns=args.vulns)
        host_data['open_ports'] = open_ports

        scanner.scan_results['hosts'][target_ip] = host_data

        if open_ports:
            print("\n" + "="*50)
            print("SUMMARY:")
            print("="*50)
            for port_info in sorted(open_ports, key=lambda x: x['port']):
                output = f"  {port_info['port']}/tcp - {port_info['service']}"
                if 'banner' in port_info:
                    output += f" ({port_info['banner'][:30]}...)"
                print(output)
                if 'potential_vulns' in port_info:
                    print(f"    [!] {', '.join(port_info['potential_vulns'])}")

        if args.output:
            scanner.save_results(args.output, args.format)

    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        if args.output:
            scanner.save_results(args.output, args.format)
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
