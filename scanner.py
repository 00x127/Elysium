#!/usr/bin/env python3

import argparse
from datetime import datetime
from core.scanner_engine import ScannerEngine
from utils.port_parser import parse_port_range

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

    scanner = ScannerEngine()

    try:
        if args.ping and '/' in args.target:
            hosts = scanner.scan_network(args.target)
            if args.output:
                scanner.results['target'] = args.target
                scanner.results['active_hosts'] = hosts
                scanner.export_results(args.output, args.format)
            return

        target_addr = scanner.validate_host(args.target)
        scanner.results['target'] = args.target

        host_info = {}

        if args.dns:
            dns_data = scanner.lookup_dns(args.target)
            if dns_data:
                host_info['dns_info'] = dns_data

        port_list = parse_port_range(args.ports)

        if args.os:
            os_data = scanner.detect_os(target_addr, use_traceroute=args.traceroute)
            host_info['os_info'] = os_data

        print(f"[*] Target: {args.target} ({target_addr})")
        print(f"[*] Ports: {len(port_list)} | Threads: {args.threads} | Timeout: {args.timeout}s")
        print("")

        discovered_ports = scanner.scan_ports(target_addr, port_list, grab_banner=args.banner, check_vulns=args.vulns)
        host_info['open_ports'] = discovered_ports

        scanner.results['hosts'][target_addr] = host_info

        if discovered_ports:
            print("\n" + "="*50)
            print("SUMMARY:")
            print("="*50)
            for port_data in sorted(discovered_ports, key=lambda x: x['port']):
                output = f"  {port_data['port']}/tcp - {port_data['service']}"
                if 'banner' in port_data:
                    output += f" ({port_data['banner'][:30]}...)"
                print(output)
                if 'potential_vulns' in port_data:
                    print(f"    [!] {', '.join(port_data['potential_vulns'])}")

        if args.output:
            scanner.export_results(args.output, args.format)

    except ValueError as e:
        print(f"Error: {e}")
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        if args.output:
            scanner.export_results(args.output, args.format)
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()
