import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from modules.vulnerabilities import VulnChecker

class ServiceDetector:
    def __init__(self):
        self.vuln_checker = VulnChecker()

    def grab_banner(self, target, port, timeout=3):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))

            try:
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
            except:
                pass

            data = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            sock.close()

            if data:
                return data[:200]
        except:
            pass
        return None

    def check_port(self, target, port, timeout=2, grab_banner=False):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()

            if result == 0:
                try:
                    svc = socket.getservbyport(port, 'tcp')
                except:
                    svc = 'unknown'

                banner = None
                if grab_banner:
                    banner = self.grab_banner(target, port)

                return port, svc, 'open', banner
        except:
            pass
        return port, None, 'closed', None

    def scan_services(self, target, ports, grab_banner=False, check_vulns=False):
        discovered = []
        print(f"[*] Scanning {target} for open ports...")
        start = time.time()

        with ThreadPoolExecutor(max_workers=200) as executor:
            future_map = {executor.submit(self.check_port, target, port, 2, grab_banner): port for port in ports}

            for future in as_completed(future_map):
                port, svc, status, banner = future.result()
                if status == 'open':
                    port_data = {'port': port, 'service': svc}

                    if banner:
                        port_data['banner'] = banner
                        print(f"[+] {target}:{port} - {svc.upper()} - {banner[:50]}")
                    else:
                        print(f"[+] {target}:{port} - {svc.upper()}")

                    if check_vulns:
                        vulns = self.vuln_checker.check(target, port, svc)
                        if vulns:
                            port_data['potential_vulns'] = vulns
                            print(f"    [!] Potential vulnerabilities: {', '.join(vulns)}")

                    discovered.append(port_data)

        elapsed = time.time() - start
        print(f"\n[*] Scan completed in {elapsed:.2f} seconds")
        print(f"[+] Found {len(discovered)} open ports")

        return discovered
