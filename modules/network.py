import subprocess
import platform
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed

class NetworkScanner:
    def __init__(self):
        pass

    def ping_sweep(self, network):
        active = []
        net = ipaddress.ip_network(network, strict=False)

        print(f"[*] Scanning network {net}...")

        def check_host(ip):
            param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            cmd = ["ping", param, str(ip)]
            try:
                result = subprocess.run(cmd, capture_output=True, timeout=2)
                if result.returncode == 0:
                    return str(ip)
            except:
                pass
            return None

        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = [executor.submit(check_host, ip) for ip in net.hosts()]
            for future in as_completed(futures):
                res = future.result()
                if res:
                    active.append(res)
                    print(f"[+] Host alive: {res}")

        return active
