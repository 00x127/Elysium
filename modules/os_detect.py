import subprocess
import platform
from modules.traceroute import TraceRoute

class OSFingerprint:
    def __init__(self):
        self.tracer = TraceRoute()
        self.ttl_map = {
            'Linux/Unix': 64,
            'Windows': 128,
            'Cisco/Network': 255
        }

    def detect(self, target, use_traceroute=False):
        print(f"[*] Performing OS detection on {target}...")
        try:
            hops = None
            if use_traceroute:
                hops = self.tracer.trace(target)

            ping_param = "-n 1" if platform.system().lower() == "windows" else "-c 1"
            cmd = ["ping", ping_param, target]
            output = subprocess.run(cmd, capture_output=True, text=True, timeout=5)

            if 'ttl=' in output.stdout.lower():
                ttl_line = [line for line in output.stdout.split('\n') if 'ttl=' in line.lower()]
                if ttl_line:
                    recv_ttl = int(ttl_line[0].split('ttl=')[1].split(' ')[0])

                    print(f"[+] Received TTL: {recv_ttl}")

                    if hops:
                        orig_ttl = recv_ttl + hops
                        print(f"[+] Calculated original TTL: {orig_ttl} (hops: {hops})")

                        best_match = 'Unknown'
                        min_diff = float('inf')

                        for os_name, os_ttl in self.ttl_map.items():
                            diff = abs(orig_ttl - os_ttl)
                            if diff < min_diff:
                                min_diff = diff
                                best_match = os_name

                        conf = max(0, 100 - (min_diff * 10))
                        print(f"[+] Estimated OS: {best_match}")
                        print(f"[+] Confidence: {conf:.1f}% (diff: {min_diff})")

                        if min_diff <= 5:
                            reliability = "HIGH"
                        elif min_diff <= 15:
                            reliability = "MEDIUM"
                        else:
                            reliability = "LOW"

                        print(f"[+] Detection reliability: {reliability}")

                        return {
                            'os': best_match,
                            'ttl': recv_ttl,
                            'calculated_ttl': orig_ttl,
                            'hops': hops,
                            'confidence': conf,
                            'reliability': reliability
                        }
                    else:
                        print("[*] Using basic TTL matching (no hop count available)")
                        best_match = 'Unknown'
                        min_diff = float('inf')

                        for os_name, os_ttl in self.ttl_map.items():
                            diff = abs(recv_ttl - os_ttl)
                            if diff < min_diff:
                                min_diff = diff
                                best_match = os_name

                        print(f"[+] Estimated OS: {best_match} (TTL: {recv_ttl})")
                        print(f"[!] Note: Accuracy limited without traceroute data")

                        return {
                            'os': best_match,
                            'ttl': recv_ttl,
                            'method': 'basic'
                        }

        except Exception as e:
            print(f"[-] OS detection failed: {e}")

        return {'os': 'Unknown'}
