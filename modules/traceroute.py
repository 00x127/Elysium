import socket
import subprocess
import platform

class TraceRoute:
    def __init__(self):
        pass

    def trace(self, target, max_hops=30, timeout=2):
        print(f"[*] Tracing route to {target}...")

        try:
            dest = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[-] Cannot resolve {target}")
            return None

        port = 33434
        icmp = socket.getprotobyname('icmp')
        udp = socket.getprotobyname('udp')

        hop_count = 0

        for ttl in range(1, max_hops + 1):
            try:
                recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)

                send_sock.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
                recv_sock.settimeout(timeout)

                recv_sock.bind(("", port))
                send_sock.sendto(b"", (dest, port))

                try:
                    data, curr = recv_sock.recvfrom(512)
                    curr = curr[0]
                except socket.timeout:
                    recv_sock.close()
                    send_sock.close()
                    continue
                finally:
                    recv_sock.close()
                    send_sock.close()

                hop_count = ttl

                if curr == dest:
                    print(f"[+] Reached target at hop {hop_count}")
                    return hop_count

            except PermissionError:
                print("[*] Insufficient privileges for raw sockets, using system traceroute...")
                return self.trace_fallback(target, max_hops)
            except Exception as e:
                continue

        print(f"[+] Estimated hops: {hop_count} (target not reached within {max_hops} hops)")
        return hop_count if hop_count > 0 else None

    def trace_fallback(self, target, max_hops=30):
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
