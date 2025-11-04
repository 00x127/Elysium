import socket

class DNSResolver:
    def __init__(self):
        pass

    def lookup(self, target):
        print(f"[*] Performing DNS lookup for {target}...")
        info = {}
        try:
            ip = socket.gethostbyname(target)
            print(f"[+] {target} resolves to {ip}")
            info['ip'] = ip

            try:
                hostname = socket.gethostbyaddr(ip)
                print(f"[+] Reverse DNS: {hostname[0]}")
                info['reverse_dns'] = hostname[0]
            except:
                print("[-] No reverse DNS record found")

            return info
        except socket.gaierror:
            print(f"[-] Could not resolve {target}")
            return None
