# 🌐 Elysium - Advanced Network Scanner

```
╔══════════════════════════════════════════════╗
║                   ELYSIUM                    ║
║           Advanced Network Recon             ║
║                  by 0x127                    ║
╚══════════════════════════════════════════════╝
```

**Professional-grade network reconnaissance tool for security researchers and penetration testers**

![Python 3.x](https://img.shields.io/badge/python-3.x-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Port Scanning** | Lightning-fast TCP port scanning with automatic service detection |
| 🌊 **Ping Sweep** | Network-wide host discovery and enumeration |
| 🖥️ **OS Detection** | Advanced operating system fingerprinting using TTL analysis with traceroute |
| 🗺️ **Traceroute Integration** | Calculate hop count for accurate TTL-based OS detection |
| 🌐 **DNS Reconnaissance** | Forward and reverse DNS lookups |
| 🏷️ **Banner Grabbing** | Extract service version information and server details |
| 🛡️ **Vulnerability Detection** | Identify common security vulnerabilities and misconfigurations |
| 📊 **Export Results** | Save scan results in JSON or TXT format for reporting |
| ⚡ **Multi-threaded** | High-performance concurrent scanning (up to 500+ threads) |
| 🎯 **Flexible Targeting** | Support for IPs, hostnames, CIDR ranges, and port specifications |

---

## 📦 Installation

### Quick Start

```bash
git clone https://github.com/0x127/elysium
cd elysium
chmod +x scanner.py
```

### Requirements

- Python 3.6+
- Linux/macOS/Windows
- Root/Administrator privileges (recommended for traceroute features)

---

## 🚀 Usage

### Basic Scanning

**Scan common ports on a target**
```bash
python3 scanner.py 192.168.1.1
```

**Scan top 100 most common ports**
```bash
python3 scanner.py 192.168.1.1 -p top100
```

**Scan specific ports**
```bash
python3 scanner.py example.com -p 80,443,22
```

**Scan port range**
```bash
python3 scanner.py 10.0.0.1 -p 1-1000
```

**Full port scan (all 65535 ports)**
```bash
python3 scanner.py target.com -p all
```

### Network Discovery

**Ping sweep a network**
```bash
python3 scanner.py 192.168.1.0/24 --ping
```

**Scan all active hosts in network**
```bash
for host in $(python3 scanner.py 192.168.1.0/24 --ping | grep "Host alive" | awk '{print $4}'); do
    python3 scanner.py $host -p common
done
```

### Advanced Scanning Features

**Banner grabbing for service identification**
```bash
python3 scanner.py target.com -p common --banner
```

**Vulnerability detection**
```bash
python3 scanner.py 192.168.1.1 -p top100 --vulns
```

**Complete reconnaissance with all features**
```bash
python3 scanner.py target.com -p common --banner --vulns --os --traceroute --dns
```

**Save results to JSON file**
```bash
python3 scanner.py 192.168.1.1 -p all -o scan_results.json
```

**Save results to text report**
```bash
python3 scanner.py target.com -p common --os --dns -o report.txt --format txt
```

### Advanced OS Detection

**Basic OS detection (TTL-based)**
```bash
python3 scanner.py target.com --os
```

**Enhanced OS detection with traceroute**
```bash
python3 scanner.py target.com --os --traceroute
```

**Full reconnaissance with DNS + OS detection**
```bash
python3 scanner.py target.com --os --traceroute --dns -p common
```

### Performance Tuning

**High-speed scanning (500 threads, 1s timeout)**
```bash
python3 scanner.py 192.168.1.1 -t 500 -T 1
```

**Stealth scan (slower, fewer threads)**
```bash
python3 scanner.py 192.168.1.1 -t 50 -T 5
```

### Comprehensive Scan

**Full reconnaissance on enterprise target**
```bash
python3 scanner.py enterprise-server.com -p all --os --traceroute --dns -t 300
```

---

## 🎯 Command Reference

### Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `target` | Target IP, hostname, or CIDR network | `192.168.1.1`, `example.com`, `10.0.0.0/24` |
| `-p, --ports` | Ports to scan | `common`, `top100`, `all`, `80,443`, `1-1000` |
| `-t, --threads` | Number of concurrent threads (default: 200) | `100`, `500` |
| `-T, --timeout` | Connection timeout in seconds (default: 2.0) | `1.0`, `5.0` |
| `--ping` | Perform ping sweep on network | - |
| `--os` | Perform OS detection via TTL analysis | - |
| `--traceroute` | Use traceroute for accurate hop-based OS detection | - |
| `--dns` | Perform DNS lookup (forward + reverse) | - |
| `--banner` | Grab service banners for version detection | - |
| `--vulns` | Check for common vulnerabilities | - |
| `-o, --output` | Save results to file | `results.json`, `report.txt` |
| `--format` | Output format (json or txt) | `json`, `txt` |

### Port Specifications

- **`common`** - Scans 19 most common ports (21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 1433, 3306, 3389, 5432, 5900, 8080, 8443)
- **`top100`** - Scans top 100 most commonly used ports
- **`all`** - Scans all 65535 ports
- **`80,443,8080`** - Comma-separated port list
- **`1-1000`** - Port range
- **`20-25,80,443,8000-9000`** - Combined specification

---

## 🛡️ Vulnerability Detection

Elysium includes built-in vulnerability checks for common services:

| Service | Potential Vulnerabilities Detected |
|---------|-----------------------------------|
| **FTP (21)** | Anonymous FTP access, vsftpd backdoor |
| **SSH (22)** | Weak algorithms, default credentials |
| **Telnet (23)** | Plaintext protocols, no encryption |
| **MySQL (3306)** | Default root account, no password |
| **RDP (3389)** | BlueKeep vulnerability, weak credentials |
| **VNC (5900)** | No authentication, weak passwords |
| **Redis (6379)** | No authentication, unprotected instance |

**Example output:**

```bash
python3 scanner.py 192.168.1.1 -p common --vulns
```

```
[+] 192.168.1.1:22 - SSH
    [!] Potential vulnerabilities: Weak SSH algorithms, Default credentials
[+] 192.168.1.1:3306 - MYSQL
    [!] Potential vulnerabilities: MySQL default root, No password
```

---

## 📊 Output Formats

### JSON Output

Perfect for automation and integration with other tools:

```bash
python3 scanner.py target.com -p common -o results.json
```

**Example JSON structure:**

```json
{
  "scan_start": "2024-11-02T10:30:00",
  "scan_end": "2024-11-02T10:32:15",
  "target": "target.com",
  "hosts": {
    "93.184.216.34": {
      "os_info": {
        "os": "Linux/Unix",
        "confidence": 100.0,
        "reliability": "HIGH"
      },
      "open_ports": [
        {
          "port": 80,
          "service": "http",
          "banner": "Apache/2.4.41 (Ubuntu)"
        }
      ]
    }
  }
}
```

### Text Report

For documentation:

```bash
python3 scanner.py target.com -p common -o report.txt --format txt
```

---

## 🔬 How OS Detection Works

### Basic Mode (`--os`)

Uses received TTL values from ICMP ping responses to estimate the operating system. Less accurate due to unknown hop count.

### Enhanced Mode (`--os --traceroute`)

1. Performs traceroute to determine exact hop count to target
2. Calculates original TTL: **`Original TTL = Received TTL + Hop Count`**
3. Compares against known OS TTL values:
   - **Linux/Unix:** 64
   - **Windows:** 128
   - **Cisco/Network devices:** 255
4. Provides confidence score and reliability rating

**Example output:**

```
[+] Detected 8 hops to target
[+] Received TTL: 120
[+] Calculated original TTL: 128 (hops: 8)
[+] Estimated OS: Windows
[+] Confidence: 100.0% (diff: 0)
[+] Detection reliability: HIGH
```

---

## 📈 Output Interpretation

### Scan Results Example

```
[*] Target: example.com (93.184.216.34)
[*] Ports: 16 | Threads: 200 | Timeout: 2.0s

[+] 93.184.216.34:80 - HTTP
[+] 93.184.216.34:443 - HTTPS

[*] Scan completed in 3.45 seconds
[+] Found 2 open ports

==================================================
SUMMARY:
==================================================
  80/tcp - http
  443/tcp - https
```

---

## 🛠️ Troubleshooting

### Permission Errors with Traceroute

If you see `Insufficient privileges for raw sockets`:

**Linux/macOS - Run with sudo:**
```bash
sudo python3 scanner.py target.com --os --traceroute
```

**Or grant CAP_NET_RAW capability:**
```bash
sudo setcap cap_net_raw+ep $(which python3)
```

### Traceroute Command Not Found

Install traceroute utility:

**Debian/Ubuntu:**
```bash
sudo apt-get install traceroute
```

**RHEL/CentOS/Fedora:**
```bash
sudo yum install traceroute
```

**macOS:**
```bash
# Usually pre-installed, no action needed
```

**Windows:**
```bash
# Uses 'tracert' automatically - pre-installed
```

---

