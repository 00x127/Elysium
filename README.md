# Elysium Network Scanner

```
╔══════════════════════════════════════════════╗
║                   ELYSIUM                    ║
║           Advanced Network Recon             ║
║                  by 0x127                    ║
╚══════════════════════════════════════════════╝
```

Network reconnaissance tool for authorized security testing and educational purposes.

## Features

- Port scanning with service detection
- Network host discovery (ping sweep)
- OS fingerprinting via TTL analysis
- DNS lookups (forward and reverse)
- Service banner grabbing
- Common vulnerability checks
- Multi-threaded scanning
- JSON and text export formats

## Installation

```bash
git clone https://github.com/0x127/elysium
cd elysium
chmod +x scanner.py
```

Requirements: Python 3.6+

## Usage

### Basic Scanning

Scan common ports:
```bash
python3 scanner.py 192.168.1.1
```

Scan specific ports:
```bash
python3 scanner.py example.com -p 80,443,22
```

Scan port range:
```bash
python3 scanner.py 10.0.0.1 -p 1-1000
```

### Network Discovery

Ping sweep:
```bash
python3 scanner.py 192.168.1.0/24 --ping
```

### Advanced Features

Banner grabbing:
```bash
python3 scanner.py target.com -p common --banner
```

Vulnerability detection:
```bash
python3 scanner.py 192.168.1.1 -p top100 --vulns
```

Full reconnaissance:
```bash
python3 scanner.py target.com -p common --banner --vulns --os --traceroute --dns
```

Export results:
```bash
python3 scanner.py target.com -p common -o results.json
```

### OS Detection

Basic TTL-based detection:
```bash
python3 scanner.py target.com --os
```

Enhanced detection with traceroute:
```bash
python3 scanner.py target.com --os --traceroute
```

## Command Line Options

| Option | Description |
|--------|-------------|
| `target` | IP address, hostname, or CIDR network |
| `-p, --ports` | Ports to scan (common, top100, all, or custom) |
| `-t, --threads` | Number of threads (default: 200) |
| `-T, --timeout` | Timeout in seconds (default: 2.0) |
| `--ping` | Perform network ping sweep |
| `--os` | Perform OS detection |
| `--traceroute` | Use traceroute for accurate OS detection |
| `--dns` | Perform DNS lookup |
| `--banner` | Grab service banners |
| `--vulns` | Check for common vulnerabilities |
| `-o, --output` | Save results to file |
| `--format` | Output format (json or txt) |

## Port Specifications

- `common` - 19 most common ports
- `top100` - Top 100 commonly used ports  
- `all` - All 65535 ports
- `80,443,8080` - Comma-separated list
- `1-1000` - Port range
- `20-25,80,443` - Combined specification

