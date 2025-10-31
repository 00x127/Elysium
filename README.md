# Elysium - Advanced Network Scanner

Elysium is a professional-grade network reconnaissance tool designed for cybersecurity enthusiasts or developers. It provides comprehensive scanning capabilities with high performance and accuracy.

## Features

- **Port Scanning**: Fast TCP port scanning with service detection
- **Ping Sweep**: Network discovery and host enumeration  
- **OS Detection**: Remote operating system fingerprinting via TTL analysis
- **DNS Recon**: Forward and reverse DNS lookups
- **Multi-threaded**: High-performance scanning with configurable threads
- **Flexible Targeting**: Support for IPs, hostnames, and network ranges

## Usage

# Scan common ports on a target
python scanner.py 192.168.1.1

# Scan specific ports
python scanner.py example.com -p 80,443,22

# Scan port range
python scanner.py 10.0.0.1 -p 1-1000

# Full port scan
python scanner.py target.com -p all

# Ping sweep a network
python scanner.py 192.168.1.0/24 --ping

# Scan all active hosts in network
for host in $(python scanner.py 192.168.1.0/24 --ping); do
    python scanner.py $host -p common
done

# OS detection and DNS lookup
python scanner.py target.com --os --dns

# High-speed scanning
python scanner.py 192.168.1.1 -t 500 -T 1

# Comprehensive scan
python scanner.py enterprise-server.com -p all --os --dns -t 300



## Installation

git clone https://github.com/0x127/elysium

cd elysium
