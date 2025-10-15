# 🔍 Network Packet Sniffer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.linux.org/)

A Python-based network packet analyzer that captures and dissects network traffic in real-time. This tool provides detailed insights into Ethernet frames, IPv4 packets, and various transport layer protocols including TCP, UDP, and ICMP.

![Packet Sniffer](https://img.shields.io/badge/status-active-success.svg)

## ✨ Features

### Protocol Analysis
- **Ethernet Frame Parsing**: Extracts source/destination MAC addresses and protocol types
- **IPv4 Packet Dissection**: Analyzes version, header length, TTL, protocol, and IP addresses
- **TCP Segment Analysis**: Decodes ports, sequence numbers, acknowledgments, and all TCP flags
- **UDP Datagram Parsing**: Extracts port information and payload data
- **ICMP Packet Inspection**: Analyzes ICMP type, code, and checksum

### Advanced Capabilities
- **Real-time Packet Capture**: Continuous monitoring of network traffic
- **Raw Socket Access**: Low-level packet capture at the data link layer
- **Formatted Output**: Hierarchical, color-coded display of packet information
- **Hexadecimal Data Display**: Detailed payload visualization
- **Multi-protocol Support**: Handles multiple network protocols simultaneously

## 🔍 How It Works

### Architecture Overview

```
┌─────────────────────────────────────┐
│     Raw Socket (AF_PACKET)          │
│     Captures all network traffic     │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│     Ethernet Frame Parser            │
│  - MAC addresses (src/dest)          │
│  - Protocol identification           │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│       IPv4 Packet Parser             │
│  - Version & Header Length           │
│  - TTL & Protocol                    │
│  - Source & Destination IPs          │
└──────────────┬──────────────────────┘
               │
        ┌──────┴──────┬──────────┐
        ▼             ▼          ▼
    ┌──────┐     ┌──────┐   ┌──────┐
    │ ICMP │     │ TCP  │   │ UDP  │
    └──────┘     └──────┘   └──────┘
```

### Packet Parsing Flow

1. **Capture**: Raw socket captures packets from network interface
2. **Ethernet Layer**: Extracts MAC addresses and identifies upper layer protocol
3. **Network Layer**: Parses IPv4 header information
4. **Transport Layer**: Decodes TCP/UDP/ICMP specific data
5. **Display**: Formats and outputs the captured information

## 🚀 Installation

### Prerequisites

- **Operating System**: Linux (Ubuntu, Debian, Fedora, etc.)
  - Note: Windows and macOS have limited raw socket support
- **Python**: Version 3.6 or higher
- **Permissions**: Root/sudo access (required for raw socket operations)

No external dependencies required! Uses only Python standard library.

## 💻 Usage

### Basic Usage

**IMPORTANT**: Must run with sudo/root privileges:

```bash
sudo python3 packet_sniffer.py
```

### Stopping the Sniffer

Press `Ctrl+C` to stop capturing packets.

### Filtering Traffic (Advanced)

To capture traffic on a specific interface:

```bash
# List available interfaces
ip link show

# Capture on specific interface (modify code to specify interface)
sudo python3 packet_sniffer.py
```

## 🔧 Technical Details

### Supported Protocols

| Layer | Protocol | Protocol Number | Features Extracted |
|-------|----------|----------------|-------------------|
| **Data Link** | Ethernet | - | MAC addresses, EtherType |
| **Network** | IPv4 | - | Version, TTL, Source/Dest IP |
| **Transport** | TCP | 6 | Ports, Seq/Ack, Flags (SYN, ACK, FIN, etc.) |
| **Transport** | UDP | 17 | Ports, Length, Payload |
| **Network** | ICMP | 1 | Type, Code, Checksum |

### TCP Flags Decoded

- **URG**: Urgent pointer field significant
- **ACK**: Acknowledgment field significant
- **PSH**: Push function
- **RST**: Reset connection
- **SYN**: Synchronize sequence numbers
- **FIN**: No more data from sender

### Code Structure

```python
packet_sniffer.py
│
├── main()                    # Main loop for packet capture
├── ethernet_frame()          # Parse Ethernet frame
├── get_mac_address()         # Format MAC address
├── ipv4_packet()            # Parse IPv4 header
├── ipv4()                   # Format IP address
├── icmp_packet()            # Parse ICMP packet
├── tcp_packet()             # Parse TCP segment
├── udp_packet()             # Parse UDP datagram
└── format_multi_line()      # Format hex output
```

## 📊 Output Examples

### Example 1: TCP Packet

```
Ethernet Frame: 
	 - Destination: AA:BB:CC:DD:EE:FF, Source: 11:22:33:44:55:66, Protocol: 8
	 - IPv4 Packet: 
		 - Version: 4, Header Length: 20, TTL: 64,
		 - Protocol: 6, Source: 192.168.1.100, Target: 93.184.216.34
	 - TCP Packet:
		 - Source Port: 45678, Destination Port: 443
		 - Sequence: 1234567890, Acknowledgement: 9876543210
		 - Flags:
			 - URG: 0, ACK: 1, PSH: 1, RST: 0, SYN: 0, fin: 0
		 - Data:
			 \x16\x03\x01\x00\x05...
```

### Example 2: ICMP Packet (Ping)

```
Ethernet Frame: 
	 - Destination: AA:BB:CC:DD:EE:FF, Source: 11:22:33:44:55:66, Protocol: 8
	 - IPv4 Packet: 
		 - Version: 4, Header Length: 20, TTL: 64,
		 - Protocol: 1, Source: 192.168.1.100, Target: 8.8.8.8
	 - ICMP Packet:
		 - Type: 8, Code: 0, Checksum: 12345
		 - Data:
			 \x00\x01\x02\x03...
```

## ⚠️ Limitations

### Platform Restrictions
- **Linux Only**: Raw sockets with `AF_PACKET` work best on Linux
- **Windows**: Requires WinPcap/Npcap and different implementation
- **macOS**: Limited raw socket support, requires different approach

### Technical Limitations
- **Root Access Required**: Must run with elevated privileges
- **No Packet Injection**: Read-only capture, no packet modification
- **IPv4 Only**: Does not parse IPv6 packets
- **No Layer 7**: Does not decode application layer protocols (HTTP, DNS, etc.)
- **Single Interface**: Captures from default interface only

## 🎯 Use Cases

### Educational
- Learning network protocols and packet structure
- Understanding the TCP/IP stack
- Studying network communication patterns
- Teaching networking concepts

### Network Analysis
- Debugging network connectivity issues
- Monitoring local network traffic
- Analyzing protocol behavior
- Detecting unusual network patterns

### Security Research
- Understanding network attack patterns
- Analyzing malware network behavior (in isolated environments)
- Studying protocol vulnerabilities
- Network forensics training

### Development
- Testing network applications
- Debugging API communications
- Verifying protocol implementations
- Performance analysis
