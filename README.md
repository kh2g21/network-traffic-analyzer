# Network Traffic Analyzer

## Overview

The Network Traffic Analyzer is a Python-based tool designed for capturing and analyzing network packets in real-time. It provides a comprehensive overview of network traffic, including detailed statistics and identification of potentially suspicious activity.

## Key Features

- **Protocol Filtering**: Capture and analyze network traffic based on specific protocols such as TCP, UDP, ICMP, and ARP.
- **Detailed Statistics**: Obtain insights into packet counts, byte counts, top ports, and top IP addresses.
- **Suspicious Traffic Detection**: Identify potentially malicious activities, including:
  - Traffic on suspicious ports
  - High traffic volume to a single IP
  - Malformed packets
- **PCAP Output**: Save captured packets to a PCAP file for further analysis and archival.

## Installation

Ensure you have Python and `scapy` installed. You can install `scapy` using pip:

```
pip install scapy
```
