# Network Traffic Analyzer

## Overview

The Network Traffic Analyzer is a Python-based tool designed for capturing and analyzing network packets in real-time. It provides a comprehensive overview of network traffic, including detailed statistics and identification of potentially suspicious activity.

## Key Features

- **Protocol & IP Filtering**: Capture and analyze network traffic based on specific protocols such as TCP, UDP, ICMP, and ARP. Also includes the option of filtering based on IP address(es).
- **Detailed Statistics**: Obtain insights into packet counts, byte counts, top ports, and top IP addresses.
- **Suspicious Traffic Detection**: Identify potentially malicious activities, including:
  - Traffic on suspicious ports
  - High traffic volume to a single IP
  - Malformed packets
- **PCAP Output**: Save captured packets to a PCAP file for further analysis.

## Installation

Ensure you have Python and `scapy` installed. You can install `scapy` using pip:

```
pip install scapy
```

## Usage

Run the tool from the command line, specifying the network interface, protocols and IP address to filter by, and an optional output file for saving captured packets:

```
python traffic-analyser.py --interface "YourInterfaceName" --protocols tcp udp --ip IP ADDRESS --output captured_packets.pcap
```

### Command Line Arguments
--interface: The network interface to sniff on (GUID or path).
--protocols: Space-separated list of protocols to filter packets by (default: tcp udp icmp arp).
--ip: Space-separated list of IP addresses to filter packets by.
--output: Optional file to save captured packets in PCAP format.

## Example

To capture traffic on the "Wi-Fi" interface, filter for TCP and UDP traffic, and save the output to ```captured_packets.pcap```, use the following command:

```
python traffic_analyser.py --interface "Wi-Fi" --protocols tcp udp --output captured_packets.pcap
```
