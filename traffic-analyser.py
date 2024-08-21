import argparse
from scapy.all import sniff, wrpcap, IP, TCP, UDP, ICMP
from collections import Counter

# Global dictionary to store stats
stats = {
    "packet_count": 0,
    "byte_count": 0,
    "protocol_distribution": Counter(),
    "port_distribution": Counter(),
    "src_ip_distribution": Counter(),
    "dst_ip_distribution": Counter(),
    "suspicious_traffic": []
}

# Global list to store captured packets
packets = []

# List of well-known suspicious ports (commonly used by malware)
suspicious_ports = {6667, 12345, 31337, 54321}

def packet_callback(packet):
    # Increment the packet count
    stats["packet_count"] += 1
    # Add the packet length to the byte count
    stats["byte_count"] += len(packet)

    # Extract protocol information
    if packet.haslayer(TCP):
        stats["protocol_distribution"]['TCP'] += 1
        port = packet[TCP].sport
    elif packet.haslayer(UDP):
        stats["protocol_distribution"]['UDP'] += 1
        port = packet[UDP].sport
    elif packet.haslayer(ICMP):
        stats["protocol_distribution"]['ICMP'] += 1
        port = None
    elif packet.haslayer(IP) and packet[IP].proto == 1:  # ICMP protocol number
        stats["protocol_distribution"]['ICMP'] += 1
        port = None
    elif packet.haslayer(IP) and packet[IP].proto == 6:  # TCP protocol number
        stats["protocol_distribution"]['TCP'] += 1
        port = None
    else:
        stats["protocol_distribution"]['OTHER'] += 1
        port = None

    # Track the port distribution
    if port:
        stats["port_distribution"][port] += 1

        # Check for suspicious ports
        if port in suspicious_ports:
            stats["suspicious_traffic"].append(f"Suspicious port detected: {port} in packet {packet.summary()}")

    # Track source and destination IP addresses
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        stats["src_ip_distribution"][src_ip] += 1
        stats["dst_ip_distribution"][dst_ip] += 1

        # Detect high traffic to a single IP (DDoS or port scanning)
        if stats["src_ip_distribution"][src_ip] > 100:
            stats["suspicious_traffic"].append(f"High traffic from IP: {src_ip} with {stats['src_ip_distribution'][src_ip]} packets")

        if stats["dst_ip_distribution"][dst_ip] > 100:
            stats["suspicious_traffic"].append(f"High traffic to IP: {dst_ip} with {stats['dst_ip_distribution'][dst_ip]} packets")

    # Check for malformed packets
    if packet.haslayer(IP) and len(packet) < 20:
        stats["suspicious_traffic"].append(f"Malformed packet detected: {packet.summary()}")

    # Append the packet to the list for later saving
    packets.append(packet)

def build_filter_string(protocols):
    """Construct a filter string for multiple protocols."""
    if not protocols:
        return ""
    return " or ".join(protocols)

def print_top_distribution(distribution, label, top_n=5):
    """Print the top N items from a distribution."""
    print(f"\nTop {top_n} {label}:")
    print(f"{label:<20}{'Count':<10}")
    print("-" * 30)
    for item, count in distribution.most_common(top_n):
        print(f"{item:<20}{count:<10}")
    print("-" * 30)

def print_stats():
    """Print a summary of the captured packets."""
    total_packets = stats["packet_count"]
    total_bytes = stats["byte_count"]
    avg_packet_size = total_bytes / total_packets if total_packets > 0 else 0

    print("\n--- Capture Summary ---")
    print(f"Total Packets: {total_packets}")
    print(f"Total Bytes: {total_bytes}")
    print(f"Average Packet Size: {avg_packet_size:.2f} bytes")

    print("\nProtocol Distribution:")
    for protocol, count in stats["protocol_distribution"].items():
        print(f"{protocol:<10}: {count} ({count/total_packets*100:.2f}%)")

    print_top_distribution(stats["port_distribution"], "Ports")
    print_top_distribution(stats["src_ip_distribution"], "Source IPs")
    print_top_distribution(stats["dst_ip_distribution"], "Destination IPs")

    # Print any suspicious traffic detected
    if stats["suspicious_traffic"]:
        print("\n--- Suspicious Traffic Detected ---")
        for alert in stats["suspicious_traffic"]:
            print(alert)
    else:
        print("\nNo suspicious traffic detected.")

def main():
    parser = argparse.ArgumentParser(description="Network Traffic Analyzer")
    parser.add_argument("--interface", required=True, help="Network interface to sniff on (GUID or path)")
    parser.add_argument("--protocols", nargs='+', choices=['tcp', 'udp', 'icmp', 'arp'], default=['tcp', 'udp', 'icmp', 'arp'], help="Protocols to filter packets by (space-separated list)")
    parser.add_argument("--output", help="File to save captured packets")
    
    global args
    args = parser.parse_args()

    # Construct the filter string for multiple protocols
    filter_str = build_filter_string(args.protocols)

    print(f"Starting network traffic analyzer on interface {args.interface} with filter '{filter_str}'...")

    # Start sniffing
    try:
        sniff(iface=args.interface, prn=packet_callback, timeout=10, filter=filter_str)
    except OSError as e:
        print(f"Error: {e}")
        print("Ensure the interface identifier is correct and try again.")

    # Save captured packets to a file if output is specified
    if args.output:
        wrpcap(args.output, packets)
        print(f"Packets saved to {args.output}")

    # Print packet information
    print_stats()

if __name__ == "__main__":
    main()
