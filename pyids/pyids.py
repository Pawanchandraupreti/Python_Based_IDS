from scapy.all import sniff, IP, TCP, UDP, Raw
import argparse
import logging

# Setup logging to write alerts to a file and the console
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler('alerts.log'),
                        logging.StreamHandler()
                    ])

def load_rules(rule_file):
    """Load and parse rules from the rules file."""
    rules_list = []
    try:
        with open(rule_file, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):  # Ignore empty lines and comments
                    parts = line.split()
                    # A very basic parser. You can extend this greatly.
                    rule = {
                        'action': parts[0],       # e.g., 'alert'
                        'protocol': parts[1],     # e.g., 'tcp'
                        'src_ip': parts[2],       # e.g., 'any'
                        'src_port': parts[3],     # e.g., 'any'
                        'direction': parts[4],    # e.g., '->'
                        'dst_ip': parts[5],       # e.g., 'any'
                        'dst_port': parts[6],     # e.g., '80'
                        'msg': parts[8].strip('"'), # e.g., 'SQL Injection Attempt'
                        'content': parts[10].strip('";)') if len(parts) > 10 else None # e.g., 'union select'
                    }
                    rules_list.append(rule)
        logging.info(f"Loaded {len(rules_list)} rules from {rule_file}")
    except FileNotFoundError:
        logging.error(f"Rule file {rule_file} not found!")
    return rules_list


def packet_callback(packet, rules):
    """Function called for every captured packet."""
    # Check if packet has an IP layer
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto

        # Map protocol number to name
        proto_map = {6: 'tcp', 17: 'udp', 1: 'icmp'}
        protocol_name = proto_map.get(protocol, str(protocol))

        src_port = None
        dst_port = None
        payload = None

        # Extract TCP layer info
        if packet.haslayer(TCP):
            tcp_layer = packet.getlayer(TCP)
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            if packet.haslayer(Raw):
                payload = str(packet[Raw].load)
        # Extract UDP layer info
        elif packet.haslayer(UDP):
            udp_layer = packet.getlayer(UDP)
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            if packet.haslayer(Raw):
                payload = str(packet[Raw].load)

        # Check each rule against the current packet
        for rule in rules:
            # 1. Check protocol
            if rule['protocol'] != protocol_name:
                continue
            # 2. Check source IP (very basic, 'any' matches all)
            if rule['src_ip'] != 'any' and rule['src_ip'] != src_ip:
                continue
            # 3. Check destination port (e.g., for rule targeting port 80)
            if rule['dst_port'] != 'any' and int(rule['dst_port']) != dst_port:
                continue
            # 4. Check for content in payload
            if rule['content'] and payload:
                if rule['content'] in payload:
                    log_alert(rule, packet, src_ip, dst_ip, src_port, dst_port)
            else:
                # If no content rule, it's a header-based rule (like ICMP)
                log_alert(rule, packet, src_ip, dst_ip, src_port, dst_port)

def log_alert(rule, packet, src_ip, dst_ip, src_port, dst_port):
    """Generate an alert log."""
    alert_msg = f"ALERT: {rule['msg']} | SRC: {src_ip}:{src_port} -> DST: {dst_ip}:{dst_port}"
    logging.warning(alert_msg)
    # You can also add the packet summary: logging.info(packet.summary())

def main():
    parser = argparse.ArgumentParser(description="PyIDS - A simple Python Intrusion Detection System")
    parser.add_argument('-i', '--interface', help='Network interface to capture on (e.g., eth0, wlan0)')
    parser.add_argument('-r', '--pcap', help='Read from a PCAP file instead of live capture')
    args = parser.parse_args()

    rules = load_rules('rules.txt')

    if args.pcap:
        # Read packets from a file
        print(f"Reading packets from PCAP file: {args.pcap}")
        from scapy.all import rdpcap
        packets = rdpcap(args.pcap)
        for packet in packets:
            packet_callback(packet, rules)
    else:
        # Live capture on network interface
        interface = args.interface if args.interface else None 
        print(f"Starting live capture on interface: {interface}")
        # The 'prn' lambda function calls packet_callback for each packet
        sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, rules), store=0)

if __name__ == "__main__":
    main()
    

    